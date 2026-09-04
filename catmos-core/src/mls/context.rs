use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use catbird_mls::EpochSecretStorage;
use catbird_mls::{KeychainAccess, MLSCommitError, MLSContext, MLSError};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::error::{CatmosError, Result};

// ─── SystemKeychain ──────────────────────────────────────────────────────────

/// Keychain implementation using the OS keychain via the `keyring` crate,
/// with an in-memory HashMap fallback when the system keychain is unavailable.
pub struct SystemKeychain {
    service: String,
    fallback: Mutex<Option<HashMap<String, Vec<u8>>>>,
}

impl SystemKeychain {
    pub fn new(service: impl Into<String>) -> Self {
        let service = service.into();
        // Probe the system keychain to decide whether to use fallback
        let needs_fallback = std::env::var_os("CATMOS_TEST_KEYCHAIN_FALLBACK").is_some() || {
            let entry = keyring::Entry::new(&service, "__probe__");
            match entry {
                Ok(e) => {
                    // Try a read; NoEntry is fine, a platform error means fallback
                    match e.get_password() {
                        Ok(_) | Err(keyring::Error::NoEntry) => false,
                        Err(_) => true,
                    }
                }
                Err(_) => true,
            }
        };

        let fallback = if needs_fallback {
            warn!("System keychain unavailable, using in-memory fallback");
            Mutex::new(Some(HashMap::new()))
        } else {
            Mutex::new(None)
        };

        Self { service, fallback }
    }
}

#[async_trait::async_trait]
impl KeychainAccess for SystemKeychain {
    async fn read(&self, key: String) -> std::result::Result<Option<Vec<u8>>, MLSError> {
        let fb = self
            .fallback
            .lock()
            .map_err(|e| MLSError::Internal(format!("Keychain fallback lock poisoned: {e}")))?;

        if let Some(map) = fb.as_ref() {
            return Ok(map.get(&key).cloned());
        }
        drop(fb);

        let entry = keyring::Entry::new(&self.service, &key)
            .map_err(|e| MLSError::Internal(format!("Keyring entry error: {e}")))?;
        match entry.get_password() {
            Ok(val) => Ok(Some(val.into_bytes())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(MLSError::Internal(format!("Keyring read error: {e}"))),
        }
    }

    async fn write(&self, key: String, value: Vec<u8>) -> std::result::Result<(), MLSError> {
        let mut fb = self
            .fallback
            .lock()
            .map_err(|e| MLSError::Internal(format!("Keychain fallback lock poisoned: {e}")))?;

        if let Some(map) = fb.as_mut() {
            map.insert(key, value);
            return Ok(());
        }
        drop(fb);

        let password = String::from_utf8(value)
            .map_err(|e| MLSError::Internal(format!("Non-UTF8 keychain value: {e}")))?;
        let entry = keyring::Entry::new(&self.service, &key)
            .map_err(|e| MLSError::Internal(format!("Keyring entry error: {e}")))?;
        entry
            .set_password(&password)
            .map_err(|e| MLSError::Internal(format!("Keyring write error: {e}")))
    }

    async fn delete(&self, key: String) -> std::result::Result<(), MLSError> {
        let mut fb = self
            .fallback
            .lock()
            .map_err(|e| MLSError::Internal(format!("Keychain fallback lock poisoned: {e}")))?;

        if let Some(map) = fb.as_mut() {
            map.remove(&key);
            return Ok(());
        }
        drop(fb);

        let entry = keyring::Entry::new(&self.service, &key)
            .map_err(|e| MLSError::Internal(format!("Keyring entry error: {e}")))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(MLSError::Internal(format!("Keyring delete error: {e}"))),
        }
    }
}

// ─── DB key management ───────────────────────────────────────────────────────

/// Get or create a 64-character hex encryption key for the MLS SQLCipher database.
///
/// Strategy:
/// 1. Try reading from the system keychain (`catmos-mls-db/{did}`)
/// 2. If not found, generate a random 32-byte key, store it, return hex
/// 3. If the keychain is unavailable, derive deterministically from SHA256(did)
pub fn get_or_create_db_key(did: &str) -> Result<String> {
    if std::env::var_os("CATMOS_TEST_KEYCHAIN_FALLBACK").is_some() {
        return Ok(derive_key_from_did(did));
    }
    let service = crate::storage::config::Config::keychain_service("catmos-mls-db");
    let entry = keyring::Entry::new(&service, did);

    match entry {
        Ok(e) => {
            // Try to read existing key
            match e.get_password() {
                Ok(existing) => {
                    info!("Loaded MLS DB key from system keychain");
                    Ok(existing)
                }
                Err(keyring::Error::NoEntry) => {
                    // Generate random key
                    let key = generate_random_hex_key();
                    e.set_password(&key).map_err(|err| {
                        CatmosError::Storage(format!(
                            "Failed to store MLS DB key in keychain: {err}"
                        ))
                    })?;
                    info!("Generated and stored new MLS DB key in system keychain");
                    Ok(key)
                }
                Err(err) => {
                    if std::env::var_os("CATMOS_TEST_KEYCHAIN_FALLBACK").is_some() {
                        warn!("System keychain unavailable, falling back to test DID-derived key");
                        Ok(derive_key_from_did(did))
                    } else {
                        Err(CatmosError::Storage(format!(
                            "System keychain unavailable for MLS DB key: {err}"
                        )))
                    }
                }
            }
        }
        Err(err) => {
            if std::env::var_os("CATMOS_TEST_KEYCHAIN_FALLBACK").is_some() {
                warn!("System keychain unavailable, falling back to test DID-derived key");
                Ok(derive_key_from_did(did))
            } else {
                Err(CatmosError::Storage(format!(
                    "System keychain entry failed for MLS DB key: {err}"
                )))
            }
        }
    }
}

fn generate_random_hex_key() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}

fn derive_key_from_did(did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    hex::encode(hasher.finalize())
}

// ─── MlsManager ──────────────────────────────────────────────────────────────

/// Thread-safe wrapper around `catbird_mls::MLSContext`.
///
/// Provides `with_context` for synchronized access to the underlying context.
pub struct MlsManager {
    context: Arc<MLSContext>,
}

impl MlsManager {
    /// Create a new MLS manager with per-DID SQLCipher storage.
    ///
    /// `data_dir` — base directory for MLS state (e.g. `~/.local/share/catmos/mls`)
    /// `did` — the user's DID, used to isolate storage and derive keychain keys
    pub fn new(data_dir: &PathBuf, did: &str) -> Result<Self> {
        // Build per-DID storage path
        let did_hash = {
            let mut h = Sha256::new();
            h.update(did.as_bytes());
            hex::encode(&h.finalize()[..16]) // 32-char hex prefix for directory name
        };
        let db_path = data_dir.join(&did_hash).join("mls.db");

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let encryption_key = get_or_create_db_key(did)?;

        let keychain = Box::new(SystemKeychain::new(
            crate::storage::config::Config::keychain_service(&format!("catmos-mls-{did_hash}")),
        ));

        let storage_path = db_path
            .to_str()
            .ok_or_else(|| CatmosError::Storage("Non-UTF8 storage path".into()))?
            .to_string();

        info!("Initializing MLS context at {storage_path}");

        let context =
            MLSContext::new(storage_path, encryption_key, keychain).map_err(CatmosError::Mls)?;
        context
            .set_epoch_secret_storage(Box::new(MlsEpochSecretStorage::new()))
            .map_err(CatmosError::Mls)?;

        Ok(Self { context })
    }

    /// Execute a closure with access to the underlying `MLSContext`.
    pub fn with_context<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&MLSContext) -> std::result::Result<T, MLSError>,
    {
        f(&self.context).map_err(CatmosError::Mls)
    }

    /// Execute a closure with access to the underlying `MLSContext` for the
    /// three-phase sender-side commit API (task #62).
    ///
    /// `stage_commit` / `confirm_commit` / `discard_pending` return
    /// `Result<_, MLSCommitError>` rather than the usual `MLSError`, so they
    /// need their own helper — `MLSCommitError` preserves the structured
    /// `EpochMismatch { local, remote }` variant across the FFI that the
    /// flat `MLSError` would erase. See `catbird-mls/src/error.rs` for the
    /// rationale, and `TODO.md` task #63.
    pub fn with_commit_context<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&MLSContext) -> std::result::Result<T, MLSCommitError>,
    {
        f(&self.context).map_err(CatmosError::MlsCommit)
    }

    /// Get a reference to the inner Arc<MLSContext>.
    pub fn context(&self) -> &Arc<MLSContext> {
        &self.context
    }

    /// Sign a transcript with the persistent MLS identity signer without
    /// exporting its private key. The returned signature is intended for a
    /// reviewed protocol adapter; the key remains inside `MLSContext`.
    pub fn sign_non_exporting(&self, identity: &str, transcript: &[u8]) -> Result<Vec<u8>> {
        self.with_context(|ctx| {
            ctx.sign_with_identity_key(identity.to_string(), transcript.to_vec())
        })
    }

    /// Return the 32-byte Ed25519 public key for an identity if registered.
    pub fn signer_public_key(&self, identity: &str) -> Option<Vec<u8>> {
        let exported = self
            .with_context(|ctx| ctx.export_identity_key(identity.to_string()))
            .ok()?;
        let value: serde_json::Value = serde_json::from_slice(&exported).ok()?;
        if let Some(arr) = value.get("public").and_then(|v| v.as_array()) {
            let bytes: Option<Vec<u8>> = arr.iter().map(|b| b.as_u64().map(|n| n as u8)).collect();
            return bytes;
        }
        if let Some(s) = value.get("public").and_then(|v| v.as_str()) {
            return hex::decode(s).ok();
        }
        None
    }
}

pub struct MlsEpochSecretStorage {
    secrets: Mutex<HashMap<(String, u64), Vec<u8>>>,
}

impl MlsEpochSecretStorage {
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl EpochSecretStorage for MlsEpochSecretStorage {
    async fn store_epoch_secret(
        &self,
        conversation_id: String,
        epoch: u64,
        secret_data: Vec<u8>,
    ) -> bool {
        let mut guard = self.secrets.lock().unwrap();
        guard.insert((conversation_id, epoch), secret_data);
        true
    }

    async fn get_epoch_secret(&self, conversation_id: String, epoch: u64) -> Option<Vec<u8>> {
        let guard = self.secrets.lock().unwrap();
        guard.get(&(conversation_id, epoch)).cloned()
    }

    async fn delete_epoch_secret(&self, conversation_id: String, epoch: u64) -> bool {
        let mut guard = self.secrets.lock().unwrap();
        guard.remove(&(conversation_id, epoch)).is_some()
    }

    async fn delete_epochs_before(&self, conversation_id: String, cutoff_epoch: u64) -> u32 {
        let mut guard = self.secrets.lock().unwrap();
        let mut count = 0;
        guard.retain(|(convo, epoch), _| {
            if convo == &conversation_id && *epoch < cutoff_epoch {
                count += 1;
                false
            } else {
                true
            }
        });
        count
    }
}
