//! Unified `CatbirdMlsClient` + Labyrinth 1.1 adapter for `catmos-cli` (`Spec §6.3`, `G2`, `D4`, `I8`, `I15`, `I16`, `ctl #2`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use catbird_mls::client::{
    account_did_hash_hex, normalize_account_did, CatbirdMlsClient, CatbirdMlsClientConfig,
    EnrollmentReceipt, LabyrinthBackupStatus, OtcPairingCompletion, OtcPairingOffer,
    PlatformChangeEvent, PlatformChangeObserver, PlatformHttpHeader, PlatformHttpRequest,
    PlatformHttpResponse, PlatformKeyStore, PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::MLSError;
use rand::Rng as _;

const CLI_KEYRING_SERVICE: &str = "blue.catbird.catmos-cli.clean-slate";

pub struct CliPlatformKeyStore {
    use_os_keyring: bool,
    memory: Mutex<HashMap<String, Vec<u8>>>,
    dpop: Mutex<HashMap<String, (String, i64)>>,
}

impl CliPlatformKeyStore {
    pub fn new_os_keyring() -> Self {
        Self {
            use_os_keyring: true,
            memory: Mutex::new(HashMap::new()),
            dpop: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_in_memory() -> Self {
        Self {
            use_os_keyring: false,
            memory: Mutex::new(HashMap::new()),
            dpop: Mutex::new(HashMap::new()),
        }
    }

    fn read_secret(&self, label: &str) -> Result<Option<Vec<u8>>, MLSError> {
        if self.use_os_keyring {
            if let Ok(entry) = crate::native_keyring::entry(CLI_KEYRING_SERVICE, label) {
                match entry.get_password() {
                    Ok(b64) => {
                        let bytes = BASE64_STANDARD.decode(b64.trim()).map_err(|e| {
                            MLSError::Internal(format!("decode keyring `{label}`: {e}"))
                        })?;
                        return Ok(Some(bytes));
                    }
                    Err(keyring::Error::NoEntry) => return Ok(None),
                    Err(_) => {}
                }
            }
        }
        let guard = self
            .memory
            .lock()
            .map_err(|_| MLSError::Internal("keystore mutex poisoned".to_string()))?;
        Ok(guard.get(label).cloned())
    }

    fn write_secret(&self, label: &str, bytes: &[u8]) -> Result<(), MLSError> {
        if self.use_os_keyring {
            if let Ok(entry) = crate::native_keyring::entry(CLI_KEYRING_SERVICE, label) {
                let encoded = BASE64_STANDARD.encode(bytes);
                if entry.set_password(&encoded).is_ok() {
                    return Ok(());
                }
            }
        }
        let mut guard = self
            .memory
            .lock()
            .map_err(|_| MLSError::Internal("keystore mutex poisoned".to_string()))?;
        guard.insert(label.to_string(), bytes.to_vec());
        Ok(())
    }

    fn delete_secret(&self, label: &str) {
        if self.use_os_keyring {
            if let Ok(entry) = crate::native_keyring::entry(CLI_KEYRING_SERVICE, label) {
                let _ = entry.delete_credential();
            }
        }
        if let Ok(mut guard) = self.memory.lock() {
            guard.remove(label);
        }
    }
}

impl PlatformKeyStore for CliPlatformKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let label = format!("db-key:{account_did_hash}");
        if let Some(existing) = self.read_secret(&label)? {
            if existing.len() == 32 {
                return Ok(existing);
            }
        }
        let mut fresh = vec![0u8; 32];
        rand::rng().fill_bytes(&mut fresh);
        self.write_secret(&label, &fresh)?;
        Ok(fresh)
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        self.read_secret(&format!("sig:{key_id}"))
    }

    fn store_signature_keypair(
        &self,
        key_id: String,
        keypair_bytes: Vec<u8>,
    ) -> Result<(), MLSError> {
        self.write_secret(&format!("sig:{key_id}"), &keypair_bytes)
    }

    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
        self.delete_secret(&format!("db-key:{account_did_hash}"));
        self.delete_secret(&format!("sig:mls-signer:{account_did_hash}"));
        if let Ok(mut guard) = self.dpop.lock() {
            guard.remove(&account_did_hash);
        }
        Ok(())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let guard = self
            .dpop
            .lock()
            .map_err(|_| MLSError::Internal("dpop mutex poisoned".to_string()))?;
        Ok(guard.get(&account_did_hash).and_then(|(tok, exp)| {
            if *exp > now_ms {
                Some(tok.clone())
            } else {
                None
            }
        }))
    }

    fn store_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
        token: String,
        expires_at_ms: i64,
    ) -> Result<(), MLSError> {
        let mut guard = self
            .dpop
            .lock()
            .map_err(|_| MLSError::Internal("dpop mutex poisoned".to_string()))?;
        guard.insert(account_did_hash, (token, expires_at_ms));
        Ok(())
    }
}

pub struct CliPlatformTransport {
    http: reqwest::Client,
    bearer_token: RwLock<Option<String>>,
    offline_spaces_probe_override: Option<bool>,
}

impl CliPlatformTransport {
    pub fn new(offline_spaces_probe_override: Option<bool>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            bearer_token: RwLock::new(None),
            offline_spaces_probe_override,
        }
    }

    pub fn set_bearer_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.bearer_token.write() {
            *guard = token;
        }
    }
}

impl PlatformTransport for CliPlatformTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        if let Some(supports) = self.offline_spaces_probe_override {
            if request.url.ends_with("/xrpc/com.atproto.space.getSpace") {
                return Ok(PlatformHttpResponse {
                    status: if supports { 401 } else { 501 },
                    headers: Vec::new(),
                    body: if supports {
                        b"{\"error\":\"AuthMissing\"}".to_vec()
                    } else {
                        b"{\"error\":\"XRPCNotSupported\"}".to_vec()
                    },
                });
            }
        }

        let http = self.http.clone();
        let bearer = self.bearer_token.read().ok().and_then(|g| g.clone());
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| MLSError::Internal(format!("build runtime: {e}")))?;
            rt.block_on(async move {
                let method = reqwest::Method::from_bytes(request.method.as_bytes())
                    .map_err(|e| MLSError::invalid_input(format!("invalid HTTP method: {e}")))?;
                let mut builder = http.request(method, &request.url);
                let mut has_auth = false;
                for h in &request.headers {
                    if h.name.eq_ignore_ascii_case("authorization") {
                        has_auth = true;
                    }
                    builder = builder.header(&h.name, &h.value);
                }
                if !has_auth {
                    if let Some(tok) = bearer {
                        builder = builder.bearer_auth(tok);
                    }
                }
                if let Some(body) = request.body {
                    builder = builder.body(body);
                }
                let resp = builder
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(format!("HTTP transport failed: {e}")))?;
                let status = resp.status().as_u16();
                let headers = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|val| PlatformHttpHeader {
                            name: k.as_str().to_string(),
                            value: val.to_string(),
                        })
                    })
                    .collect();
                let body = resp
                    .bytes()
                    .await
                    .map_err(|e| MLSError::Internal(format!("read HTTP body: {e}")))?
                    .to_vec();
                Ok(PlatformHttpResponse {
                    status,
                    headers,
                    body,
                })
            })
        })
        .join()
        .map_err(|_| MLSError::Internal("HTTP transport thread panicked".to_string()))?
    }

    fn connect_realtime_stream(
        &self,
        _home_ds_endpoint: String,
        _cursor_seq: Option<i64>,
    ) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

struct CliChangeObserver;

impl PlatformChangeObserver for CliChangeObserver {
    fn on_change(&self, event: PlatformChangeEvent) {
        tracing::debug!(?event, "catmos-cli unified MLS state change");
    }
}

pub struct CliUnifiedMlsClient {
    storage_root: PathBuf,
    normalized_did: String,
    did_hash: String,
    sdk: Arc<CatbirdMlsClient>,
}

impl CliUnifiedMlsClient {
    pub fn is_opted_in(storage_root: &Path, account_did: &str) -> bool {
        let Ok(norm) = normalize_account_did(account_did) else {
            return false;
        };
        let Ok(hash) = account_did_hash_hex(&norm) else {
            return false;
        };
        storage_root
            .join("mls-opt-in")
            .join(format!("{hash}.enabled"))
            .exists()
    }

    pub fn set_opted_in(
        storage_root: &Path,
        account_did: &str,
        enabled: bool,
    ) -> anyhow::Result<()> {
        let norm = normalize_account_did(account_did)?;
        let hash = account_did_hash_hex(&norm)?;
        let dir = storage_root.join("mls-opt-in");
        std::fs::create_dir_all(&dir)?;
        let marker = dir.join(format!("{hash}.enabled"));
        if enabled {
            std::fs::write(&marker, b"1")?;
        } else if marker.exists() {
            let _ = std::fs::remove_file(&marker);
        }
        Ok(())
    }

    pub fn open_desktop(
        storage_root: PathBuf,
        account_did: &str,
        home_ds_did: String,
        home_ds_endpoint: String,
        pds_endpoint: String,
    ) -> anyhow::Result<Self> {
        Self::open_inner(
            storage_root,
            account_did,
            home_ds_did,
            home_ds_endpoint,
            pds_endpoint,
            Arc::new(CliPlatformKeyStore::new_os_keyring()),
            Arc::new(CliPlatformTransport::new(Some(true))),
        )
    }

    pub fn open_for_testing(
        storage_root: PathBuf,
        account_did: &str,
        pds_supports_spaces: bool,
    ) -> anyhow::Result<Self> {
        Self::open_inner(
            storage_root,
            account_did,
            "did:web:mlschat.catbird.blue".to_string(),
            "https://mlschat.catbird.blue".to_string(),
            "https://swan.place".to_string(),
            Arc::new(CliPlatformKeyStore::new_in_memory()),
            Arc::new(CliPlatformTransport::new(Some(pds_supports_spaces))),
        )
    }

    fn open_inner(
        storage_root: PathBuf,
        account_did: &str,
        home_ds_did: String,
        home_ds_endpoint: String,
        pds_endpoint: String,
        keystore: Arc<CliPlatformKeyStore>,
        transport: Arc<CliPlatformTransport>,
    ) -> anyhow::Result<Self> {
        let normalized_did = normalize_account_did(account_did)?;
        let did_hash = account_did_hash_hex(&normalized_did)?;
        let dev_dir = storage_root.join("mls-opt-in");
        std::fs::create_dir_all(&dev_dir)?;
        let dev_file = dev_dir.join(format!("{did_hash}.device"));
        let device_id = if let Ok(existing) = std::fs::read_to_string(&dev_file) {
            let trimmed = existing.trim();
            if !trimmed.is_empty() {
                trimmed.to_string()
            } else {
                let d = format!("catmos-cli-{}", uuid::Uuid::new_v4());
                std::fs::write(&dev_file, d.as_bytes())?;
                d
            }
        } else {
            let d = format!("catmos-cli-{}", uuid::Uuid::new_v4());
            std::fs::write(&dev_file, d.as_bytes())?;
            d
        };

        let cfg = CatbirdMlsClientConfig {
            storage_root: storage_root.to_string_lossy().to_string(),
            account_did: normalized_did.clone(),
            device_id,
            home_ds_did,
            home_ds_endpoint,
            pds_endpoint,
        };
        let observer: Arc<dyn PlatformChangeObserver> = Arc::new(CliChangeObserver);
        let sdk = CatbirdMlsClient::open(cfg, keystore, transport, Some(observer))?;
        Ok(Self {
            storage_root,
            normalized_did,
            did_hash,
            sdk,
        })
    }

    pub fn enable_and_enroll(
        &self,
        granted_scopes: Option<&[String]>,
    ) -> anyhow::Result<(EnrollmentReceipt, LabyrinthBackupStatus)> {
        let default_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let scopes = granted_scopes.unwrap_or(&default_scopes);
        let receipt = self.sdk.enroll_device(scopes)?;
        Self::set_opted_in(&self.storage_root, &self.normalized_did, true)?;
        let status = self.sdk.labyrinth_status()?;
        Ok((receipt, status))
    }

    pub fn sdk(&self) -> &Arc<CatbirdMlsClient> {
        &self.sdk
    }

    pub fn did_hash(&self) -> &str {
        &self.did_hash
    }

    pub fn status(&self) -> anyhow::Result<LabyrinthBackupStatus> {
        Ok(self.sdk.labyrinth_status()?)
    }

    pub fn setup_recovery_code(&self) -> anyhow::Result<String> {
        Ok(self.sdk.setup_recovery_code()?)
    }

    pub fn restore_recovery_code(&self, code: &str) -> anyhow::Result<LabyrinthBackupStatus> {
        Ok(self.sdk.restore_with_recovery_code(code)?)
    }

    pub fn initiate_otc(&self) -> anyhow::Result<OtcPairingOffer> {
        Ok(self.sdk.initiate_otc_pairing()?)
    }

    pub fn complete_otc(&self, six_digit_code: &str) -> anyhow::Result<OtcPairingCompletion> {
        Ok(self.sdk.complete_otc_pairing(six_digit_code)?)
    }

    pub fn revoke_device(&self, target_device_id: &str) -> anyhow::Result<LabyrinthBackupStatus> {
        Ok(self.sdk.revoke_labyrinth_device(target_device_id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_unified_client_enforces_ctl2_and_completes_labyrinth_flows() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let did = "did:plc:catmoscliunified00001";
        assert!(!CliUnifiedMlsClient::is_opted_in(tmp.path(), did));

        let client = CliUnifiedMlsClient::open_for_testing(tmp.path().to_path_buf(), did, true)
            .expect("open unified client");
        let (receipt, status) = client.enable_and_enroll(None).expect("enroll");
        assert!(CliUnifiedMlsClient::is_opted_in(tmp.path(), did));
        assert!(receipt.labyrinth_backup_enabled);
        assert_eq!(status.epoch_seq, 1);

        let code = client.setup_recovery_code().expect("recovery code");
        assert_eq!(
            code.chars().filter(|c| c.is_ascii_alphanumeric()).count(),
            40
        );

        let after_restore = client.restore_recovery_code(&code).expect("restore");
        assert_eq!(after_restore.epoch_seq, 2);

        let offer = client.initiate_otc().expect("initiate OTC");
        let otc_done = client
            .complete_otc(&offer.six_digit_code)
            .expect("complete PQ OTC");
        assert_eq!(otc_done.initiator_mlkem768_ek_len, 1184);
        assert_eq!(otc_done.responder_mlkem768_ct_len, 1088);
        assert_eq!(otc_done.new_epoch_seq, 3);
    }
}
