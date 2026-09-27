use async_trait::async_trait;
use keyring::Entry;

use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};

const SERVICE_NAME: &str = "blue.catbird.catmos";

/// A legacy plaintext file is evidence of old custody, never authority for a
/// new identity. Migration must verify it against the existing native identity
/// and explicitly commit OS-keychain custody before ordinary startup resumes.
#[derive(Debug, thiserror::Error)]
pub enum PrivateSigningKeyError {
    #[error("LegacySigningKeyMigrationRequired: signing identity exists only in a legacy file; verified migration to the OS keychain is required; the file was preserved")]
    LegacyMigrationRequired,
    #[error("SigningKeychainUnavailable: protected signing-key custody is unavailable")]
    KeychainUnavailable(#[source] keyring::Error),
    #[error("InvalidProtectedSigningKey: protected signing-key encoding is invalid")]
    InvalidEncoding,
}

fn write_private_signing_key(
    entry: &Entry,
    key_data: &[u8],
) -> std::result::Result<(), PrivateSigningKeyError> {
    use base64::Engine;
    if key_data.is_empty() {
        return Err(PrivateSigningKeyError::InvalidEncoding);
    }
    entry
        .set_password(&base64::engine::general_purpose::STANDARD.encode(key_data))
        .map_err(PrivateSigningKeyError::KeychainUnavailable)
}

fn read_private_signing_key(
    entry: &Entry,
    legacy_path: &std::path::Path,
) -> std::result::Result<Option<Vec<u8>>, PrivateSigningKeyError> {
    use base64::Engine;
    match entry.get_password() {
        Ok(encoded) => {
            let key = base64::engine::general_purpose::STANDARD
                .decode(&encoded)
                .map_err(|_| PrivateSigningKeyError::InvalidEncoding)?;
            if key.is_empty() || base64::engine::general_purpose::STANDARD.encode(&key) != encoded {
                return Err(PrivateSigningKeyError::InvalidEncoding);
            }
            Ok(Some(key))
        }
        Err(keyring::Error::NoEntry) if legacy_path.exists() => {
            Err(PrivateSigningKeyError::LegacyMigrationRequired)
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(PrivateSigningKeyError::KeychainUnavailable(error)),
    }
}

/// OS keychain-backed credential store using the `keyring` crate.
pub struct KeyringCredentialStore;

impl KeyringCredentialStore {
    /// Typed startup preflight. This does not read or modify a legacy file.
    pub async fn private_signing_key(
        &self,
        user_did: &str,
    ) -> std::result::Result<Option<Vec<u8>>, PrivateSigningKeyError> {
        use sha2::Digest;
        let key = Self::key_signing(user_did);
        let directory = crate::storage::config::Config::data_dir()
            .map_err(|_| PrivateSigningKeyError::InvalidEncoding)?;
        let legacy_path = directory.join("credentials").join(format!(
            "{}.key",
            hex::encode(sha2::Sha256::digest(key.as_bytes()))
        ));
        let entry = Self::entry(&key).map_err(PrivateSigningKeyError::KeychainUnavailable)?;
        read_private_signing_key(&entry, &legacy_path)
    }
    pub fn new() -> Self {
        match Self::try_new() {
            Ok(store) => store,
            Err(err) => panic!("{err}"),
        }
    }

    pub fn try_new() -> Result<Self> {
        #[cfg(target_os = "android")]
        {
            Err(OrchestratorError::Credential(
                "Android secure credential storage is not implemented; refusing to initialize MLS with keyring's mock store"
                    .to_string(),
            ))
        }

        #[cfg(not(target_os = "android"))]
        {
            Ok(Self)
        }
    }

    fn entry(key: &str) -> std::result::Result<Entry, keyring::Error> {
        Entry::new(
            &crate::storage::config::Config::keychain_service(SERVICE_NAME),
            key,
        )
    }

    pub(crate) async fn retain_generation(
        user_did: &str,
        device_id: &str,
        key_id: &str,
        generation: i64,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        if generation < 1 {
            return Err(OrchestratorError::Credential(
                "Invalid authenticated generation".into(),
            ));
        }
        let store = Self;
        let signing = store.get_signing_key(user_did).await?.ok_or_else(|| {
            OrchestratorError::Credential("Missing enrolled signing custody".into())
        })?;
        Self::store_string(format!("request_generation:{user_did}"),&serde_json::json!({"deviceId":device_id,"keyId":key_id,"generation":generation,"custodyHash":hex::encode(Sha256::digest(signing))}).to_string()).await
    }
    fn key_signing(user_did: &str) -> String {
        format!("signing_key:{}", user_did)
    }

    fn key_mls_did(user_did: &str) -> String {
        format!("mls_did:{}", user_did)
    }

    fn key_device_uuid(user_did: &str) -> String {
        format!("device_uuid:{}", user_did)
    }

    /// The UUID generated by catmos and submitted in `registerDevice`.
    ///
    /// The delivery service mints a separate `device_id`; keeping the two
    /// values under different key names prevents a server identifier from
    /// being sent back as the client UUID during device reconciliation.
    fn key_local_device_uuid(user_did: &str) -> String {
        format!("local_device_uuid:{}", user_did)
    }

    /// The server-minted device identifier returned by device registration.
    fn key_server_device_id(user_did: &str) -> String {
        format!("server_device_id:{}", user_did)
    }

    fn file_fallback_path(key: &str) -> Option<std::path::PathBuf> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(key.as_bytes());
        let hash = hex::encode(hasher.finalize());
        let dir = crate::storage::config::Config::data_dir()
            .ok()?
            .join("credentials");
        let _ = std::fs::create_dir_all(&dir);
        Some(dir.join(format!("{hash}.key")))
    }

    async fn get_string(key: String) -> Result<Option<String>> {
        match Self::entry(&key) {
            Ok(entry) => match entry.get_password() {
                Ok(value) if !value.trim().is_empty() => Ok(Some(value)),
                Ok(_) | Err(keyring::Error::NoEntry) => {
                    if let Some(path) = Self::file_fallback_path(&key) {
                        if path.exists() {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if !content.trim().is_empty() {
                                    return Ok(Some(content.trim().to_string()));
                                }
                            }
                        }
                    }
                    Ok(None)
                }
                Err(error) => {
                    if let Some(path) = Self::file_fallback_path(&key) {
                        if path.exists() {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if !content.trim().is_empty() {
                                    return Ok(Some(content.trim().to_string()));
                                }
                            }
                        }
                    }
                    Err(OrchestratorError::Credential(error.to_string()))
                }
            },
            Err(error) => {
                if let Some(path) = Self::file_fallback_path(&key) {
                    if path.exists() {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if !content.trim().is_empty() {
                                return Ok(Some(content.trim().to_string()));
                            }
                        }
                    }
                }
                Err(OrchestratorError::Credential(error.to_string()))
            }
        }
    }

    async fn store_string(key: String, value: &str) -> Result<()> {
        let value = value.trim();
        if value.is_empty() {
            return Err(OrchestratorError::Credential(
                "cannot persist an empty device identifier".to_string(),
            ));
        }
        if let Some(path) = Self::file_fallback_path(&key) {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&path)
                .map_err(|error| OrchestratorError::Credential(error.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|error| OrchestratorError::Credential(error.to_string()))?;
            }
            file.write_all(value.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| OrchestratorError::Credential(error.to_string()))?;
        }
        match Self::entry(&key) {
            Ok(entry) => match entry.set_password(value) {
                Ok(()) => Ok(()),
                Err(e) => {
                    if let Some(path) = Self::file_fallback_path(&key) {
                        if path.exists() {
                            return Ok(());
                        }
                    }
                    Err(OrchestratorError::Credential(e.to_string()))
                }
            },
            Err(e) => {
                if let Some(path) = Self::file_fallback_path(&key) {
                    if path.exists() {
                        return Ok(());
                    }
                }
                Err(OrchestratorError::Credential(e.to_string()))
            }
        }
    }

    fn delete_key(key: String) {
        if let Some(path) = Self::file_fallback_path(&key) {
            let _ = std::fs::remove_file(&path);
        }
        if let Ok(entry) = Self::entry(&key) {
            let _ = entry.delete_credential();
        }
    }
    /// Store the client-generated UUID independently from the server ID.
    pub async fn store_local_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()> {
        Self::store_string(Self::key_local_device_uuid(user_did), uuid).await
    }

    /// Read the client-generated UUID used to correlate `listDevices` rows.
    pub async fn get_local_device_uuid(&self, user_did: &str) -> Result<Option<String>> {
        Self::get_string(Self::key_local_device_uuid(user_did)).await
    }

    /// Store the server-minted device ID separately from the local UUID.
    pub async fn store_server_device_id(&self, user_did: &str, device_id: &str) -> Result<()> {
        Self::store_string(Self::key_server_device_id(user_did), device_id).await
    }

    /// Read the server-minted device ID. The legacy `device_uuid` slot is not
    /// consulted: it is ambiguous after the local/server split and therefore
    /// must never authorize a device or a publish request.
    pub async fn get_server_device_id(&self, user_did: &str) -> Result<Option<String>> {
        Self::get_string(Self::key_server_device_id(user_did)).await
    }

    /// Remove device authority material while retaining the local UUID for a
    /// later exact `listDevices` reconciliation.
    pub async fn clear_server_device_authority(&self, user_did: &str) -> Result<()> {
        Self::delete_key(Self::key_server_device_id(user_did));
        Self::delete_key(Self::key_device_uuid(user_did));
        Ok(())
    }

    pub async fn direct_request_receipt_authority_document(
        &self,
        expected_authority_did: &str,
    ) -> Result<Option<Vec<u8>>> {
        <Self as CredentialStore>::direct_request_receipt_authority_document(
            self,
            expected_authority_did,
        )
        .await
    }

    pub async fn get_chat_declaration_authority(&self, user_did: &str) -> Result<Option<String>> {
        <Self as CredentialStore>::get_chat_declaration_authority(self, user_did).await
    }
}

#[async_trait]
impl CredentialStore for KeyringCredentialStore {
    async fn get_auth_generation(&self, user_did: &str) -> Result<Option<i64>> {
        use sha2::{Digest, Sha256};
        let Some(raw) = Self::get_string(format!("request_generation:{user_did}")).await? else {
            return Ok(None);
        };
        let value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| OrchestratorError::Credential(e.to_string()))?;
        let Some(key) = self.get_signing_key(user_did).await? else {
            return Ok(None);
        };
        if value["deviceId"].as_str() != self.get_device_uuid(user_did).await?.as_deref()
            || value["custodyHash"] != hex::encode(Sha256::digest(key))
        {
            return Ok(None);
        }
        Ok(value["generation"].as_i64().filter(|g| *g > 0))
    }
    async fn direct_request_receipt_authority_document(
        &self,
        expected_authority_did: &str,
    ) -> Result<Option<Vec<u8>>> {
        crate::device_records::receipt_authority_document(expected_authority_did)
            .await
            .map(Some)
            .map_err(|error| OrchestratorError::Credential(error.to_string()))
    }

    async fn get_chat_declaration_authority(&self, user_did: &str) -> Result<Option<String>> {
        crate::device_records::chat_declaration_authority(user_did)
            .await
            .map_err(|error| OrchestratorError::Credential(error.to_string()))
    }

    async fn get_authorized_device_keys(&self, root_did: &str) -> Result<Option<Vec<Vec<u8>>>> {
        crate::device_records::authorized_keys(root_did)
            .await
            .map(Some)
            .map_err(|error| OrchestratorError::Credential(error.to_string()))
    }

    async fn store_signing_key(&self, user_did: &str, key_data: &[u8]) -> Result<()> {
        let entry = Self::entry(&Self::key_signing(user_did)).map_err(|e| {
            OrchestratorError::Credential(
                PrivateSigningKeyError::KeychainUnavailable(e).to_string(),
            )
        })?;
        write_private_signing_key(&entry, key_data)
            .map_err(|e| OrchestratorError::Credential(e.to_string()))
    }

    async fn get_signing_key(&self, user_did: &str) -> Result<Option<Vec<u8>>> {
        self.private_signing_key(user_did)
            .await
            .map_err(|e| OrchestratorError::Credential(e.to_string()))
    }

    async fn delete_signing_key(&self, user_did: &str) -> Result<()> {
        let entry = Self::entry(&Self::key_signing(user_did))
            .map_err(|e| OrchestratorError::Credential(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(OrchestratorError::Credential(error.to_string())),
        }
    }

    async fn store_mls_did(&self, user_did: &str, mls_did: &str) -> Result<()> {
        Self::store_string(Self::key_mls_did(user_did), mls_did).await
    }

    async fn get_mls_did(&self, user_did: &str) -> Result<Option<String>> {
        Self::get_string(Self::key_mls_did(user_did)).await
    }

    async fn store_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()> {
        // The external orchestrator trait calls this slot `device_uuid`, but
        // its value is the server-minted ID returned by `registerDevice`.
        // Keep that compatibility contract while storing the local UUID in a
        // distinct catmos-only slot above.
        self.store_server_device_id(user_did, uuid).await
    }

    async fn get_device_uuid(&self, user_did: &str) -> Result<Option<String>> {
        self.get_server_device_id(user_did).await
    }

    async fn has_credentials(&self, user_did: &str) -> Result<bool> {
        let has_key = self.get_signing_key(user_did).await?.is_some();
        let has_uuid = self.get_device_uuid(user_did).await?.is_some();
        Ok(has_key && has_uuid)
    }

    async fn clear_all(&self, user_did: &str) -> Result<()> {
        self.delete_signing_key(user_did).await?;
        // Delete MLS DID
        if let Ok(entry) = Self::entry(&Self::key_mls_did(user_did)) {
            let _ = entry.delete_credential();
        }
        // Delete both the legacy/server ID slot and the client UUID slot.
        Self::delete_key(Self::key_device_uuid(user_did));
        Self::delete_key(Self::key_server_device_id(user_did));
        Self::delete_key(Self::key_local_device_uuid(user_did));
        Self::delete_key(format!("request_generation:{user_did}"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_repository_identity_returns_error_not_unsupported_or_empty() {
        let result = KeyringCredentialStore::new()
            .get_authorized_device_keys("did:plc:invalid#device")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn declaration_and_receipt_authority_fail_closed_on_invalid_identity() {
        let store = KeyringCredentialStore::new();
        assert!(store.get_chat_declaration_authority("not-a-did").await.is_err());
        assert!(store.direct_request_receipt_authority_document("not-a-did").await.is_err());
    }

    #[test]
    fn local_uuid_and_server_device_id_use_distinct_keychain_slots() {
        assert_ne!(
            KeyringCredentialStore::key_local_device_uuid("did:plc:catmos"),
            KeyringCredentialStore::key_server_device_id("did:plc:catmos")
        );
        assert_eq!(
            KeyringCredentialStore::key_local_device_uuid("did:plc:catmos"),
            "local_device_uuid:did:plc:catmos"
        );
        assert_eq!(
            KeyringCredentialStore::key_server_device_id("did:plc:catmos"),
            "server_device_id:did:plc:catmos"
        );
    }

    #[cfg(target_os = "android")]
    #[test]
    fn android_credential_store_constructor_fails_closed() {
        let err = match KeyringCredentialStore::try_new() {
            Ok(_) => panic!("Android must not use keyring's mock credential store"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("Android secure credential storage is not implemented"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn non_android_credential_store_constructor_succeeds() {
        let _ =
            KeyringCredentialStore::try_new().expect("desktop credential constructor should work");
    }
}

#[cfg(test)]
mod private_custody_tests {
    use super::*;

    #[test]
    fn private_key_write_and_keychain_failure_never_write_a_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let legacy = directory.path().join("legacy.key");
        let entry = Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default()));
        write_private_signing_key(&entry, &[7; 32]).unwrap();
        assert_eq!(
            read_private_signing_key(&entry, &legacy).unwrap(),
            Some(vec![7; 32])
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        entry
            .get_credential()
            .downcast_ref::<keyring::mock::MockCredential>()
            .unwrap()
            .set_error(keyring::Error::Invalid("synthetic".into(), "denied".into()));
        assert!(matches!(
            write_private_signing_key(&entry, &[8; 32]),
            Err(PrivateSigningKeyError::KeychainUnavailable(_))
        ));
        assert_eq!(
            read_private_signing_key(&entry, &legacy).unwrap(),
            Some(vec![7; 32])
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn legacy_only_identity_fails_closed_and_preserves_file() {
        let directory = tempfile::tempdir().unwrap();
        let legacy = directory.path().join("legacy.key");
        std::fs::write(&legacy, b"synthetic legacy sentinel").unwrap();
        let entry = Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default()));
        assert!(matches!(
            read_private_signing_key(&entry, &legacy),
            Err(PrivateSigningKeyError::LegacyMigrationRequired)
        ));
        assert_eq!(
            std::fs::read(&legacy).unwrap(),
            b"synthetic legacy sentinel"
        );
        write_private_signing_key(&entry, &[9; 32]).unwrap();
        assert_eq!(
            read_private_signing_key(&entry, &legacy).unwrap(),
            Some(vec![9; 32])
        );
        assert_eq!(
            std::fs::read(&legacy).unwrap(),
            b"synthetic legacy sentinel"
        );
        entry
            .get_credential()
            .downcast_ref::<keyring::mock::MockCredential>()
            .unwrap()
            .set_error(keyring::Error::Invalid("synthetic".into(), "denied".into()));
        assert!(matches!(
            read_private_signing_key(&entry, &legacy),
            Err(PrivateSigningKeyError::KeychainUnavailable(_))
        ));
        assert_eq!(
            std::fs::read(&legacy).unwrap(),
            b"synthetic legacy sentinel"
        );
    }
}
