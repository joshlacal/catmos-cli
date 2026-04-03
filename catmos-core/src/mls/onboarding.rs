//! MLS device onboarding: registration, welcome processing, external commit
//! joining, and group metadata decryption.
//!
//! This module implements the complete flow that makes a catmos-cli device
//! capable of decrypting messages in existing MLS conversations.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use catbird_atproto::catbird::mls_chat;

use super::MlsManager;
use crate::chat::ChatService;
use crate::error::{CatmosError, Result};
use crate::storage::db::Database;

// ── Types ──────────────────────────────────────────────────────────────

/// Locally-persisted device registration info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub mls_did: String,
    pub device_uuid: String,
    pub signature_public_key: Vec<u8>,
}

/// Decrypted group metadata from MLS group context extensions.
#[derive(Debug, Clone)]
pub struct GroupMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// Response shape for registerDevice (owned, DeserializeOwned-compatible).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDeviceResp {
    device_id: String,
    mls_did: String,
    #[serde(default)]
    welcome_messages: Vec<WelcomeMessageResp>,
    #[serde(default)]
    auto_joined_convos: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WelcomeMessageResp {
    convo_id: String,
    welcome: String, // base64-encoded
}

// ── Session DB keys ────────────────────────────────────────────────────

const KEY_DEVICE_ID: &str = "mls_device_id";
const KEY_MLS_DID: &str = "mls_did";
const KEY_DEVICE_UUID: &str = "device_uuid";

// ── MlsManager onboarding methods ─────────────────────────────────────

impl MlsManager {
    /// Full MLS device registration flow.
    ///
    /// 1. Get-or-create a persistent device UUID
    /// 2. Create 25 key packages via the MLS context
    /// 3. Call `registerDevice` XRPC
    /// 4. Process welcome messages from the response
    /// 5. Persist device info to the session DB
    pub async fn register_device(
        &self,
        service: &ChatService,
        did: &str,
        device_name: &str,
        db: &Database,
    ) -> Result<DeviceInfo> {
        info!("Starting MLS device registration for {did}");

        // 1. Device UUID — reuse if present, else generate
        let device_uuid = match db.get_session_value(KEY_DEVICE_UUID).await? {
            Some(uuid) => {
                info!("Reusing existing device UUID: {uuid}");
                uuid
            }
            None => {
                let uuid = uuid::Uuid::new_v4().to_string();
                db.store_session_value(KEY_DEVICE_UUID, &uuid).await?;
                info!("Generated new device UUID: {uuid}");
                uuid
            }
        };

        // 2. Create key packages (identity = bare user DID as UTF-8 bytes)
        let identity = did.as_bytes().to_vec();
        let packages = self.create_key_packages(&identity, 25)?;
        info!("Created {} key packages", packages.len());

        // The signature public key comes from the first key package (all share the same signer)
        let signature_public_key = packages
            .first()
            .map(|kp| kp.signature_public_key.clone())
            .unwrap_or_default();

        // 3. Build XRPC request
        let now = chrono::Utc::now();
        let expires_str = (now + chrono::Duration::days(30))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let key_packages: Vec<mls_chat::register_device::KeyPackageItem> = packages
            .iter()
            .map(|kp| {
                mls_chat::register_device::KeyPackageItemData {
                    cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
                    expires: expires_str.parse().expect("valid datetime"),
                    key_package: BASE64.encode(&kp.key_package_data),
                }
                .into()
            })
            .collect();

        let req: mls_chat::register_device::Input =
            mls_chat::register_device::InputData {
                device_name: device_name.to_string(),
                device_uuid: Some(device_uuid.clone()),
                signature_public_key: signature_public_key.clone(),
                key_packages,
            }
            .into();

        // 4. Call registerDevice
        let resp: RegisterDeviceResp = service
            .xrpc_procedure(mls_chat::register_device::NSID, &req)
            .await?;

        info!(
            "Device registered: id={}, mls_did={}, welcomes={}, auto_joined={}",
            resp.device_id,
            resp.mls_did,
            resp.welcome_messages.len(),
            resp.auto_joined_convos.len()
        );

        // 5. Process welcome messages
        for wm in &resp.welcome_messages {
            match self.process_welcome_b64(&wm.welcome, did) {
                Ok(group_id) => {
                    info!(
                        "Joined convo {} via welcome (group={})",
                        wm.convo_id,
                        hex::encode(&group_id)
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to process welcome for convo {}: {e}",
                        wm.convo_id
                    );
                }
            }
        }

        // 6. Persist device info
        db.store_session_value(KEY_DEVICE_ID, &resp.device_id)
            .await?;
        db.store_session_value(KEY_MLS_DID, &resp.mls_did).await?;

        let info = DeviceInfo {
            device_id: resp.device_id,
            mls_did: resp.mls_did,
            device_uuid,
            signature_public_key,
        };

        Ok(info)
    }

    /// Process a base64-encoded welcome message to join a group.
    /// Returns the group ID bytes on success.
    pub fn process_welcome_b64(&self, welcome_b64: &str, did: &str) -> Result<Vec<u8>> {
        let welcome_bytes = BASE64
            .decode(welcome_b64)
            .map_err(|e| CatmosError::Other(format!("Invalid base64 welcome: {e}")))?;
        self.process_welcome(&welcome_bytes, did)
    }

    /// Process raw welcome bytes to join a group.
    /// Returns the group ID bytes on success.
    pub fn process_welcome(&self, welcome_bytes: &[u8], did: &str) -> Result<Vec<u8>> {
        let identity = did.as_bytes().to_vec();
        let result = self.with_context(|ctx| {
            ctx.process_welcome(welcome_bytes.to_vec(), identity, None)
        })?;
        Ok(result.group_id)
    }

    /// Join a conversation via external commit.
    ///
    /// 1. Fetch group info from the server
    /// 2. Create an external commit via the MLS context
    /// 3. Send the commit to the server
    /// 4. On failure, discard the pending join and optionally retry once
    pub async fn join_via_external_commit(
        &self,
        service: &ChatService,
        convo_id: &str,
        did: &str,
    ) -> Result<()> {
        self.try_external_commit(service, convo_id, did).await
    }

    async fn try_external_commit(
        &self,
        service: &ChatService,
        convo_id: &str,
        did: &str,
    ) -> Result<()> {
        // 1. Fetch group info
        let group_state: serde_json::Value = service
            .xrpc_query(
                mls_chat::get_group_state::NSID,
                &[("convoId", convo_id), ("include", "groupInfo")],
            )
            .await?;

        let group_info_b64 = group_state
            .get("groupInfo")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                CatmosError::Other(format!(
                    "getGroupState response missing groupInfo for {convo_id}"
                ))
            })?;

        let group_info_bytes = BASE64.decode(group_info_b64).map_err(|e| {
            CatmosError::Other(format!("Invalid base64 groupInfo: {e}"))
        })?;

        // 2. Create external commit
        let identity = did.as_bytes().to_vec();
        let ext_result = self.with_context(|ctx| {
            ctx.create_external_commit(group_info_bytes.clone(), identity)
        })?;

        debug!(
            "Created external commit for {} ({} bytes), group_id={}",
            convo_id,
            ext_result.commit_data.len(),
            hex::encode(&ext_result.group_id)
        );

        // 3. Send the commit to the server
        let commit_b64 = BASE64.encode(&ext_result.commit_data);

        let req: mls_chat::commit_group_change::Input =
            mls_chat::commit_group_change::InputData {
                convo_id: convo_id.to_string(),
                action: "processExternalCommit".to_string(),
                commit: Some(commit_b64),
                device_id: None,
                group_info: None,
                idempotency_key: None,
                key_package_hashes: None,
                member_dids: None,
                pending_addition_id: None,
                welcome: None,
            }
            .into();

        match service
            .xrpc_procedure::<_, serde_json::Value>(
                mls_chat::commit_group_change::NSID,
                &req,
            )
            .await
        {
            Ok(_) => {
                info!("Joined conversation {convo_id} via external commit");
                Ok(())
            }
            Err(e) => {
                // Discard the pending join to avoid orphaned crypto state
                warn!("External commit rejected for {convo_id}: {e}");
                if let Err(discard_err) = self.with_context(|ctx| {
                    ctx.discard_pending_external_join(ext_result.group_id)
                }) {
                    warn!("Failed to discard pending join: {discard_err}");
                }
                Err(e)
            }
        }
    }

    /// Decrypt group metadata from MLS group context extensions.
    ///
    /// Returns `Ok(None)` if the group has no metadata set or if the group is
    /// not found in local MLS state.
    pub fn decrypt_group_metadata(&self, group_id: &[u8]) -> Result<Option<GroupMetadata>> {
        if group_id.is_empty() {
            return Ok(None);
        }

        let metadata_bytes = self
            .with_context(|ctx| ctx.get_group_metadata(group_id.to_vec()))?;

        if metadata_bytes.is_empty() {
            return Ok(None);
        }

        // Parse as {"v":1,"name":"...","description":"..."}
        #[derive(Deserialize)]
        struct MetadataJson {
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            description: Option<String>,
        }

        match serde_json::from_slice::<MetadataJson>(&metadata_bytes) {
            Ok(meta) => Ok(Some(GroupMetadata {
                name: meta.name,
                description: meta.description,
            })),
            Err(e) => {
                warn!("Failed to parse group metadata JSON: {e}");
                Ok(None)
            }
        }
    }

    /// Main entry point: ensure this device is registered and has joined all
    /// available conversations.
    ///
    /// - If already registered (device_id in DB), loads and returns the info.
    /// - Otherwise, performs full registration.
    /// - After registration, attempts to join any conversations lacking local
    ///   MLS state via external commit.
    pub async fn ensure_registered(
        &self,
        service: &ChatService,
        did: &str,
        db: &Database,
    ) -> Result<DeviceInfo> {
        // Check if already registered
        if let (Some(device_id), Some(mls_did)) = (
            db.get_session_value(KEY_DEVICE_ID).await?,
            db.get_session_value(KEY_MLS_DID).await?,
        ) {
            let device_uuid = db
                .get_session_value(KEY_DEVICE_UUID)
                .await?
                .unwrap_or_default();

            info!("Device already registered: {device_id}");
            return Ok(DeviceInfo {
                device_id,
                mls_did,
                device_uuid,
                signature_public_key: Vec::new(), // not needed post-registration
            });
        }

        // Not yet registered — do full registration
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "catmos-cli".to_string());
        let device_name = format!("catmos-cli ({})", hostname);

        match self.register_device(service, did, &device_name, db).await {
            Ok(info) => Ok(info),
            Err(e) => {
                // Check for "already registered" in the error message
                let msg = e.to_string();
                if msg.contains("TooManyDevices") {
                    warn!("Too many devices registered — skipping registration");
                    return Err(CatmosError::Other(
                        "Too many devices registered. Remove a device first.".into(),
                    ));
                }
                if msg.contains("DeviceAlreadyRegistered") || msg.contains("already registered") {
                    warn!("Device already registered on server, loading existing info");
                    // Try to load from the list_devices endpoint
                    let devices = service.list_devices().await?;
                    if let Some(dev) = devices.first() {
                        db.store_session_value(KEY_DEVICE_ID, &dev.device_id)
                            .await?;
                        db.store_session_value(KEY_MLS_DID, &dev.mls_did).await?;
                        return Ok(DeviceInfo {
                            device_id: dev.device_id.clone(),
                            mls_did: dev.mls_did.clone(),
                            device_uuid: db
                                .get_session_value(KEY_DEVICE_UUID)
                                .await?
                                .unwrap_or_default(),
                            signature_public_key: Vec::new(),
                        });
                    }
                }
                Err(e)
            }
        }
    }
}

impl ChatService {
    /// After fetching conversations, try to decrypt MLS group metadata
    /// for each conversation to populate names/descriptions.
    pub fn apply_group_metadata(&self, convos: &mut [crate::types::Conversation]) {
        for convo in convos.iter_mut() {
            let group_id_bytes = match hex::decode(&convo.group_id) {
                Ok(b) => b,
                Err(_) => continue,
            };

            match self.mls.decrypt_group_metadata(&group_id_bytes) {
                Ok(Some(meta)) => {
                    if convo.name.is_none() {
                        convo.name = meta.name;
                    }
                    if convo.description.is_none() {
                        convo.description = meta.description;
                    }
                }
                Ok(None) => {} // no metadata
                Err(e) => {
                    debug!(
                        "Could not decrypt metadata for {}: {e}",
                        &convo.group_id[..12.min(convo.group_id.len())]
                    );
                }
            }
        }
    }

    /// Attempt to join conversations that this device doesn't have local
    /// MLS state for, via external commit.
    pub async fn join_missing_conversations(&self, did: &str) {
        let convos = self.conversations.read().await.clone();
        for convo in &convos {
            // Check if we already have local state by trying to get the epoch
            let group_id_bytes = match hex::decode(&convo.group_id) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let has_local_state = self
                .mls
                .with_context(|ctx| ctx.get_epoch(group_id_bytes))
                .is_ok();

            if !has_local_state {
                info!(
                    "No local MLS state for convo {}, attempting external commit",
                    &convo.group_id[..12.min(convo.group_id.len())]
                );
                match self
                    .mls
                    .join_via_external_commit(self, &convo.group_id, did)
                    .await
                {
                    Ok(()) => info!("Joined {} via external commit", convo.group_id),
                    Err(e) => warn!(
                        "Failed to join {} via external commit: {e}",
                        &convo.group_id[..12.min(convo.group_id.len())]
                    ),
                }
            }
        }
    }
}
