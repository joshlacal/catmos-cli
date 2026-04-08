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
        let expires_str =
            (now + chrono::Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

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

        let req: mls_chat::register_device::Input = mls_chat::register_device::InputData {
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
                    warn!("Failed to process welcome for convo {}: {e}", wm.convo_id);
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
        let result =
            self.with_context(|ctx| ctx.process_welcome(welcome_bytes.to_vec(), identity, None))?;
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
        self.try_external_commit_with_retry(service, convo_id, did, 1)
            .await
    }

    async fn try_external_commit_with_retry(
        &self,
        service: &ChatService,
        convo_id: &str,
        did: &str,
        max_retries: u32,
    ) -> Result<()> {
        let convo_label = &convo_id[..12.min(convo_id.len())];
        let mut retries_left = max_retries;

        loop {
            info!("try_external_commit: fetching groupInfo for convo {convo_label} (retries_left={retries_left})");

            // 1. Fetch group info (with retry on GroupInfoUnavailable)
            let group_info_b64 = match self.fetch_group_info(service, convo_id).await {
                Ok(info) => info,
                Err(e) if Self::is_group_info_unavailable(&e) && retries_left > 0 => {
                    warn!(
                        "try_external_commit: GroupInfo unavailable for {convo_label}, \
                         requesting refresh and retrying ({retries_left} retries left)"
                    );

                    // Request a GroupInfo refresh from other devices via SSE
                    if let Err(refresh_err) =
                        self.request_group_info_refresh(service, convo_id).await
                    {
                        warn!(
                            "try_external_commit: failed to request GroupInfo refresh for {convo_label}: {refresh_err}"
                        );
                        return Err(e);
                    }

                    info!(
                        "try_external_commit: GroupInfo refresh requested for {convo_label}, \
                         waiting 5s for iOS devices to publish"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                    // Retry fetch
                    match self.fetch_group_info(service, convo_id).await {
                        Ok(info) => {
                            info!("try_external_commit: GroupInfo now available for {convo_label} after refresh");
                            info
                        }
                        Err(retry_err) => {
                            warn!(
                                "try_external_commit: GroupInfo still unavailable for {convo_label} after refresh: {retry_err}"
                            );
                            return Err(retry_err);
                        }
                    }
                }
                Err(e) => return Err(e),
            };

            let group_info_bytes = BASE64
                .decode(&group_info_b64)
                .map_err(|e| CatmosError::Other(format!("Invalid base64 groupInfo: {e}")))?;

            info!(
                "try_external_commit: decoded groupInfo for {convo_label} — {} bytes",
                group_info_bytes.len()
            );

            // 2. Create external commit
            let identity = did.as_bytes().to_vec();
            let ext_result = self.with_context(|ctx| {
                ctx.create_external_commit(group_info_bytes.clone(), identity)
            })?;

            debug!(
                "Created external commit for {convo_label} ({} bytes), group_id={}",
                ext_result.commit_data.len(),
                hex::encode(&ext_result.group_id)
            );

            // 3. Send the commit to the server (with GroupInfo so other clients can join)
            let commit_b64 = BASE64.encode(&ext_result.commit_data);
            let group_info_b64 = ext_result.group_info.as_ref().map(|gi| BASE64.encode(gi));

            // Get confirmation tag from the new local group state after external commit
            let tag_b64 = self
                .with_context(|ctx| ctx.get_confirmation_tag(ext_result.group_id.clone()))
                .map(|tag| BASE64.encode(&tag))
                .ok();

            let req: mls_chat::commit_group_change::Input =
                mls_chat::commit_group_change::InputData {
                    convo_id: convo_id.to_string(),
                    action: "externalCommit".to_string(),
                    commit: Some(commit_b64),
                    confirmation_tag: tag_b64,
                    device_id: None,
                    group_info: group_info_b64,
                    idempotency_key: None,
                    key_package_hashes: None,
                    member_dids: None,
                    pending_addition_id: None,
                    welcome: None,
                }
                .into();

            match service
                .xrpc_procedure::<_, serde_json::Value>(mls_chat::commit_group_change::NSID, &req)
                .await
            {
                Ok(_) => {
                    // Server accepted — merge the pending external join locally
                    // to finalize the new group state (spec compliance).
                    match self.with_context(|ctx| {
                        ctx.merge_pending_commit(ext_result.group_id.clone())
                    }) {
                        Ok(result) => {
                            info!(
                                "Joined conversation {convo_id} via external commit (epoch {})",
                                result.new_epoch
                            );
                        }
                        Err(e) => {
                            // Non-fatal: the group state may still be usable after
                            // the next sync processes the commit we just sent.
                            warn!(
                                "merge_pending_commit failed after external commit for {convo_label}: {e}"
                            );
                        }
                    }
                    return Ok(());
                }
                Err(e) => {
                    // Discard the pending join to avoid orphaned crypto state
                    warn!("External commit rejected for {convo_label}: {e}");
                    if let Err(discard_err) = self
                        .with_context(|ctx| ctx.discard_pending_external_join(ext_result.group_id))
                    {
                        warn!("Failed to discard pending join: {discard_err}");
                    }

                    // On 409 (epoch conflict), retry with fresh GroupInfo
                    if Self::is_epoch_conflict(&e) && retries_left > 0 {
                        retries_left -= 1;
                        warn!(
                            "try_external_commit: 409 epoch conflict for {convo_label}, \
                             retrying with fresh GroupInfo ({retries_left} retries left)"
                        );
                        continue;
                    }

                    return Err(e);
                }
            }
        }
    }

    /// Check whether an error indicates a 409 epoch conflict.
    fn is_epoch_conflict(err: &CatmosError) -> bool {
        let msg = err.to_string();
        msg.contains("returned 409") || msg.contains("EpochMismatch")
    }

    /// Fetch the base64-encoded GroupInfo for a conversation from the server.
    async fn fetch_group_info(&self, service: &ChatService, convo_id: &str) -> Result<String> {
        let group_state: serde_json::Value = service
            .xrpc_query(
                mls_chat::get_group_state::NSID,
                &[("convoId", convo_id), ("include", "groupInfo")],
            )
            .await?;

        debug!(
            "fetch_group_info: getGroupState response keys: {:?}",
            group_state
                .as_object()
                .map(|o| o.keys().collect::<Vec<_>>())
        );

        group_state
            .get("groupInfo")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                CatmosError::Other(format!(
                    "GroupInfoUnavailable: getGroupState response missing groupInfo for {convo_id}"
                ))
            })
    }

    /// Check whether an error indicates that GroupInfo is unavailable
    /// (404 from the server or missing groupInfo field in the response).
    fn is_group_info_unavailable(err: &CatmosError) -> bool {
        let msg = err.to_string();
        msg.contains("GroupInfoUnavailable")
            || msg.contains("missing groupInfo")
            || msg.contains("returned 404")
    }

    /// Ask the server to request a GroupInfo refresh from other devices.
    /// This sends an SSE event so that iOS clients can publish fresh GroupInfo.
    async fn request_group_info_refresh(
        &self,
        service: &ChatService,
        convo_id: &str,
    ) -> Result<()> {
        let req = serde_json::json!({
            "convoId": convo_id,
            "action": "refreshGroupInfo"
        });
        let _: serde_json::Value = service
            .xrpc_procedure(mls_chat::commit_group_change::NSID, &req)
            .await?;
        info!(
            "request_group_info_refresh: sent refreshGroupInfo for {}",
            &convo_id[..12.min(convo_id.len())]
        );
        Ok(())
    }

    /// Decrypt group metadata from MLS group context extensions.
    ///
    /// Returns `Ok(None)` if the group has no metadata set or if the group is
    /// not found in local MLS state.
    pub fn decrypt_group_metadata(&self, group_id: &[u8]) -> Result<Option<GroupMetadata>> {
        if group_id.is_empty() {
            return Ok(None);
        }

        let metadata_bytes = self.with_context(|ctx| ctx.get_group_metadata(group_id.to_vec()))?;

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
        info!(
            "join_missing_conversations: checking {} conversations for missing local MLS state",
            convos.len()
        );

        let mut joined = 0u32;
        let mut skipped = 0u32;
        let mut failed = 0u32;

        for convo in &convos {
            let convo_label = convo
                .name
                .as_deref()
                .unwrap_or(&convo.group_id[..12.min(convo.group_id.len())]);

            // Check if we already have local state by trying to get the epoch
            let group_id_bytes = match hex::decode(&convo.group_id) {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        "join_missing_conversations: invalid hex group_id for {convo_label}: {e}"
                    );
                    continue;
                }
            };

            let has_local_state = self
                .mls
                .with_context(|ctx| ctx.get_epoch(group_id_bytes.clone()))
                .is_ok();

            if has_local_state {
                skipped += 1;
                debug!("join_missing_conversations: {convo_label} — already have local state");
                continue;
            }

            // Try syncing commits first — if another device already committed,
            // processing those commits may give us local state without needing
            // an external commit (which inflates the epoch).
            info!(
                "join_missing_conversations: {convo_label} — no local MLS state, syncing commits first"
            );
            if let Err(e) = self.sync_conversation(&convo.group_id).await {
                debug!("join_missing_conversations: {convo_label} — sync failed (expected if no local state): {e}");
            }

            // Re-check: did sync give us local state?
            let has_state_after_sync = self
                .mls
                .with_context(|ctx| ctx.get_epoch(group_id_bytes.clone()))
                .is_ok();

            if has_state_after_sync {
                skipped += 1;
                info!("join_missing_conversations: {convo_label} — acquired local state via sync, skipping external commit");
                continue;
            }

            info!(
                "join_missing_conversations: {convo_label} — still no local MLS state, attempting external commit"
            );
            match self
                .mls
                .join_via_external_commit(self, &convo.group_id, did)
                .await
            {
                Ok(()) => {
                    joined += 1;
                    info!("join_missing_conversations: {convo_label} — joined via external commit");
                }
                Err(e) => {
                    failed += 1;
                    warn!(
                        "join_missing_conversations: {convo_label} — external commit failed: {e}"
                    );
                }
            }
        }

        info!(
            "join_missing_conversations: done — joined={joined}, skipped={skipped} (already had state), failed={failed}"
        );
    }
}
