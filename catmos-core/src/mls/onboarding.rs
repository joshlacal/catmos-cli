//! MLS device onboarding: registration, welcome processing, external commit
//! joining, and group metadata decryption.
//!
//! This module implements the complete flow that makes a catmos-cli device
//! capable of decrypting messages in existing MLS conversations.

use sha2::{Digest, Sha256};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::{MlsManager, MLS_CIPHER_SUITE};
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

fn derive_key_id(public_key: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

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
            Some(uuid) if !uuid.trim().is_empty() => {
                info!("Reusing existing device UUID: {uuid}");
                uuid
            }
            _ => {
                let uuid = uuid::Uuid::new_v4().to_string();
                db.store_session_value(KEY_DEVICE_UUID, &uuid).await?;
                info!("Generated new device UUID: {uuid}");
                uuid
            }
        };

        // 2. Create key packages (identity = bare user DID#device_uuid as UTF-8 bytes)
        let mls_did = format!("{did}#{device_uuid}");
        let identity_bytes = mls_did.as_bytes().to_vec();
        let packages = self.create_key_packages(&identity_bytes, 25)?;
        info!("Created {} key packages", packages.len());

        // Sort packages strictly by hash_ref (keyPackageRef)
        let mut packages = packages;
        packages.sort_by(|a, b| a.hash_ref.cmp(&b.hash_ref));

        // The signature public key comes from the first key package (all share the same signer)
        let signature_public_key = packages
            .first()
            .map(|kp| kp.signature_public_key.clone())
            .unwrap_or_default();
        let key_id = derive_key_id(&signature_public_key);

        // 3. Build canonical v2 deviceEnrollmentBody
        let key_packages_json: Vec<serde_json::Value> = packages
            .iter()
            .map(|kp| {
                serde_json::json!({
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": BASE64.encode(&kp.key_package_data),
                    "sha256": BASE64.encode(Sha256::digest(&kp.key_package_data)),
                    "keyPackageRef": BASE64.encode(&kp.hash_ref),
                })
            })
            .collect();

        let signed_at = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\0",
            "actorDid": did,
            "deviceId": device_uuid,
            "deviceName": if device_name.is_empty() { "catmos-cli" } else { device_name },
            "keyId": key_id,
            "signaturePublicKey": BASE64.encode(&signature_public_key),
            "expectedAuthGeneration": 0,
            "capability": {
                "protocolVersion": "1",
                "mlsVersion": "1.0",
                "cipherSuite": MLS_CIPHER_SUITE,
                "credentialType": "basic",
                "addByValue": "supported",
                "updatePath": "supported",
                "removeByValue": "supported",
                "ratchetTreeGroupInfo": "supported",
                "externalPubGroupInfo": "presentButExternalCommitsForbidden",
                "applicationFrameProfile": "dagCborApplication1",
                "controlProfile": "publicGroup1",
                "attachmentProfile": "aes256GcmBlob1",
                "metadataProfile": "exporterAes256Gcm1",
                "typingProfile": "signedClearEphemeral1"
            },
            "keyPackages": key_packages_json,
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "signedAt": signed_at,
        });

        // 4. Prepare signed request envelope using canonical transport
        let binding = catbird_mls::orchestrator::CleanChatSigningContext {
            actor_did: did.to_string(),
            device_id: device_uuid.clone(),
            auth_generation: None,
        };
        let prepared = catbird_mls::orchestrator::canonical_transport::prepare_signed_request_with(
            &binding,
            catbird_mls::orchestrator::CanonicalOperation::EnrollDevice,
            serde_json::to_vec(&body).map_err(|e| CatmosError::Mls(catbird_mls::MLSError::Internal(e.to_string())))?,
            |transcript| {
                self.with_context(|ctx| {
                    ctx.sign_with_identity_key(mls_did.clone(), transcript.to_vec())
                })
                .map_err(|_| catbird_mls::orchestrator::TransportError::Signing)
            },
        )
        .map_err(|e| CatmosError::Mls(catbird_mls::MLSError::Internal(e.to_string())))?;

        let prepared_body_bytes = prepared.body.ok_or_else(|| {
            CatmosError::Mls(catbird_mls::MLSError::Internal("Prepared enrollment body is missing".into()))
        })?;


        // 5. Submit to enrollDevice
        let resp: serde_json::Value = service
            .xrpc_post_raw("blue.catbird.chat.enrollDevice", &prepared_body_bytes)
            .await?;

        let device_obj = resp.get("device").unwrap_or(&resp);
        let server_device_id = device_obj
            .get("deviceId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CatmosError::Xrpc("enrollDevice response missing deviceId".into()))?
            .to_string();
        if server_device_id != device_uuid {
            return Err(CatmosError::AuthFailed(format!(
                "server substituted device ID {} for client ID {}",
                server_device_id, device_uuid
            )));
        }
        let mls_did = format!("{did}#{server_device_id}");

        // 6. Persist device info
        db.store_session_value(KEY_DEVICE_ID, &server_device_id).await?;
        db.store_session_value(KEY_MLS_DID, &mls_did).await?;

        info!("Device registered successfully: id={}, mls_did={}", server_device_id, mls_did);

        let info = DeviceInfo {
            device_id: server_device_id,
            mls_did,
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
    ///
    /// NOTE: The §8.4 recovery path in `recovery_ops.rs` does NOT call this —
    /// it must fetch GroupInfo BEFORE deleting local state, so it uses
    /// `external_commit_with_group_info` directly after its own fetch.
    pub async fn join_via_external_commit(
        &self,
        service: &ChatService,
        convo_id: &str,
        did: &str,
    ) -> Result<()> {
        self.try_external_commit(service, convo_id, did).await
    }

    /// Steps 3-5 of §8.4 EXTERNAL_COMMIT_REJOIN: given an already-fetched
    /// base64 GroupInfo blob, create the External Commit, send it, and merge.
    /// On any failure the half-built `MlsGroup` is discarded via
    /// `discard_pending_external_join` (§8.4.1).
    ///
    /// Used by `ChatService::external_commit_rejoin` so the GroupInfo fetch
    /// happens before local state is deleted.
    pub(crate) async fn external_commit_with_group_info(
        &self,
        service: &ChatService,
        convo_id: &str,
        did: &str,
        group_info_b64: &str,
    ) -> Result<()> {
        let convo_label = &convo_id[..12.min(convo_id.len())];
        let group_info_bytes = BASE64
            .decode(group_info_b64)
            .map_err(|e| CatmosError::Other(format!("Invalid base64 groupInfo: {e}")))?;

        info!(
            "external_commit_with_group_info: decoded groupInfo for {convo_label} — {} bytes",
            group_info_bytes.len()
        );

        let identity = did.as_bytes().to_vec();
        let ext_result =
            self.with_context(|ctx| ctx.create_external_commit(group_info_bytes, identity))?;

        debug!(
            "Created external commit for {convo_label} ({} bytes), group_id={}",
            ext_result.commit_data.len(),
            hex::encode(&ext_result.group_id)
        );

        let tag_bytes = self
            .with_context(|ctx| ctx.get_confirmation_tag(ext_result.group_id.clone()))
            .ok();

        let req = crate::chat::service::build_commit_group_change(
            convo_id,
            "externalCommit",
            Some(ext_result.commit_data.clone()),
            None,
            ext_result.group_info.clone(),
            tag_bytes,
            None,
            None,
        );

        match service
            .xrpc_procedure::<_, serde_json::Value>("blue.catbird.chat.submitTransition", &req)
            .await
        {
            Ok(_) => {
                match self.with_context(|ctx| ctx.merge_pending_commit(ext_result.group_id.clone()))
                {
                    Ok(result) => {
                        info!(
                            "Joined conversation {convo_id} via external commit (epoch {})",
                            result.new_epoch
                        );
                        // Encrypted-bootstrap after external-commit join.
                        // `convo_id` here is the hex group id (matches how
                        // `bootstrap_group_metadata` is wired in
                        // sync_conversation). Failure is non-fatal.
                        let group_id_hex = hex::encode(&ext_result.group_id);
                        if let Err(e) = service
                            .bootstrap_group_metadata(convo_id, &group_id_hex)
                            .await
                        {
                            warn!(
                                "external_commit_with_group_info: bootstrap_group_metadata failed for {convo_label}: {e}"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "merge_pending_commit failed after external commit for {convo_label}: {e}"
                        );
                    }
                }
                Ok(())
            }
            Err(e) => {
                warn!("External commit rejected for {convo_label}: {e}");
                if let Err(discard_err) =
                    self.with_context(|ctx| ctx.discard_pending_external_join(ext_result.group_id))
                {
                    warn!("Failed to discard pending join: {discard_err}");
                }
                Err(e)
            }
        }
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

            // 3. Send the commit to the server (with GroupInfo so other clients can join).
            //
            // Build CommitGroupChange<'static> directly (via
            // `chat::service::build_commit_group_change`) to bypass the
            // double-encoding trap in `petrel_catbird::generated::blue::catbird::chat::
            // commit_group_change::InputData`. That wrapper types bytes fields
            // as `Option<String>` and maps them via `bytes::Bytes::from(String)`
            // which takes the UTF-8 bytes of the string verbatim — passing a
            // pre-base64-encoded string (the old pattern here) resulted in
            // `{"$bytes": base64(ASCII-of-base64)}` on the wire, which the
            // server then decodes into ASCII-of-base64 garbage instead of the
            // raw commit. That's the root of the MLS-joining blocker tracked
            // in `project_catmos_cli_status.md`. See #64 commit for the full
            // rationale; the fix applies identically to this external-commit
            // path.

            // Get confirmation tag from the new local group state after external commit
            let tag_bytes = self
                .with_context(|ctx| ctx.get_confirmation_tag(ext_result.group_id.clone()))
                .ok();

            let req = crate::chat::service::build_commit_group_change(
                convo_id,
                "externalCommit",
                Some(ext_result.commit_data.clone()),
                None, // welcome: none for externalCommit (server
                // enforce_non_add_action_contract rejects it)
                ext_result.group_info.clone(),
                tag_bytes,
                None, // member_dids: none for externalCommit (same gate)
                None, // idempotency_key
            );

            match service
                .xrpc_procedure::<_, serde_json::Value>("blue.catbird.chat.submitTransition", &req)
                .await
            {
                Ok(_) => {
                    // Server accepted — merge the pending external join locally
                    // to finalize the new group state (spec compliance).
                    match self
                        .with_context(|ctx| ctx.merge_pending_commit(ext_result.group_id.clone()))
                    {
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
    ///
    /// The server returns `groupInfo` in AT Protocol `{"$bytes": "base64..."}`
    /// wrapper form (matches the regenerated mls-ds types). Older server builds
    /// emitted a plain base64 string. Accept both so CLI keeps working while
    /// the wire format evolves.
    pub(crate) async fn fetch_group_info(
        &self,
        service: &ChatService,
        convo_id: &str,
    ) -> Result<String> {
        let actor_device_id = service.actor_device_id().await?;
        let group_state: serde_json::Value = service
            .xrpc_query(
                "blue.catbird.chat.getConversationState",
                &[
                    ("actorDeviceId", &actor_device_id),
                    ("convoId", convo_id),
                    ("conversationId", convo_id),
                    ("include", "groupInfo"),
                ],
            )
            .await?;

        debug!(
            "fetch_group_info: getGroupState response keys: {:?}",
            group_state
                .as_object()
                .map(|o| o.keys().collect::<Vec<_>>())
        );

        let gi = group_state.get("groupInfo").ok_or_else(|| {
            CatmosError::Other(format!(
                "GroupInfoUnavailable: getGroupState response missing groupInfo for {convo_id}"
            ))
        })?;

        if let Some(s) = gi.as_str() {
            return Ok(s.to_string());
        }
        if let Some(b) = gi.get("$bytes").and_then(|v| v.as_str()) {
            return Ok(b.to_string());
        }

        Err(CatmosError::Other(format!(
            "GroupInfoUnavailable: unexpected groupInfo shape {gi:?} for {convo_id}"
        )))
    }

    /// Check whether an error indicates that GroupInfo is unavailable
    /// (404 from the server or missing groupInfo field in the response).
    pub(crate) fn is_group_info_unavailable(err: &CatmosError) -> bool {
        let msg = err.to_string();
        msg.contains("GroupInfoUnavailable")
            || msg.contains("missing groupInfo")
            || msg.contains("returned 404")
    }

    /// Fetch a pending base64-encoded Welcome message addressed to this caller
    /// for `convo_id`, if one exists on the server. Returns `Ok(None)` when the
    /// server has no pending Welcome (the response simply omits the field).
    /// Returns `Err` for transport / non-404 server errors.
    pub(crate) async fn fetch_pending_welcome(
        &self,
        service: &ChatService,
        convo_id: &str,
    ) -> Result<Option<String>> {
        let actor_device_id = service.actor_device_id().await?;
        let group_state: serde_json::Value = match service
            .xrpc_query(
                "blue.catbird.chat.getConversationState",
                &[
                    ("actorDeviceId", &actor_device_id),
                    ("convoId", convo_id),
                    ("conversationId", convo_id),
                    ("include", "welcome"),
                ],
            )
            .await
        {
            Ok(v) => v,
            Err(e) if Self::is_group_info_unavailable(&e) => return Ok(None),
            Err(e) => return Err(e),
        };

        let Some(w) = group_state.get("welcome") else {
            return Ok(None);
        };
        if let Some(s) = w.as_str() {
            return Ok(Some(s.to_string()));
        }
        if let Some(b) = w.get("$bytes").and_then(|v| v.as_str()) {
            return Ok(Some(b.to_string()));
        }
        Ok(None)
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
            .xrpc_procedure("blue.catbird.chat.submitTransition", &req)
            .await?;
        info!(
            "request_group_info_refresh: sent refreshGroupInfo for {}",
            &convo_id[..12.min(convo_id.len())]
        );
        Ok(())
    }

    // `decrypt_group_metadata` (legacy 0xff00 plaintext reader) removed in
    // Phase F. Encrypted metadata is fetched via
    // `chat/metadata.rs::bootstrap_group_metadata` which decodes the
    // ciphertext blob from the DS using the per-epoch exporter-derived key.

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

// `apply_group_metadata` (legacy 0xff00 fallback for fetch_conversations)
// removed in Phase F. The encrypted bootstrap path
// (chat/metadata.rs::bootstrap_group_metadata) handles all post-cutover
// metadata population.

impl ChatService {
    /// Attempt to join conversations that this device doesn't have local
    /// MLS state for, via external commit.
    pub async fn join_missing_conversations(&self, did: &str) {
        let convos = self.conversations().await;
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
