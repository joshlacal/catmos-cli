use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, COOKIE};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

use catbird_atproto::catbird::mls_chat;

use crate::auth::AuthMethod;
use crate::error::{CatmosError, Result};
use crate::mls::MlsManager;
use crate::storage::aliases::AliasStore;
use crate::storage::config::Config;
use crate::storage::db::Database;
use crate::types::{BlobUsage, Conversation, Device, KeyPackageStatus};

// ── Thin response wrappers for endpoints not covered in messages.rs ─────
//
// Jacquard-generated output types use lifetime parameters and don't implement
// `DeserializeOwned`. We use thin owned wrappers whose field names match the
// generated types exactly (camelCase via serde rename).

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListDevicesResp {
    devices: Vec<DeviceInfoResp>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceInfoResp {
    device_id: String,
    credential_did: String,
    device_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageStatusResp {
    #[serde(default)]
    stats: Option<KeyPackageStatsResp>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageStatsResp {
    total_available: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishKeyPackagesResp {
    #[serde(default)]
    publish_result: Option<PublishResultResp>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishResultResp {
    succeeded: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveDeviceResp {
    deleted: bool,
    #[serde(default)]
    key_packages_deleted: Option<i64>,
    #[serde(default)]
    conversations_left: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadBlobResp {
    blob_id: String,
    size: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetBlobUsageResp {
    used_bytes: i64,
    quota_bytes: i64,
    blob_count: i64,
}

/// Central coordinator for chat operations: XRPC calls, message encryption,
/// WebSocket subscriptions, and local storage.
pub struct ChatService {
    pub(crate) http: reqwest::Client,
    pub(crate) auth: AuthMethod,
    pub mls: Arc<MlsManager>,
    pub db: Arc<Database>,
    pub(crate) config: Config,
    pub(crate) aliases: Arc<RwLock<AliasStore>>,
    pub(crate) conversations: Arc<RwLock<Vec<Conversation>>>,
    /// DID -> handle cache, populated during fetch_conversations.
    pub(crate) handle_cache: Arc<RwLock<HashMap<String, String>>>,
    /// Per-conversation repair cooldown: tracks when each conversation was last repaired
    /// to prevent epoch inflation from rapid successive external commits.
    pub(crate) repair_cooldowns: Arc<Mutex<HashMap<String, Instant>>>,
    /// Own-commit SHA256 dedup: hash → timestamp. Prevents processing our own commits
    /// as incoming messages (spec §5.4). Entries expire after 5 minutes.
    pub(crate) own_commits: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
}

impl ChatService {
    pub fn new(
        auth: AuthMethod,
        mls: Arc<MlsManager>,
        db: Arc<Database>,
        config: Config,
        aliases: Arc<RwLock<AliasStore>>,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            auth,
            mls,
            db,
            config,
            aliases,
            conversations: Arc::new(RwLock::new(Vec::new())),
            handle_cache: Arc::new(RwLock::new(HashMap::new())),
            repair_cooldowns: Arc::new(Mutex::new(HashMap::new())),
            own_commits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The authenticated user's DID.
    pub fn did(&self) -> &str {
        match &self.auth {
            AuthMethod::OAuth { did, .. } => did,
            AuthMethod::AppPassword { did, .. } => did,
        }
    }

    /// Snapshot of cached conversations.
    pub async fn conversations(&self) -> Vec<Conversation> {
        self.conversations.read().await.clone()
    }

    /// Snapshot of the DID -> handle cache.
    pub async fn handle_cache(&self) -> HashMap<String, String> {
        self.handle_cache.read().await.clone()
    }

    /// Resolve user input (alias, name, or ID prefix) to a conversation ID.
    pub async fn resolve_convo(&self, input: &str) -> Result<String> {
        let aliases = self.aliases.read().await;
        let convos = self.conversations.read().await;
        aliases
            .resolve(input, &convos)
            .ok_or_else(|| CatmosError::ConvoNotFound(input.to_string()))
    }

    /// Resolve a DID to a handle via the public Bluesky API.
    pub async fn resolve_handle(&self, did: &str) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct ProfileBasic {
            handle: Option<String>,
        }
        // Use public API directly — no auth needed
        let resp = self
            .http
            .get(format!(
                "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={did}"
            ))
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;
        if resp.status().is_success() {
            let profile: ProfileBasic = resp
                .json()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            Ok(profile
                .handle
                .unwrap_or_else(|| did.rsplit(':').next().unwrap_or(did).to_string()))
        } else {
            Ok(did.rsplit(':').next().unwrap_or(did).to_string())
        }
    }

    // ── XRPC transport ──────────────────────────────────────────────────

    /// POST an XRPC procedure (e.g. `blue.catbird.mlsChat.sendMessage`).
    pub async fn xrpc_procedure<T: Serialize, R: DeserializeOwned>(
        &self,
        nsid: &str,
        input: &T,
    ) -> Result<R> {
        let (url, headers) = self.build_request(nsid)?;
        debug!("XRPC POST {nsid} -> {url}");

        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .json(input)
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatmosError::Xrpc(format!(
                "{nsid} returned {status}: {body}"
            )));
        }

        resp.json::<R>()
            .await
            .map_err(|e| CatmosError::Xrpc(format!("Failed to parse {nsid} response: {e}")))
    }

    /// GET an XRPC query (e.g. `blue.catbird.mlsChat.getConvos`).
    pub async fn xrpc_query<R: DeserializeOwned>(
        &self,
        nsid: &str,
        params: &[(&str, &str)],
    ) -> Result<R> {
        let (url, headers) = self.build_request(nsid)?;
        debug!("XRPC GET {nsid} -> {url}");

        let resp = self
            .http
            .get(&url)
            .headers(headers)
            .query(params)
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatmosError::Xrpc(format!(
                "{nsid} returned {status}: {body}"
            )));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;
        tracing::debug!("XRPC {nsid} raw: {}", &body[..body.len().min(500)]);
        serde_json::from_str::<R>(&body).map_err(|e| {
            CatmosError::Xrpc(format!(
                "Failed to parse {nsid}: {e}\nBody: {}",
                &body[..body.len().min(300)]
            ))
        })
    }

    // ── Conversation management ──────────────────────────────────────────

    /// Create a new MLS group conversation on the server.
    pub async fn create_conversation(
        &self,
        name: &str,
        members: &[String],
        description: Option<&str>,
    ) -> Result<Conversation> {
        let req: mls_chat::create_convo::Input = mls_chat::create_convo::InputData {
            group_id: String::new(), // server assigns
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            initial_members: if members.is_empty() {
                None
            } else {
                Some(
                    members
                        .iter()
                        .map(|m| catbird_atproto::types::string::Did::from(m.clone()))
                        .collect(),
                )
            },
            metadata: Some(
                mls_chat::create_convo::MetadataInputData {
                    name: Some(name.to_string()),
                    description: description.map(String::from),
                }
                .into(),
            ),
            welcome_message: None,
            current_epoch: None,
            key_package_hashes: None,
        }
        .into();

        let resp: super::messages::CreateConvoResp = self
            .xrpc_procedure(mls_chat::create_convo::NSID, &req)
            .await?;

        Ok(super::messages::convo_resp_to_conversation(&resp.convo))
    }

    /// Leave (remove self from) a conversation.
    pub async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        let req: mls_chat::leave_convo::Input = mls_chat::leave_convo::InputData {
            convo_id: convo_id.to_string(),
            commit: None,
            target_did: None,
        }
        .into();

        let _: serde_json::Value = self
            .xrpc_procedure(mls_chat::leave_convo::NSID, &req)
            .await?;

        Ok(())
    }

    /// List devices registered for the authenticated user.
    pub async fn list_devices(&self) -> Result<Vec<Device>> {
        let resp: ListDevicesResp = self.xrpc_query(mls_chat::list_devices::NSID, &[]).await?;

        let devices = resp
            .devices
            .into_iter()
            .map(|d| Device {
                device_id: d.device_id,
                mls_did: d.credential_did,
                device_name: d.device_name,
            })
            .collect();

        Ok(devices)
    }

    /// Get the current key package availability status.
    pub async fn get_key_package_status(&self) -> Result<KeyPackageStatus> {
        let resp: KeyPackageStatusResp = self
            .xrpc_query(
                mls_chat::get_key_package_status::NSID,
                &[("include", "stats")],
            )
            .await?;

        match resp.stats {
            Some(s) => Ok(KeyPackageStatus {
                available: s.total_available as u64,
                target: 10, // server default target
                needs_replenish: s.total_available < 5,
            }),
            None => Ok(KeyPackageStatus {
                available: 0,
                target: 10,
                needs_replenish: true,
            }),
        }
    }

    // ── Join / Update / Member management ─────────────────────────────────

    /// Join an existing conversation via external commit.
    pub async fn join_conversation(&self, convo_id: &str) -> Result<()> {
        let req: mls_chat::commit_group_change::Input = mls_chat::commit_group_change::InputData {
            convo_id: convo_id.to_string(),
            action: "externalCommit".to_string(),
            commit: None,
            confirmation_tag: None,
            device_id: None,
            group_info: None,
            idempotency_key: None,
            key_package_hashes: None,
            member_dids: None,
            pending_addition_id: None,
            welcome: None,
        }
        .into();

        let _: serde_json::Value = self
            .xrpc_procedure(mls_chat::commit_group_change::NSID, &req)
            .await?;

        Ok(())
    }

    /// Update conversation metadata (name, description).
    pub async fn update_conversation(
        &self,
        convo_id: &str,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<()> {
        // The generated UpdateConvo type doesn't have metadata fields directly,
        // so we construct the JSON manually using the correct field names from
        // the generated type.
        let mut json = serde_json::json!({
            "action": "updateMetadata",
            "convoId": convo_id,
        });
        if let Some(n) = name {
            json["name"] = serde_json::Value::String(n.to_string());
        }
        if let Some(d) = description {
            json["description"] = serde_json::Value::String(d.to_string());
        }

        let _: serde_json::Value = self
            .xrpc_procedure(mls_chat::update_convo::NSID, &json)
            .await?;

        Ok(())
    }

    /// Add a member to a conversation.
    pub async fn add_member(&self, convo_id: &str, member_did: &str) -> Result<()> {
        let req: mls_chat::commit_group_change::Input = mls_chat::commit_group_change::InputData {
            convo_id: convo_id.to_string(),
            action: "addMembers".to_string(),
            commit: None,
            confirmation_tag: None,
            device_id: None,
            group_info: None,
            idempotency_key: None,
            key_package_hashes: None,
            member_dids: Some(vec![catbird_atproto::types::string::Did::from(
                member_did.to_string(),
            )]),
            pending_addition_id: None,
            welcome: None,
        }
        .into();

        let _: serde_json::Value = self
            .xrpc_procedure(mls_chat::commit_group_change::NSID, &req)
            .await?;

        Ok(())
    }

    /// Remove a member from a conversation.
    pub async fn remove_member(&self, convo_id: &str, member_did: &str) -> Result<()> {
        let req: mls_chat::commit_group_change::Input = mls_chat::commit_group_change::InputData {
            convo_id: convo_id.to_string(),
            action: "removeMembers".to_string(),
            commit: None,
            confirmation_tag: None,
            device_id: None,
            group_info: None,
            idempotency_key: None,
            key_package_hashes: None,
            member_dids: Some(vec![catbird_atproto::types::string::Did::from(
                member_did.to_string(),
            )]),
            pending_addition_id: None,
            welcome: None,
        }
        .into();

        let _: serde_json::Value = self
            .xrpc_procedure(mls_chat::commit_group_change::NSID, &req)
            .await?;

        Ok(())
    }

    /// Promote a member to admin or moderator.
    pub async fn promote_member(
        &self,
        convo_id: &str,
        member_did: &str,
        admin: bool,
        _moderator: bool,
    ) -> Result<()> {
        if admin {
            let req: mls_chat::promote_admin::Input = mls_chat::promote_admin::InputData {
                convo_id: convo_id.to_string(),
                target_did: catbird_atproto::types::string::Did::from(member_did.to_string()),
            }
            .into();

            let _: serde_json::Value = self
                .xrpc_procedure(mls_chat::promote_admin::NSID, &req)
                .await?;
        }

        Ok(())
    }

    /// Send a reaction (add or remove) to a message.
    pub async fn send_reaction(
        &self,
        convo_id: &str,
        message_id: &str,
        emoji: &str,
        remove: bool,
    ) -> Result<()> {
        let action = if remove { "remove" } else { "add" };
        // Match the iOS MLSMessagePayload format with nested reaction object
        let payload = serde_json::json!({
            "version": 1,
            "messageType": "reaction",
            "reaction": {
                "messageId": message_id,
                "emoji": emoji,
                "action": action,
            }
        });
        let plaintext = serde_json::to_vec(&payload)?;

        // Encrypt via MLS -- ciphertext padding is handled by the MLS layer
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let encrypt_result = self
            .mls
            .with_context(|ctx| ctx.encrypt_message(group_id_bytes.clone(), plaintext))?;

        let epoch = self.get_epoch(convo_id).unwrap_or(0);
        let msg_id = ulid::Ulid::new().to_string();
        let padded_size = encrypt_result.ciphertext.len() as i64;

        let confirmation_tag = self.get_confirmation_tag_b64(&group_id_bytes);

        let req: mls_chat::send_message::Input = mls_chat::send_message::InputData {
            convo_id: convo_id.to_string(),
            ciphertext: encrypt_result.ciphertext,
            epoch: epoch as usize,
            msg_id,
            padded_size,
            delivery: None,
            confirmation_tag,
        }
        .into();

        let _: serde_json::Value = self
            .xrpc_procedure(mls_chat::send_message::NSID, &req)
            .await?;

        Ok(())
    }

    /// Register a new device for the authenticated user.
    ///
    /// Note: Full MLS device registration (with signature key + key packages)
    /// is handled by the MLS orchestration layer. This method provides a
    /// simplified registration path using the generated NSID.
    pub async fn register_device(&self, name: Option<&str>) -> Result<Device> {
        let device_name = name.unwrap_or("catmos-cli");

        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct MinimalRegister {
            device_name: String,
        }

        let req = MinimalRegister {
            device_name: device_name.to_string(),
        };

        let device: Device = self
            .xrpc_procedure(mls_chat::register_device::NSID, &req)
            .await?;

        Ok(device)
    }

    /// Replenish key packages on the server.
    pub async fn replenish_key_packages(&self) -> Result<u32> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let identity = self.did().as_bytes().to_vec();
        let packages = self.mls.create_key_packages(&identity, 10)?;

        let now = chrono::Utc::now();
        let expires_str =
            (now + chrono::Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let key_packages: Vec<mls_chat::publish_key_packages::KeyPackageItem> = packages
            .iter()
            .map(|kp| {
                mls_chat::publish_key_packages::KeyPackageItemData {
                    cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
                    expires: expires_str.parse().expect("valid datetime"),
                    key_package: BASE64.encode(&kp.key_package_data),
                }
                .into()
            })
            .collect();

        let req: mls_chat::publish_key_packages::Input =
            mls_chat::publish_key_packages::InputData {
                action: "publish".to_string(),
                device_id: None,
                key_packages: Some(key_packages),
                local_hashes: None,
            }
            .into();

        let resp: PublishKeyPackagesResp = self
            .xrpc_procedure(mls_chat::publish_key_packages::NSID, &req)
            .await?;

        let accepted = resp.publish_result.map(|r| r.succeeded as u32).unwrap_or(0);

        Ok(accepted)
    }

    /// Remove a device by its ID. Returns (deleted, key_packages_deleted, conversations_left).
    pub async fn remove_device(&self, device_id: &str) -> Result<(bool, i64, i64)> {
        let req: mls_chat::remove_device::Input = mls_chat::remove_device::InputData {
            device_id: device_id.to_string(),
        }
        .into();

        let resp: RemoveDeviceResp = self
            .xrpc_procedure(mls_chat::remove_device::NSID, &req)
            .await?;

        Ok((
            resp.deleted,
            resp.key_packages_deleted.unwrap_or(0),
            resp.conversations_left.unwrap_or(0),
        ))
    }

    // ── Debug / introspection ───────────────────────────────────────────

    /// Get the current MLS epoch for a conversation from local state.
    pub fn get_epoch(&self, convo_id: &str) -> Result<u64> {
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;
        self.mls.with_context(|ctx| ctx.get_epoch(group_id_bytes))
    }

    /// Get the tree hash for a conversation from local MLS state.
    pub fn get_tree_hash(&self, convo_id: &str) -> Result<Vec<u8>> {
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;
        let data = self
            .mls
            .with_context(|ctx| ctx.get_tree_hash(group_id_bytes))?;
        Ok(data.tree_hash)
    }

    /// Fetch group state from the server.
    pub async fn get_group_state(&self, convo_id: &str) -> Result<serde_json::Value> {
        let resp: serde_json::Value = self
            .xrpc_query(mls_chat::get_group_state::NSID, &[("convoId", convo_id)])
            .await?;
        Ok(resp)
    }

    // ── Blob operations ─────────────────────────────────────────────────

    /// Upload a file as an encrypted blob associated with a conversation.
    /// Returns the server-assigned blob ID.
    pub async fn upload_blob(&self, convo_id: &str, file_path: &str) -> Result<String> {
        let data = tokio::fs::read(file_path)
            .await
            .map_err(|e| CatmosError::Other(format!("Failed to read file {file_path}: {e}")))?;

        let nsid = mls_chat::upload_blob::NSID;
        let (url, headers) = self.build_request(nsid)?;
        debug!("XRPC POST {nsid} -> {url}");

        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .query(&[("convoId", convo_id)])
            .header("content-type", "application/octet-stream")
            .body(data)
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatmosError::Xrpc(format!(
                "{nsid} returned {status}: {body}"
            )));
        }

        let resp: UploadBlobResp = resp
            .json()
            .await
            .map_err(|e| CatmosError::Xrpc(format!("Failed to parse {nsid} response: {e}")))?;

        debug!("Uploaded blob {} ({} bytes)", resp.blob_id, resp.size);
        Ok(resp.blob_id)
    }

    /// Download a blob by ID and write it to the given output path.
    pub async fn download_blob(&self, blob_id: &str, output_path: &str) -> Result<()> {
        let nsid = mls_chat::get_blob::NSID;
        let (url, headers) = self.build_request(nsid)?;
        debug!("XRPC GET {nsid} -> {url}");

        let resp = self
            .http
            .get(&url)
            .headers(headers)
            .query(&[("blobId", blob_id)])
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatmosError::Xrpc(format!(
                "{nsid} returned {status}: {body}"
            )));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        tokio::fs::write(output_path, &bytes)
            .await
            .map_err(|e| CatmosError::Other(format!("Failed to write {output_path}: {e}")))?;

        Ok(())
    }

    /// Get the authenticated user's blob storage usage stats.
    pub async fn get_blob_usage(&self) -> Result<BlobUsage> {
        let resp: GetBlobUsageResp = self.xrpc_query(mls_chat::get_blob_usage::NSID, &[]).await?;

        Ok(BlobUsage {
            used_bytes: resp.used_bytes,
            quota_bytes: resp.quota_bytes,
            blob_count: resp.blob_count,
        })
    }

    /// Build the target URL and auth headers for an XRPC call.
    ///
    /// - OAuth: routes through nest (confidential client proxy)
    /// - AppPassword: routes directly to mls-ds for `blue.catbird.mlsChat.*` endpoints
    fn build_request(&self, nsid: &str) -> Result<(String, HeaderMap)> {
        let mut headers = HeaderMap::new();

        match &self.auth {
            AuthMethod::OAuth {
                session_cookie,
                nest_url,
                ..
            } => {
                let url = format!("{nest_url}/xrpc/{nsid}");
                // Use Bearer token (same session_id as cookie, but more reliable for API clients)
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {session_cookie}"))
                        .map_err(|e| CatmosError::AuthFailed(e.to_string()))?,
                );
                Ok((url, headers))
            }
            AuthMethod::AppPassword { access_jwt, .. } => {
                // Route mlsChat calls directly to the MLS delivery service
                let base = if nsid.starts_with("blue.catbird.mlsChat.") {
                    &self.config.server.mls_url
                } else {
                    &self.config.server.nest_url
                };
                let url = format!("{base}/xrpc/{nsid}");
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {access_jwt}"))
                        .map_err(|e| CatmosError::AuthFailed(e.to_string()))?,
                );
                Ok((url, headers))
            }
        }
    }
}
