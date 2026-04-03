use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, COOKIE};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

use crate::auth::AuthMethod;
use crate::error::{CatmosError, Result};
use crate::mls::MlsManager;
use crate::storage::aliases::AliasStore;
use crate::storage::config::Config;
use crate::storage::db::Database;
use crate::types::{Conversation, Device, KeyPackageStatus};

/// Central coordinator for chat operations: XRPC calls, message encryption,
/// WebSocket subscriptions, and local storage.
pub struct ChatService {
    pub(crate) http: reqwest::Client,
    pub(crate) auth: AuthMethod,
    pub(crate) mls: Arc<MlsManager>,
    pub(crate) db: Arc<Database>,
    pub(crate) config: Config,
    pub(crate) aliases: Arc<RwLock<AliasStore>>,
    pub(crate) conversations: Arc<RwLock<Vec<Conversation>>>,
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
        }
    }

    /// The authenticated user's DID.
    pub fn did(&self) -> &str {
        match &self.auth {
            AuthMethod::OAuth { .. } => "",
            AuthMethod::AppPassword { did, .. } => did,
        }
    }

    /// Snapshot of cached conversations.
    pub async fn conversations(&self) -> Vec<Conversation> {
        self.conversations.read().await.clone()
    }

    /// Resolve user input (alias, name, or ID prefix) to a conversation ID.
    pub async fn resolve_convo(&self, input: &str) -> Result<String> {
        let aliases = self.aliases.read().await;
        let convos = self.conversations.read().await;
        aliases
            .resolve(input, &convos)
            .ok_or_else(|| CatmosError::ConvoNotFound(input.to_string()))
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

        resp.json::<R>()
            .await
            .map_err(|e| CatmosError::Xrpc(format!("Failed to parse {nsid} response: {e}")))
    }

    // ── Conversation management ──────────────────────────────────────────

    /// Create a new MLS group conversation on the server.
    pub async fn create_conversation(
        &self,
        name: &str,
        members: &[String],
        description: Option<&str>,
    ) -> Result<Conversation> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            name: String,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            members: Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
        }

        let req = Req {
            name: name.to_string(),
            members: members.to_vec(),
            description: description.map(String::from),
        };

        let convo: Conversation = self
            .xrpc_procedure("blue.catbird.mlsChat.createConvo", &req)
            .await?;

        Ok(convo)
    }

    /// Leave (remove self from) a conversation.
    pub async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            group_id: String,
        }

        let req = Req {
            group_id: convo_id.to_string(),
        };

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.mlsChat.leaveConvo", &req)
            .await?;

        Ok(())
    }

    /// List devices registered for the authenticated user.
    pub async fn list_devices(&self) -> Result<Vec<Device>> {
        #[derive(serde::Deserialize)]
        struct Resp {
            devices: Vec<Device>,
        }

        let resp: Resp = self
            .xrpc_query("blue.catbird.mlsChat.getDevices", &[])
            .await?;

        Ok(resp.devices)
    }

    /// Get the current key package availability status.
    pub async fn get_key_package_status(&self) -> Result<KeyPackageStatus> {
        let status: KeyPackageStatus = self
            .xrpc_query("blue.catbird.mlsChat.getKeyPackageStatus", &[])
            .await?;

        Ok(status)
    }

    // ── Join / Update / Member management ─────────────────────────────────

    /// Join an existing conversation via external commit.
    pub async fn join_conversation(&self, convo_id: &str) -> Result<()> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            group_id: String,
            action: String,
        }

        let req = Req {
            group_id: convo_id.to_string(),
            action: "processExternalCommit".to_string(),
        };

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.mlsChat.commitGroupChange", &req)
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
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            group_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            name: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
        }

        let req = Req {
            group_id: convo_id.to_string(),
            name: name.map(String::from),
            description: description.map(String::from),
        };

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.mlsChat.updateConvo", &req)
            .await?;

        Ok(())
    }

    /// Add a member to a conversation.
    pub async fn add_member(&self, convo_id: &str, member_did: &str) -> Result<()> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            group_id: String,
            action: String,
            members: Vec<String>,
        }

        let req = Req {
            group_id: convo_id.to_string(),
            action: "addMembers".to_string(),
            members: vec![member_did.to_string()],
        };

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.mlsChat.commitGroupChange", &req)
            .await?;

        Ok(())
    }

    /// Remove a member from a conversation.
    pub async fn remove_member(&self, convo_id: &str, member_did: &str) -> Result<()> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            group_id: String,
            action: String,
            members: Vec<String>,
        }

        let req = Req {
            group_id: convo_id.to_string(),
            action: "removeMembers".to_string(),
            members: vec![member_did.to_string()],
        };

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.mlsChat.commitGroupChange", &req)
            .await?;

        Ok(())
    }

    /// Promote a member to admin or moderator.
    pub async fn promote_member(
        &self,
        convo_id: &str,
        member_did: &str,
        admin: bool,
        moderator: bool,
    ) -> Result<()> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct MemberRole {
            did: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            is_admin: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            is_moderator: Option<bool>,
        }

        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            group_id: String,
            member_roles: Vec<MemberRole>,
        }

        let req = Req {
            group_id: convo_id.to_string(),
            member_roles: vec![MemberRole {
                did: member_did.to_string(),
                is_admin: if admin { Some(true) } else { None },
                is_moderator: if moderator { Some(true) } else { None },
            }],
        };

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.mlsChat.updateConvo", &req)
            .await?;

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
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let action = if remove { "remove" } else { "add" };
        let payload = serde_json::json!({
            "type": "reaction",
            "targetMessageId": message_id,
            "emoji": emoji,
            "action": action,
        });
        let plaintext = serde_json::to_vec(&payload)?;

        // Pad and encrypt
        let padded = {
            const BUCKETS: &[usize] = &[512, 1024, 2048, 4096, 8192];
            let target = BUCKETS
                .iter()
                .find(|&&b| b >= plaintext.len())
                .copied()
                .unwrap_or(8192);
            let mut p = plaintext;
            p.resize(target, 0);
            p
        };

        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let encrypt_result = self.mls.with_context(|ctx| {
            ctx.encrypt_message(group_id_bytes, padded)
        })?;

        let ciphertext_b64 = BASE64.encode(&encrypt_result.ciphertext);

        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            group_id: String,
            ciphertext: String,
            action: String,
        }

        let req = Req {
            group_id: convo_id.to_string(),
            ciphertext: ciphertext_b64,
            action: "reaction".to_string(),
        };

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.mlsChat.sendMessage", &req)
            .await?;

        Ok(())
    }

    /// Register a new device for the authenticated user.
    pub async fn register_device(&self, name: Option<&str>) -> Result<Device> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            #[serde(skip_serializing_if = "Option::is_none")]
            device_name: Option<String>,
        }

        let req = Req {
            device_name: name.map(String::from),
        };

        let device: Device = self
            .xrpc_procedure("blue.catbird.mlsChat.registerDevice", &req)
            .await?;

        Ok(device)
    }

    /// Replenish key packages on the server.
    pub async fn replenish_key_packages(&self) -> Result<u32> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let identity = self.did().as_bytes().to_vec();
        let packages = self.mls.create_key_packages(&identity, 10)?;

        let encoded: Vec<String> = packages
            .iter()
            .map(|kp| BASE64.encode(&kp.key_package_data))
            .collect();

        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Req {
            key_packages: Vec<String>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            accepted: u32,
        }

        let req = Req {
            key_packages: encoded,
        };

        let resp: Resp = self
            .xrpc_procedure("blue.catbird.mlsChat.publishKeyPackages", &req)
            .await?;

        Ok(resp.accepted)
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
            .xrpc_query(
                "blue.catbird.mlsChat.getGroupState",
                &[("groupId", convo_id)],
            )
            .await?;
        Ok(resp)
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
            } => {
                let url = format!("{nest_url}/xrpc/{nsid}");
                headers.insert(
                    COOKIE,
                    HeaderValue::from_str(&format!("session={session_cookie}"))
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
