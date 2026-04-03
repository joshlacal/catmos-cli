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
