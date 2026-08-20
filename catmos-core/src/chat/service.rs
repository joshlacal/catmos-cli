use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use catbird_mls::orchestrator_bridge::FFICommitKind;
use catbird_mls::{GroupConfig, KeyPackageData};

use crate::auth::{AuthMethod, TokenSession};
use crate::error::{CatmosError, Result};
use crate::mls::{MlsManager, KEY_PACKAGE_LOW_THRESHOLD, KEY_PACKAGE_TARGET, MLS_CIPHER_SUITE};
use crate::recovery::{
    GroupInfo404Tracker, QuarantineExitReason, QuarantineReason, RecoveryTracker,
};
use crate::storage::aliases::AliasStore;
use crate::storage::config::Config;
use crate::storage::db::Database;
use crate::types::{BlobUsage, Conversation, Device, KeyPackageStatus};

#[derive(Debug, Clone)]
pub enum QuarantineEvent {
    Entered {
        convo_id: String,
        reason: QuarantineReason,
        suspected_dids: Vec<String>,
        since_ms: i64,
    },
    Cleared {
        convo_id: String,
        via: QuarantineExitReason,
    },
}

/// Return true if the response status and body indicate an ExpiredToken error.
pub(crate) fn is_expired_token_response(status: StatusCode, body: &[u8]) -> bool {
    if !matches!(status, StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST) {
        return false;
    }
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
            return err == "ExpiredToken";
        }
        return false;
    }
    if let Ok(text) = std::str::from_utf8(body) {
        return text.contains(r#""error":"ExpiredToken"#) || text.contains(r#""error": "ExpiredToken"#);
    }
    false
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitGroupChangeResp {
    success: bool,
    #[serde(default)]
    new_epoch: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetKeyPackagesResp {
    pub key_packages: Vec<KeyPackageRefResp>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyPackageRefResp {
    pub did: String,
    #[serde(with = "serde_bytes_wrapper")]
    pub key_package: Vec<u8>,
    #[serde(default)]
    pub key_package_hash: Option<String>,
}

mod serde_bytes_wrapper {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use serde::{de::Error as DeError, Deserialize, Deserializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BytesEnvelope {
        DollarBytes {
            #[serde(rename = "$bytes")]
            bytes: String,
        },
        Base64String(String),
        ByteArray(Vec<u8>),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        match BytesEnvelope::deserialize(d)? {
            BytesEnvelope::DollarBytes { bytes } | BytesEnvelope::Base64String(bytes) => {
                BASE64
                    .decode(&bytes)
                    .map_err(|e| D::Error::custom(format!("invalid $bytes base64: {e}")))
            }
            BytesEnvelope::ByteArray(vec) => Ok(vec),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileBasic {
    handle: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadBlobResp {
    blob_id: String,
    size: i64,
}

#[derive(Clone)]
pub struct ChatService {
    pub(crate) http: reqwest::Client,
    pub(crate) auth: AuthMethod,
    pub(crate) token_session: Option<TokenSession>,
    pub mls: Arc<MlsManager>,
    pub db: Arc<Database>,
    pub(crate) config: Config,
    pub(crate) aliases: Arc<RwLock<AliasStore>>,
    pub(crate) conversations: Arc<RwLock<Vec<Conversation>>>,
    pub(crate) handle_cache: Arc<RwLock<HashMap<String, String>>>,
    pub(crate) recovery_tracker: Arc<Mutex<RecoveryTracker>>,
    pub(crate) groupinfo_404_tracker: Arc<Mutex<GroupInfo404Tracker>>,
    pub(crate) decrypt_fail_counts: Arc<Mutex<HashMap<String, u32>>>,
    pub(crate) epoch_divergence_counts: Arc<Mutex<HashMap<String, u32>>>,
    pub(crate) own_commits: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    pub(crate) inventory_session: Arc<RwLock<Option<(String, String)>>>,
    pub(crate) quarantine_events: tokio::sync::broadcast::Sender<QuarantineEvent>,
}

impl ChatService {
    pub fn new(
        auth: AuthMethod,
        token_session: Option<TokenSession>,
        mls: Arc<MlsManager>,
        db: Arc<Database>,
        config: Config,
        aliases: Arc<RwLock<AliasStore>>,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            auth,
            token_session,
            mls,
            db,
            config,
            aliases,
            conversations: Arc::new(RwLock::new(Vec::new())),
            handle_cache: Arc::new(RwLock::new(HashMap::new())),
            recovery_tracker: Arc::new(Mutex::new(RecoveryTracker::new())),
            groupinfo_404_tracker: Arc::new(Mutex::new(GroupInfo404Tracker::new())),
            decrypt_fail_counts: Arc::new(Mutex::new(HashMap::new())),
            epoch_divergence_counts: Arc::new(Mutex::new(HashMap::new())),
            own_commits: Arc::new(Mutex::new(HashMap::new())),
            inventory_session: Arc::new(RwLock::new(None)),
            quarantine_events: tokio::sync::broadcast::channel(32).0,
        }
    }

    pub async fn conversations(&self) -> Vec<Conversation> {
        let guard = self.conversations.read().await;
        guard.clone()
    }

    pub fn subscribe_quarantine_events(&self) -> tokio::sync::broadcast::Receiver<QuarantineEvent> {
        self.quarantine_events.subscribe()
    }

    pub fn did(&self) -> &str {
        match &self.auth {
            AuthMethod::OAuth { did, .. } => did,
            AuthMethod::AppPassword { did, .. } => did,
        }
    }

    pub async fn handle_cache(&self) -> HashMap<String, String> {
        self.handle_cache.read().await.clone()
    }

    pub async fn resolve_convo(&self, input: &str) -> Result<String> {
        if let Some(target) = self.aliases.read().await.get(input) {
            return Ok(target.to_string());
        }
        let convos = self.conversations().await;
        if let Some(c) = convos.iter().find(|c| c.group_id == input || c.conversation_id == input) {
            return Ok(c.group_id.clone());
        }
        Ok(input.to_string())
    }

    pub async fn resolve_handle(&self, did: &str) -> Result<String> {
        let base_url = match &self.auth {
            AuthMethod::OAuth { nest_url, .. } => nest_url.clone(),
            AuthMethod::AppPassword { pds_url, .. } => pds_url.clone(),
        };
        let resp = self
            .http
            .get(format!("{}/xrpc/app.bsky.actor.getProfile", base_url.trim_end_matches('/')))
            .query(&[("actor", did)])
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

    pub async fn xrpc_procedure<Req: Serialize + ?Sized, Resp: DeserializeOwned>(
        &self,
        nsid: &str,
        input: &Req,
    ) -> Result<Resp> {
        let bearer = self.get_service_token(nsid).await?;
        let (url, headers) = self.build_request(nsid, &bearer)?;
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
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let body_bytes = if self.should_retry_after_refresh(status, &body_bytes) {
            let new_bearer = self.refresh_bearer().await?;
            let fresh_bearer = self.get_service_token(nsid).await.unwrap_or(new_bearer);
            let (url, headers) = self.build_request(nsid, &fresh_bearer)?;
            debug!("XRPC POST {nsid} retry after refresh -> {url}");
            let retry_resp = self
                .http
                .post(&url)
                .headers(headers)
                .json(input)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            let retry_status = retry_resp.status();
            let retry_bytes = retry_resp
                .bytes()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            if !retry_status.is_success() {
                let body_str = String::from_utf8_lossy(&retry_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {retry_status}: {body_str}"
                )));
            }
            retry_bytes
        } else {
            if !status.is_success() {
                let body_str = String::from_utf8_lossy(&body_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {status}: {body_str}"
                )));
            }
            body_bytes
        };

        serde_json::from_slice::<Resp>(&body_bytes)
            .map_err(|e| CatmosError::Xrpc(format!("Failed to parse {nsid} response: {e}")))
    }

    pub async fn xrpc_post_raw<Resp: DeserializeOwned>(
        &self,
        nsid: &str,
        body_json: &[u8],
    ) -> Result<Resp> {
        let bearer = self.get_service_token(nsid).await?;
        let (url, mut headers) = self.build_request(nsid, &bearer)?;
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        debug!("XRPC POST (raw) {nsid} -> {url}");

        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .body(body_json.to_vec())
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let is_sensitive_device_endpoint = nsid.contains("enrollDevice")
            || nsid.contains("getOwnDevices")
            || nsid.contains("rebindDeviceAuthentication")
            || nsid.contains("revokeDevice");

        let body_bytes = if self.should_retry_after_refresh(status, &body_bytes) {
            let new_bearer = self.refresh_bearer().await?;
            let (url, mut headers) = self.build_request(nsid, &new_bearer)?;
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            debug!("XRPC POST (raw) {nsid} retry after refresh -> {url}");
            let retry_resp = self
                .http
                .post(&url)
                .headers(headers)
                .body(body_json.to_vec())
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            let retry_status = retry_resp.status();
            let retry_bytes = retry_resp
                .bytes()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            if !retry_status.is_success() {
                let body_str = String::from_utf8_lossy(&retry_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {retry_status}: {body_str}"
                )));
            }
            retry_bytes
        } else {
            if !status.is_success() {
                let body_str = String::from_utf8_lossy(&body_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {status}: {body_str}"
                )));
            }
            body_bytes
        };

        serde_json::from_slice::<Resp>(&body_bytes)
            .map_err(|e| CatmosError::Xrpc(format!("Failed to parse {nsid} response: {e}")))
    }

    pub async fn xrpc_query<R: DeserializeOwned>(
        &self,
        nsid: &str,
        params: &[(&str, &str)],
    ) -> Result<R> {
        let bearer = self.get_service_token(nsid).await?;
        let (url, headers) = self.build_request(nsid, &bearer)?;
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
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let is_sensitive_device_endpoint = nsid.contains("getOwnDevices")
            || nsid.contains("enrollDevice")
            || nsid.contains("rebindDeviceAuthentication")
            || nsid.contains("revokeDevice");

        let body_bytes = if self.should_retry_after_refresh(status, &body_bytes) {
            let new_bearer = self.refresh_bearer().await?;
            let fresh_bearer = self.get_service_token(nsid).await.unwrap_or(new_bearer);
            let (url, headers) = self.build_request(nsid, &fresh_bearer)?;
            debug!("XRPC GET {nsid} retry after refresh -> {url}");
            let retry_resp = self
                .http
                .get(&url)
                .headers(headers)
                .query(params)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            let retry_status = retry_resp.status();
            let retry_bytes = retry_resp
                .bytes()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            if !retry_status.is_success() {
                let body_str = String::from_utf8_lossy(&retry_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {retry_status}: {body_str}"
                )));
            }
            retry_bytes
        } else {
            if !status.is_success() {
                let body_str = String::from_utf8_lossy(&body_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {status}: {body_str}"
                )));
            }
            body_bytes
        };

        if !is_sensitive_device_endpoint {
            let sample_len = body_bytes.len().min(500);
            tracing::debug!("XRPC {nsid} raw: {}", String::from_utf8_lossy(&body_bytes[..sample_len]));
        }
        serde_json::from_slice::<R>(&body_bytes).map_err(|e| {
            if is_sensitive_device_endpoint {
                CatmosError::Xrpc(format!("Failed to parse {nsid}: {e}"))
            } else {
                let sample_len = body_bytes.len().min(300);
                CatmosError::Xrpc(format!(
                    "Failed to parse {nsid}: {e}
Body: {}",
                    String::from_utf8_lossy(&body_bytes[..sample_len])
                ))
            }
        })
    }

    pub(crate) fn should_retry_after_refresh(&self, status: StatusCode, body: &[u8]) -> bool {
        self.token_session.is_some() && is_expired_token_response(status, body)
    }

    pub async fn actor_device_id(&self) -> Result<String> {
        if let Some(id) = self.db.get_session_value("mls_device_id").await? {
            if !id.trim().is_empty() {
                return Ok(id);
            }
        }
        if let Some(id) = self.db.get_session_value("device_uuid").await? {
            if !id.trim().is_empty() {
                return Ok(id);
            }
        }
        Err(CatmosError::AuthFailed(
            "No registered MLS device ID found. Please register a device first.".into(),
        ))
    }

    pub(crate) async fn get_service_token(&self, nsid: &str) -> Result<String> {
        match (&self.auth, &self.token_session) {
            (AuthMethod::OAuth { session_cookie, .. }, _) => Ok(session_cookie.clone()),
            (AuthMethod::AppPassword { pds_url, .. }, Some(sess)) => {
                let access_jwt = sess.current_bearer().await?;
                let aud = crate::mls::atproto_proxy_header_value();
                let aud_encoded = aud.replace('#', "%23");
                let pds_base = pds_url.trim_end_matches('/');

                let url = format!("{pds_base}/xrpc/com.atproto.server.getServiceAuth?aud={aud_encoded}&lxm={nsid}");
                let resp = self
                    .http
                    .get(&url)
                    .header(AUTHORIZATION, format!("Bearer {access_jwt}"))
                    .send()
                    .await;

                if let Ok(r) = resp {
                    if r.status().is_success() {
                        #[derive(Deserialize)]
                        struct SvcResp {
                            token: String,
                        }
                        if let Ok(parsed) = r.json::<SvcResp>().await {
                            return Ok(parsed.token);
                        }
                    }
                }

                // If pds_base was bsky.social, resolve actual PDS from plc.directory
                if pds_base.contains("bsky.social") {
                    let did = self.did();
                    if let Ok(plc_resp) = self.http.get(&format!("https://plc.directory/{did}")).send().await {
                        if let Ok(doc) = plc_resp.json::<serde_json::Value>().await {
                            if let Some(services) = doc.get("service").and_then(|v| v.as_array()) {
                                for svc in services {
                                    if let Some(endpoint) = svc.get("serviceEndpoint").and_then(|v| v.as_str()) {
                                        let ep_clean = endpoint.trim_end_matches('/');
                                        let ep_url = format!("{ep_clean}/xrpc/com.atproto.server.getServiceAuth?aud={aud_encoded}&lxm={nsid}");
                                        if let Ok(r2) = self
                                            .http
                                            .get(&ep_url)
                                            .header(AUTHORIZATION, format!("Bearer {access_jwt}"))
                                            .send()
                                            .await
                                        {
                                            if r2.status().is_success() {
                                                #[derive(Deserialize)]
                                                struct SvcResp {
                                                    token: String,
                                                }
                                                if let Ok(parsed) = r2.json::<SvcResp>().await {
                                                    return Ok(parsed.token);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(access_jwt)
            }
            (AuthMethod::AppPassword { .. }, None) => Err(CatmosError::AuthFailed(
                "AppPassword auth without a TokenSession — restart catmos".into(),
            )),
        }
    }

    pub(crate) async fn current_bearer(&self) -> Result<String> {
        match (&self.auth, &self.token_session) {
            (AuthMethod::OAuth { session_cookie, .. }, _) => Ok(session_cookie.clone()),
            (AuthMethod::AppPassword { .. }, Some(sess)) => sess.current_bearer().await,
            (AuthMethod::AppPassword { .. }, None) => Err(CatmosError::AuthFailed(
                "AppPassword auth without a TokenSession — restart catmos".into(),
            )),
        }
    }

    pub(crate) async fn refresh_bearer(&self) -> Result<String> {
        let sess = self
            .token_session
            .as_ref()
            .ok_or_else(|| CatmosError::AuthFailed("no TokenSession — cannot refresh".into()))?;
        tracing::info!("Refreshing app-password session tokens");
        sess.refresh(&self.db).await
    }

    // ── Conversation management ──────────────────────────────────────────

    pub async fn create_conversation(
        &self,
        name: &str,
        members: &[String],
        description: Option<&str>,
    ) -> Result<Conversation> {
        let creator_did = self.did().to_string();
        let mut seen = HashSet::new();
        let initial_members: Vec<String> = members
            .iter()
            .filter(|did| did.as_str() != creator_did)
            .filter(|did| seen.insert((*did).clone()))
            .cloned()
            .collect();

        let key_packages = if initial_members.is_empty() {
            Vec::new()
        } else {
            self.fetch_key_packages(&initial_members).await?
        };

        if !initial_members.is_empty() {
            let available: HashSet<&str> = key_packages.iter().map(|kp| kp.did.as_str()).collect();
            let missing: Vec<&str> = initial_members
                .iter()
                .map(String::as_str)
                .filter(|did| !available.contains(did))
                .collect();
            if !missing.is_empty() {
                return Err(CatmosError::Other(format!(
                    "No key packages available for initial member(s): {}",
                    missing.join(", ")
                )));
            }
        }

        let group_id_bytes = rand::random::<[u8; 16]>().to_vec();
        let group_id_hex = hex::encode(&group_id_bytes);

        self.mls.with_context(|ctx| {
            ctx.create_group_with_id(
                creator_did.as_bytes().to_vec(),
                group_id_bytes.clone(),
                Some(GroupConfig::default()),
            )
        })?;

        let initial_add = if key_packages.is_empty() {
            None
        } else {
            let kp_data: Vec<KeyPackageData> = key_packages
                .iter()
                .map(|kp| KeyPackageData {
                    data: kp.key_package.clone(),
                })
                .collect();
            match self
                .mls
                .with_context(|ctx| ctx.add_members(group_id_bytes.clone(), kp_data))
            {
                Ok(add) => Some(add),
                Err(e) => {
                    let _ = self
                        .mls
                        .with_context(|ctx| ctx.delete_group(group_id_bytes.clone()));
                    return Err(e);
                }
            }
        };

        let key_package_hashes: Vec<(String, String)> = key_packages
            .iter()
            .filter_map(|kp| {
                kp.key_package_hash
                    .as_ref()
                    .map(|hash| (kp.did.clone(), hash.clone()))
            })
            .collect();

        let req = build_create_convo_request(
            &group_id_hex,
            &initial_members,
            initial_add.as_ref().map(|add| add.welcome_data.clone()),
            key_package_hashes,
        );

        let resp: super::messages::CreateConvoResp = match self
            .xrpc_procedure("blue.catbird.chat.createConversation", &req)
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                let _ = self
                    .mls
                    .with_context(|ctx| ctx.delete_group(group_id_bytes.clone()));
                return Err(e);
            }
        };

        if initial_add.is_some() {
            self.mls
                .with_context(|ctx| ctx.merge_pending_commit(group_id_bytes.clone()))?;
        }

        let mut convo = super::messages::convo_resp_to_conversation(&resp.convo);

        if !name.trim().is_empty() || description.is_some() {
            self.update_conversation(&group_id_hex, Some(name), description)
                .await?;
            let epoch = self
                .mls
                .with_context(|ctx| ctx.get_epoch(group_id_bytes.clone()))?;
            convo.epoch = epoch;
            convo.name = Some(name.to_string());
            convo.description = description.map(str::to_string);
        }

        match self.mls.with_context(|ctx| {
            ctx.export_group_info(group_id_bytes.clone(), creator_did.as_bytes().to_vec())
        }) {
            Ok(group_info) => {
                if let Err(e) = self.publish_group_info(&group_id_hex, &group_info).await {
                    warn!(
                        "create_conversation: failed to publish GroupInfo for {group_id_hex}: {e}"
                    );
                }
            }
            Err(e) => {
                warn!("create_conversation: failed to export GroupInfo for {group_id_hex}: {e}");
            }
        }

        Ok(convo)
    }

    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        let req = build_commit_group_change(
            convo_id,
            "updateGroupInfo",
            None,
            None,
            Some(group_info.to_vec()),
            None,
            None,
            None,
        );

        let _: CommitGroupChangeResp = self
            .xrpc_procedure("blue.catbird.chat.submitTransition", &req)
            .await?;
        Ok(())
    }

    pub(crate) async fn bootstrap_reset_group(
        &self,
        original_convo_id: &str,
        new_group_id_hex: &str,
        cipher_suite: &str,
        members: &[String],
        group_info: Vec<u8>,
        metadata_blob_locator: Option<&str>,
        metadata_version: Option<i64>,
    ) -> Result<()> {
        let mut req = serde_json::json!({
            "originalConvoId": original_convo_id,
            "newGroupId": new_group_id_hex,
            "cipherSuite": cipher_suite,
            "groupInfo": BASE64.encode(group_info),
            "members": members,
        });
        if let Some(locator) = metadata_blob_locator {
            req["metadataBlobLocator"] = serde_json::json!(locator);
        }
        if let Some(version) = metadata_version {
            req["metadataVersion"] = serde_json::json!(version);
        }

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.chat.requestReset", &req)
            .await?;
        Ok(())
    }

    pub async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        let req = serde_json::json!({
            "convoId": convo_id,
        });

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.chat.requestLeave", &req)
            .await?;

        Ok(())
    }

    pub async fn list_devices(&self) -> Result<Vec<Device>> {
        let actor_device_id = self.actor_device_id().await?;
        let resp: serde_json::Value = self
            .xrpc_query(
                "blue.catbird.chat.getOwnDevices",
                &[("actorDeviceId", &actor_device_id)],
            )
            .await?;

        if let Some(items) = resp.get("items").and_then(|v| v.as_array()) {
            let mut devices = Vec::new();
            for item in items {
                let dev = item.get("device").unwrap_or(item);
                let device_id = dev
                    .get("deviceId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let device_name = dev
                    .get("deviceName")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&device_id)
                    .to_string();
                let mls_did = format!("{}#{}", self.did(), device_id);
                devices.push(Device {
                    device_id,
                    mls_did,
                    device_name,
                });
            }
            return Ok(devices);
        }

        if let Some(devices_arr) = resp.get("devices").and_then(|v| v.as_array()) {
            let mut devices = Vec::new();
            for dev in devices_arr {
                let device_id = dev
                    .get("deviceId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let credential_did = dev
                    .get("credentialDid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let device_name = dev
                    .get("deviceName")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&device_id)
                    .to_string();
                devices.push(Device {
                    device_id,
                    mls_did: credential_did,
                    device_name,
                });
            }
            return Ok(devices);
        }

        Ok(Vec::new())
    }

    pub async fn get_key_package_status(&self) -> Result<KeyPackageStatus> {
        let actor_device_id = self.actor_device_id().await?;
        let resp: serde_json::Value = self
            .xrpc_query(
                "blue.catbird.chat.getOwnDevices",
                &[("actorDeviceId", &actor_device_id)],
            )
            .await?;

        if let Some(items) = resp.get("items").and_then(|v| v.as_array()) {
            for item in items {
                let dev = item.get("device").unwrap_or(item);
                let dev_id = dev.get("deviceId").and_then(|v| v.as_str()).unwrap_or("");
                if dev_id == actor_device_id || items.len() == 1 {
                    let avail = dev
                        .get("availablePackageCount")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    return Ok(KeyPackageStatus {
                        available: avail as u64,
                        target: KEY_PACKAGE_TARGET,
                        needs_replenish: (avail as u64) < KEY_PACKAGE_LOW_THRESHOLD,
                    });
                }
            }
        }

        if let Some(stats) = resp.get("stats") {
            let avail = stats
                .get("totalAvailable")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            return Ok(KeyPackageStatus {
                available: avail as u64,
                target: KEY_PACKAGE_TARGET,
                needs_replenish: (avail as u64) < KEY_PACKAGE_LOW_THRESHOLD,
            });
        }

        Ok(KeyPackageStatus {
            available: 0,
            target: KEY_PACKAGE_TARGET,
            needs_replenish: true,
        })
    }

    pub async fn update_conversation(
        &self,
        convo_id: &str,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<()> {
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|_| CatmosError::Other(format!("Invalid hex group ID: {convo_id}")))?;
        let result = self.mls.with_context(|ctx| {
            ctx.update_group_metadata_encrypted(
                group_id_bytes.clone(),
                name.map(str::to_string),
                description.map(str::to_string),
                None,
                None,
            )
        })?;

        self.track_own_commit(&result.commit_bytes).await;

        if let Err(e) = self
            .put_group_metadata_blob(
                &result.metadata_blob_locator,
                Some(convo_id),
                convo_id,
                Some("metadata"),
                Some(result.metadata_version as i64),
                None,
                result.metadata_blob_ciphertext.clone(),
            )
            .await
        {
            let _ = self
                .mls
                .with_context(|ctx| ctx.clear_pending_commit(group_id_bytes.clone()));
            return Err(e);
        }

        let req = build_commit_group_change(
            convo_id,
            "updateMetadata",
            Some(result.commit_bytes.clone()),
            None,
            None,
            None,
            None,
            Some(ulid::Ulid::new().to_string()),
        );

        match self
            .xrpc_procedure::<_, CommitGroupChangeResp>("blue.catbird.chat.submitTransition", &req)
            .await
        {
            Ok(resp) if resp.success => {
                if let Err(e) = self
                    .mls
                    .with_context(|ctx| ctx.merge_pending_commit(group_id_bytes.clone()))
                {
                    warn!("update_conversation: merge_pending_commit failed for {convo_id}: {e}");
                    return Err(e);
                }
                info!(
                    "Updated metadata for conversation {convo_id}                      (encrypted, version={}, locator={})",
                    result.metadata_version, result.metadata_blob_locator
                );
                Ok(())
            }
            Ok(_) => {
                let _ = self
                    .mls
                    .with_context(|ctx| ctx.clear_pending_commit(group_id_bytes.clone()));
                Err(CatmosError::Xrpc(format!(
                    "commitGroupChange[updateMetadata] returned success=false for {convo_id}"
                )))
            }
            Err(e) => {
                let _ = self
                    .mls
                    .with_context(|ctx| ctx.clear_pending_commit(group_id_bytes));
                Err(e)
            }
        }
    }

    pub async fn add_member(&self, convo_id: &str, member_did: &str) -> Result<()> {
        let kp_refs = self.fetch_key_packages(&[member_did.to_string()]).await?;
        if kp_refs.is_empty() {
            return Err(CatmosError::Other(format!(
                "No key packages available for {member_did}"
            )));
        }
        let key_packages: Vec<Vec<u8>> = kp_refs.iter().map(|k| k.key_package.clone()).collect();

        let did = self.did().to_string();
        let plan = self.mls.with_commit_context(|ctx| {
            ctx.stage_commit(
                convo_id.to_string(),
                FFICommitKind::AddMembers {
                    member_dids: vec![member_did.to_string()],
                    key_packages: key_packages.clone(),
                },
                did.as_bytes().to_vec(),
            )
        })?;

        let welcome_bytes = plan.welcome_bytes.clone().ok_or_else(|| {
            CatmosError::Other("stage_commit(AddMembers) did not return welcome bytes".to_string())
        })?;

        let req = build_commit_group_change(
            convo_id,
            "addMembers",
            Some(plan.commit_bytes.clone()),
            Some(welcome_bytes),
            None,
            None,
            Some(vec![member_did.to_string()]),
            Some(ulid::Ulid::new().to_string()),
        );

        self.track_own_commit(&plan.commit_bytes).await;

        let handle = plan.handle.clone();
        match self
            .xrpc_procedure::<_, CommitGroupChangeResp>("blue.catbird.chat.submitTransition", &req)
            .await
        {
            Ok(resp) if resp.success => {
                let server_epoch = match resp.new_epoch {
                    Some(e) if e > 0 => e as u64,
                    _ => catbird_mls::mls_skip_server_epoch_fence(),
                };
                if let Err(e) = self
                    .mls
                    .with_commit_context(|ctx| ctx.confirm_commit(handle.clone(), server_epoch))
                {
                    warn!("add_member: confirm_commit failed for {convo_id}: {e} — discarding");
                    let _ = self
                        .mls
                        .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                    return Err(e);
                }
                info!(
                    "Added {member_did} to {convo_id} (epoch hint: {:?})",
                    resp.new_epoch
                );
                Ok(())
            }
            Ok(_) => {
                let _ = self
                    .mls
                    .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                Err(CatmosError::Xrpc(format!(
                    "commitGroupChange[addMembers] returned success=false for {convo_id}"
                )))
            }
            Err(e) => {
                let _ = self
                    .mls
                    .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                Err(e)
            }
        }
    }

    pub async fn remove_member(&self, convo_id: &str, member_did: &str) -> Result<()> {
        let did = self.did().to_string();
        let plan = self.mls.with_commit_context(|ctx| {
            ctx.stage_commit(
                convo_id.to_string(),
                FFICommitKind::RemoveMembers {
                    member_dids: vec![member_did.to_string()],
                },
                did.as_bytes().to_vec(),
            )
        })?;

        let req = build_commit_group_change(
            convo_id,
            "removeMembers",
            Some(plan.commit_bytes.clone()),
            None,
            None,
            None,
            Some(vec![member_did.to_string()]),
            Some(ulid::Ulid::new().to_string()),
        );

        self.track_own_commit(&plan.commit_bytes).await;

        let handle = plan.handle.clone();
        match self
            .xrpc_procedure::<_, CommitGroupChangeResp>("blue.catbird.chat.submitTransition", &req)
            .await
        {
            Ok(resp) if resp.success => {
                let server_epoch = match resp.new_epoch {
                    Some(e) if e > 0 => e as u64,
                    _ => catbird_mls::mls_skip_server_epoch_fence(),
                };
                if let Err(e) = self
                    .mls
                    .with_commit_context(|ctx| ctx.confirm_commit(handle.clone(), server_epoch))
                {
                    warn!("remove_member: confirm_commit failed for {convo_id}: {e} — discarding");
                    let _ = self
                        .mls
                        .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                    return Err(e);
                }
                info!(
                    "Removed {member_did} from {convo_id} (epoch hint: {:?})",
                    resp.new_epoch
                );
                Ok(())
            }
            Ok(_) => {
                let _ = self
                    .mls
                    .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                Err(CatmosError::Xrpc(format!(
                    "commitGroupChange[removeMembers] returned success=false for {convo_id}"
                )))
            }
            Err(e) => {
                let _ = self
                    .mls
                    .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                Err(e)
            }
        }
    }

    async fn track_own_commit(&self, commit_bytes: &[u8]) {
        let hash: [u8; 32] = Sha256::digest(commit_bytes).into();
        let mut own = self.own_commits.lock().await;
        own.insert(hash, Instant::now());
        own.retain(|_, ts| ts.elapsed() < std::time::Duration::from_secs(300));
    }

    pub(crate) async fn fetch_key_packages(
        &self,
        dids: &[String],
    ) -> Result<Vec<KeyPackageRefResp>> {
        let params: Vec<(&str, &str)> = dids.iter().map(|d| ("dids", d.as_str())).collect();
        let resp: GetKeyPackagesResp = self
            .xrpc_query("blue.catbird.chat.getKeyPackages", &params)
            .await?;
        Ok(resp.key_packages)
    }

    pub async fn promote_member(
        &self,
        convo_id: &str,
        member_did: &str,
        admin: bool,
        _moderator: bool,
    ) -> Result<()> {
        if admin {
            let req = serde_json::json!({
                "convoId": convo_id,
                "action": "promoteAdmin",
                "targetDid": member_did,
            });

            let _: serde_json::Value = self
                .xrpc_procedure("blue.catbird.chat.submitTransition", &req)
                .await?;
        }

        Ok(())
    }

    pub async fn send_reaction(
        &self,
        convo_id: &str,
        message_id: &str,
        emoji: &str,
        remove: bool,
    ) -> Result<()> {
        let action = if remove { "remove" } else { "add" };
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

        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let encrypt_result = self
            .mls
            .with_context(|ctx| ctx.encrypt_message(group_id_bytes.clone(), plaintext))?;

        let epoch = self.get_epoch(convo_id).unwrap_or(0);
        let msg_id = ulid::Ulid::new().to_string();
        let padded_size = encrypt_result.ciphertext.len() as i64;
        let confirmation_tag = self.get_confirmation_tag_b64(&group_id_bytes);

        let req = serde_json::json!({
            "convoId": convo_id,
            "ciphertext": BASE64.encode(&encrypt_result.ciphertext),
            "epoch": epoch,
            "msgId": msg_id,
            "paddedSize": padded_size,
            "confirmationTag": confirmation_tag,
        });

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.chat.sendMessage", &req)
            .await?;

        Ok(())
    }

    pub fn get_epoch(&self, convo_id: &str) -> Result<u64> {
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;
        self.mls.with_context(|ctx| ctx.get_epoch(group_id_bytes))
    }

    pub fn get_tree_hash(&self, convo_id: &str) -> Result<Vec<u8>> {
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;
        let data = self
            .mls
            .with_context(|ctx| ctx.get_tree_hash(group_id_bytes))?;
        Ok(data.tree_hash)
    }

    pub async fn get_group_state(&self, convo_id: &str) -> Result<serde_json::Value> {
        let actor_device_id = self.actor_device_id().await?;
        let resp: serde_json::Value = self
            .xrpc_query(
                "blue.catbird.chat.getConversationState",
                &[
                    ("actorDeviceId", &actor_device_id),
                    ("convoId", convo_id),
                    ("conversationId", convo_id),
                ],
            )
            .await?;
        Ok(resp)
    }

    pub async fn upload_blob(&self, convo_id: &str, file_path: &str) -> Result<String> {
        let data = tokio::fs::read(file_path)
            .await
            .map_err(|e| CatmosError::Other(format!("Failed to read file {file_path}: {e}")))?;

        let actor_device_id = self.actor_device_id().await?;
        let nsid = "blue.catbird.chat.uploadBlob";
        let bearer = self.get_service_token(nsid).await?;
        let (url, headers) = self.build_request(nsid, &bearer)?;
        debug!("XRPC POST {nsid} -> {url}");

        let params = [
            ("actorDeviceId", actor_device_id.as_str()),
            ("convoId", convo_id),
            ("conversationId", convo_id),
        ];

        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .query(&params)
            .header("content-type", "application/octet-stream")
            .body(data.clone())
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let body_bytes = if self.should_retry_after_refresh(status, &body_bytes) {
            let new_bearer = self.refresh_bearer().await?;
            let fresh_bearer = self.get_service_token(nsid).await.unwrap_or(new_bearer);
            let (url, headers) = self.build_request(nsid, &fresh_bearer)?;
            let retry_resp = self
                .http
                .post(&url)
                .headers(headers)
                .query(&params)
                .header("content-type", "application/octet-stream")
                .body(data)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            let retry_status = retry_resp.status();
            let retry_bytes = retry_resp
                .bytes()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            if !retry_status.is_success() {
                let body_str = String::from_utf8_lossy(&retry_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {retry_status}: {body_str}"
                )));
            }
            retry_bytes
        } else {
            if !status.is_success() {
                let body_str = String::from_utf8_lossy(&body_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {status}: {body_str}"
                )));
            }
            body_bytes
        };

        let resp: UploadBlobResp = serde_json::from_slice(&body_bytes)
            .map_err(|e| CatmosError::Xrpc(format!("Failed to parse {nsid} response: {e}")))?;

        debug!("Uploaded blob {} ({} bytes)", resp.blob_id, resp.size);
        Ok(resp.blob_id)
    }

    pub async fn download_blob(&self, blob_id: &str, output_path: &str) -> Result<()> {
        let actor_device_id = self.actor_device_id().await?;
        let nsid = "blue.catbird.chat.getBlob";
        let bearer = self.get_service_token(nsid).await?;
        let (url, headers) = self.build_request(nsid, &bearer)?;
        debug!("XRPC GET {nsid} -> {url}");

        let params = [
            ("actorDeviceId", actor_device_id.as_str()),
            ("blobId", blob_id),
        ];

        let resp = self
            .http
            .get(&url)
            .headers(headers)
            .query(&params)
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let body_bytes = if self.should_retry_after_refresh(status, &body_bytes) {
            let new_bearer = self.refresh_bearer().await?;
            let fresh_bearer = self.get_service_token(nsid).await.unwrap_or(new_bearer);
            let (url, headers) = self.build_request(nsid, &fresh_bearer)?;
            let retry_resp = self
                .http
                .get(&url)
                .headers(headers)
                .query(&params)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            let retry_status = retry_resp.status();
            let retry_bytes = retry_resp
                .bytes()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            if !retry_status.is_success() {
                let body_str = String::from_utf8_lossy(&retry_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {retry_status}: {body_str}"
                )));
            }
            retry_bytes
        } else {
            if !status.is_success() {
                let body_str = String::from_utf8_lossy(&body_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "{nsid} returned {status}: {body_str}"
                )));
            }
            body_bytes
        };

        tokio::fs::write(output_path, &body_bytes)
            .await
            .map_err(|e| CatmosError::Other(format!("Failed to write {output_path}: {e}")))?;

        Ok(())
    }

    pub async fn get_blob_usage(&self) -> Result<BlobUsage> {
        let actor_device_id = self.actor_device_id().await?;
        let resp: serde_json::Value = self
            .xrpc_query(
                "blue.catbird.chat.getBlobUsage",
                &[("actorDeviceId", &actor_device_id)],
            )
            .await?;

        let used_bytes = resp.get("usedBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let quota_bytes = resp.get("quotaBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let blob_count = resp.get("blobCount").and_then(|v| v.as_i64()).unwrap_or(0);

        Ok(BlobUsage {
            used_bytes,
            quota_bytes,
            blob_count,
        })
    }

    pub async fn remove_device(&self, device_id: &str) -> Result<(bool, i64, i64)> {
        let req = serde_json::json!({
            "deviceId": device_id,
        });

        let resp: serde_json::Value = self
            .xrpc_procedure("blue.catbird.chat.revokeDevice", &req)
            .await?;

        let deleted = resp.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false);
        let kp_deleted = resp.get("keyPackagesDeleted").and_then(|v| v.as_i64()).unwrap_or(0);
        let convos_left = resp.get("conversationsLeft").and_then(|v| v.as_i64()).unwrap_or(0);

        Ok((deleted, kp_deleted, convos_left))
    }

    pub async fn replenish_key_packages(&self) -> Result<u32> {
        let actor_device_id = self.actor_device_id().await?;
        let identity = format!("{}#{}", self.did(), actor_device_id);
        let packages = self.mls.create_key_packages(identity.as_bytes(), 25)?;

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

        let req = serde_json::json!({
            "keyPackages": key_packages_json,
        });

        let resp: serde_json::Value = self
            .xrpc_procedure("blue.catbird.chat.replenishKeyPackages", &req)
            .await?;

        let accepted = resp.get("accepted").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(accepted as u32)
    }

    pub(crate) fn build_request(&self, nsid: &str, bearer: &str) -> Result<(String, HeaderMap)> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| CatmosError::AuthFailed(e.to_string()))?,
        );

        let url = match &self.auth {
            AuthMethod::OAuth { nest_url, .. } => format!("{nest_url}/xrpc/{nsid}"),
            AuthMethod::AppPassword { pds_url, .. } => {
                if nsid.starts_with("blue.catbird.chat.") || nsid.starts_with("blue.catbird.mlsChat.") {
                    let proxy_val = crate::mls::atproto_proxy_header_value();
                    if let Ok(hv) = HeaderValue::from_str(&proxy_val) {
                        headers.insert(
                            reqwest::header::HeaderName::from_static("atproto-proxy"),
                            hv,
                        );
                    }
                    let chat_base = std::env::var("ATPROTO_CHAT_HOST")
                        .unwrap_or_else(|_| self.config.server.mls_url.clone());
                    format!("{}/xrpc/{nsid}", chat_base.trim_end_matches('/'))
                } else {
                    format!("{}/xrpc/{nsid}", pds_url.trim_end_matches('/'))
                }
            }
        };

        Ok((url, headers))
    }
}

pub(crate) fn build_create_convo_request(
    group_id_hex: &str,
    initial_members: &[String],
    welcome_bytes: Option<Vec<u8>>,
    key_package_hashes: Vec<(String, String)>,
) -> serde_json::Value {
    let mut req = serde_json::json!({
        "groupId": group_id_hex,
        "cipherSuite": MLS_CIPHER_SUITE,
        "currentEpoch": if welcome_bytes.is_some() { 1 } else { 0 },
    });
    if let Some(welcome) = welcome_bytes {
        req["welcomeMessage"] = serde_json::json!(BASE64.encode(&welcome));
    }
    if !initial_members.is_empty() {
        req["initialMembers"] = serde_json::json!(initial_members);
    }
    if !key_package_hashes.is_empty() {
        let hashes: Vec<serde_json::Value> = key_package_hashes
            .into_iter()
            .map(|(did, hash)| {
                serde_json::json!({
                    "did": did,
                    "hash": hash,
                })
            })
            .collect();
        req["keyPackageHashes"] = serde_json::json!(hashes);
    }
    req
}

pub(crate) fn build_commit_group_change(
    convo_id: &str,
    action: &str,
    commit: Option<Vec<u8>>,
    welcome: Option<Vec<u8>>,
    group_info: Option<Vec<u8>>,
    confirmation_tag: Option<Vec<u8>>,
    member_dids: Option<Vec<String>>,
    idempotency_key: Option<String>,
) -> serde_json::Value {
    let mut val = serde_json::json!({
        "convoId": convo_id,
        "action": action,
    });
    if let Some(c) = commit {
        val["commit"] = serde_json::json!(BASE64.encode(c));
    }
    if let Some(w) = welcome {
        val["welcome"] = serde_json::json!(BASE64.encode(w));
    }
    if let Some(gi) = group_info {
        val["groupInfo"] = serde_json::json!(BASE64.encode(gi));
    }
    if let Some(ct) = confirmation_tag {
        val["confirmationTag"] = serde_json::json!(BASE64.encode(ct));
    }
    if let Some(dids) = member_dids {
        val["memberDids"] = serde_json::json!(dids);
    }
    if let Some(ik) = idempotency_key {
        val["idempotencyKey"] = serde_json::json!(ik);
    }
    val
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    const KNOWN_BYTES: &[u8] = &[0, 1, 2, 3, 4, 0xde, 0xad, 0xbe, 0xef];
    const SINGLE_ENCODED: &str = "AAECAwTerb7v";
    const DOUBLE_ENCODED: &str = "QUFFQ0F3VGVyYjd2";

    #[test]
    fn build_create_convo_request_uses_xwing_and_raw_welcome_bytes() {
        assert_eq!(B64.encode(KNOWN_BYTES), SINGLE_ENCODED);
        assert_eq!(B64.encode(SINGLE_ENCODED.as_bytes()), DOUBLE_ENCODED);

        let input = build_create_convo_request(
            "deadbeef",
            &["did:plc:alice".to_string()],
            Some(KNOWN_BYTES.to_vec()),
            vec![("did:plc:alice".to_string(), "hash-a".to_string())],
        );

        let json = serde_json::to_value(&input).expect("serialize CreateConvo");
        assert_eq!(json["cipherSuite"], MLS_CIPHER_SUITE);
        assert_eq!(json["currentEpoch"], 1);
        assert_eq!(json["initialMembers"][0], "did:plc:alice");
        assert_eq!(json["keyPackageHashes"][0]["did"], "did:plc:alice");
        assert_eq!(json["keyPackageHashes"][0]["hash"], "hash-a");

        let encoded = json["welcomeMessage"]
            .as_str()
            .expect("welcomeMessage base64 string");
        assert_eq!(encoded, SINGLE_ENCODED);
        assert_ne!(encoded, DOUBLE_ENCODED);
    }

    #[test]
    fn build_create_convo_request_seeds_empty_create_at_epoch_zero() {
        let input = build_create_convo_request("deadbeef", &[], None, vec![]);

        let json = serde_json::to_value(&input).expect("serialize CreateConvo");
        assert_eq!(json["cipherSuite"], MLS_CIPHER_SUITE);
        assert_eq!(json["currentEpoch"], 0);
        assert!(json.get("initialMembers").is_none());
        assert!(json.get("welcomeMessage").is_none());
        assert!(json.get("keyPackageHashes").is_none());
    }

    #[test]
    fn expired_token_response_detection() {
        assert!(is_expired_token_response(
            StatusCode::BAD_REQUEST,
            br#"{"error":"ExpiredToken","message":"Token has expired"}"#
        ));
        assert!(is_expired_token_response(
            StatusCode::UNAUTHORIZED,
            br#"{"error":"ExpiredToken"}"#
        ));
        assert!(!is_expired_token_response(
            StatusCode::BAD_REQUEST,
            br#"{"error":"InvalidRequest","message":"ExpiredToken flow not allowed here"}"#
        ));
        assert!(!is_expired_token_response(
            StatusCode::UNAUTHORIZED,
            br#"{"error":"AuthRequired"}"#
        ));
        assert!(!is_expired_token_response(
            StatusCode::NOT_FOUND,
            br#"{"error":"ExpiredToken"}"#
        ));
    }
}
