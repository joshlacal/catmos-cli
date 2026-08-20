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
use crate::mls::{MlsManager, MLS_CIPHER_SUITE};
use crate::recovery::{
    GroupInfo404Tracker, QuarantineExitReason, QuarantineReason, RecoveryTracker,
};
use crate::storage::aliases::AliasStore;
use crate::storage::config::Config;
use crate::storage::db::Database;
use crate::types::{BlobUsage, Conversation, Device, KeyPackageStatus};

/// Layer 3 quarantine event published on the broadcast channel held by
/// `ChatService::quarantine_events`. The TUI subscribes and translates these
/// into `AppEvent::Quarantined` / `AppEvent::QuarantineCleared`. Mirrors the
/// `OrchestratorEventCallback::on_conversation_quarantined` /
/// `_quarantine_cleared` pair from `catbird-mls/src/orchestrator_bridge.rs`
/// (f363fd1) — catmos-cli doesn't consume the orchestrator bridge, so we
/// publish at the platform layer instead.
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
            if err == "ExpiredToken" {
                return true;
            }
        }
    }
    if let Ok(text) = std::str::from_utf8(body) {
        if text.contains("ExpiredToken") {
            return true;
        }
    }
    false
}


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

// ── commitGroupChange ───────────────────────────────────────────────────
//
// Thin DeserializeOwned response wrapper for `commitGroupChange`. Mirrors the
// Jacquard-generated `CommitGroupChangeOutput` shape for the fields we care
// about at the sender side — used to pick up the server-echoed `newEpoch`
// which we fence `confirm_commit` against.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitGroupChangeResp {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    new_epoch: Option<i64>,
}

// ── getKeyPackages ──────────────────────────────────────────────────────
//
// DeserializeOwned wrapper for `getKeyPackages` output. The server emits
// `keyPackage` as a `{"$bytes": "base64..."}` envelope (AT Protocol bytes
// wrapper), so we use `serde_bytes_wrapper` below to unwrap it.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // did / cipher_suite / key_package_hash are parsed but
                    // not yet consumed — kept for log-line surface and for
                    // future `keyPackageHashes` commit-group-change field.
pub(crate) struct KeyPackageRefResp {
    did: String,
    cipher_suite: String,
    #[serde(with = "serde_bytes_wrapper")]
    key_package: Vec<u8>,
    #[serde(default)]
    key_package_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetKeyPackagesResp {
    #[serde(default)]
    key_packages: Vec<KeyPackageRefResp>,
    #[serde(default)]
    #[allow(dead_code)]
    missing: Option<Vec<String>>,
}

/// AT Protocol `{"$bytes": "base64..."}` envelope → raw `Vec<u8>`.
///
/// The server-side lexicon types serialize `bytes` fields as
/// `{"$bytes": "<BASE64>"}`. Use this helper when deserializing into a
/// plain `Vec<u8>` in our thin owned response wrappers.
mod serde_bytes_wrapper {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use serde::{de::Error as DeError, Deserialize, Deserializer};

    #[derive(Deserialize)]
    struct Wrapper {
        #[serde(rename = "$bytes")]
        bytes: String,
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let w = Wrapper::deserialize(d)?;
        BASE64
            .decode(&w.bytes)
            .map_err(|e| D::Error::custom(format!("invalid $bytes base64: {e}")))
    }
}

/// Build a `CommitGroupChange<'static>` for the wire **without** going through
/// the buggy `InputData → Input` adapter in `catbird-atproto`.
///
/// Why not use `catbird_atproto::catbird::mls_chat::commit_group_change::InputData`?
/// That adapter types `commit` / `welcome` / `group_info` / `confirmation_tag` as
/// `Option<String>`, and its `From<InputData> for Input` impl maps them via
/// `String → bytes::Bytes`. `bytes::Bytes::from(String)` takes the UTF-8 bytes
/// of the string verbatim — so when callers pass a pre-base64 string, the
/// bytes field ends up containing the ASCII of the base64 text and the jacquard
/// serializer then wraps it as `{"$bytes": base64(ASCII-base64)}`, producing
/// double-encoded commits the server rejects or silently mis-decodes. Building
/// the lexicon struct directly lets us pass raw `bytes::Bytes::from(Vec<u8>)`
/// so the single serializer layer does the one correct base64 encode.
#[allow(clippy::too_many_arguments)]
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

pub(crate) fn build_create_convo_request(
    group_id: &str,
    initial_members: &[String],
    welcome_message: Option<Vec<u8>>,
    key_package_hashes: Vec<(String, String)>,
) -> serde_json::Value {
    let current_epoch = if welcome_message.is_some() { 1 } else { 0 };

    let mut val = serde_json::json!({
        "groupId": group_id,
        "cipherSuite": MLS_CIPHER_SUITE,
        "currentEpoch": current_epoch,
    });
    if !initial_members.is_empty() {
        val["initialMembers"] = serde_json::json!(initial_members);
    }
    if let Some(w) = welcome_message {
        val["welcomeMessage"] = serde_json::json!(BASE64.encode(w));
    }
    if !key_package_hashes.is_empty() {
        let kps: Vec<serde_json::Value> = key_package_hashes
            .into_iter()
            .map(|(did, hash)| serde_json::json!({ "did": did, "hash": hash }))
            .collect();
        val["keyPackageHashes"] = serde_json::json!(kps);
    }
    val
}

/// Central coordinator for chat operations: XRPC calls, message encryption,
/// WebSocket subscriptions, and local storage.
pub struct ChatService {
    pub(crate) http: reqwest::Client,
    pub(crate) auth: AuthMethod,
    /// Jacquard-backed token lifecycle (login/refresh) for AppPassword auth.
    /// `None` for OAuth, which is refreshed server-side by nest.
    pub(crate) token_session: Option<TokenSession>,
    pub mls: Arc<MlsManager>,
    pub db: Arc<Database>,
    pub(crate) config: Config,
    pub(crate) aliases: Arc<RwLock<AliasStore>>,
    pub(crate) conversations: Arc<RwLock<Vec<Conversation>>>,
    /// DID -> handle cache, populated during fetch_conversations.
    pub(crate) handle_cache: Arc<RwLock<HashMap<String, String>>>,
    /// Process-wide rejoin tracker (spec §8.4). Replaces the previous
    /// `repair_cooldowns` map — the new tracker also enforces the global
    /// `MIN_REJOIN_INTERVAL` floor across all conversations and the per-convo
    /// `MAX_REJOIN_ATTEMPTS` cap.
    pub(crate) recovery_tracker: Arc<Mutex<RecoveryTracker>>,
    /// Per-conversation GroupInfo 404 circuit breaker (spec §8.3).
    pub(crate) groupinfo_404_tracker: Arc<Mutex<GroupInfo404Tracker>>,
    /// Per-conversation consecutive decryption failures at the same epoch.
    /// Reset on every successful decrypt; threshold = `DECRYPTION_FAILURE_THRESHOLD`
    /// (spec §10).
    pub(crate) decrypt_fail_counts: Arc<Mutex<HashMap<String, u32>>>,
    /// Per-conversation consecutive `merge_incoming_commit` / WrongEpoch
    /// failures. Threshold = `EPOCH_DIVERGENCE_THRESHOLD` (spec §10).
    pub(crate) epoch_divergence_counts: Arc<Mutex<HashMap<String, u32>>>,
    /// Own-commit SHA256 dedup: hash → timestamp. Prevents processing our own commits
    /// as incoming messages (spec §5.4). Entries expire after 5 minutes.
    pub(crate) own_commits: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    /// Broadcast channel for Layer 3 quarantine state changes. The TUI
    /// subscribes via `subscribe_quarantine_events`; off-the-record
    /// listeners (tests, future telemetry) can also subscribe. Capacity 32
    /// keeps slow consumers from blocking the sender; a missed event just
    /// means the next `get_recovery_flags` read will reconcile state.
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
            quarantine_events: tokio::sync::broadcast::channel(32).0,
        }
    }

    /// Subscribe to Layer 3 quarantine state changes (TUI banner / status
    /// line, tests). Receivers fall behind safely — bursts of >32 events
    /// drop oldest first.
    pub fn subscribe_quarantine_events(&self) -> tokio::sync::broadcast::Receiver<QuarantineEvent> {
        self.quarantine_events.subscribe()
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

    /// POST an XRPC procedure (e.g. `blue.catbird.chat.sendMessage`).
    ///
    /// On 401/Unauthorized from AppPassword sessions, refreshes the jacquard
    /// session and retries exactly once.
    pub async fn xrpc_procedure<Req: Serialize + ?Sized, Resp: DeserializeOwned>(
        &self,
        nsid: &str,
        input: &Req,
    ) -> Result<Resp> {
        let bearer = self.current_bearer().await?;
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
            let (url, headers) = self.build_request(nsid, &new_bearer)?;
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

    /// POST raw JSON bytes to an XRPC procedure.
    pub async fn xrpc_post_raw<Resp: DeserializeOwned>(
        &self,
        nsid: &str,
        body_json: &[u8],
    ) -> Result<Resp> {
        let bearer = self.current_bearer().await?;
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
                if is_sensitive_device_endpoint {
                    return Err(CatmosError::Xrpc(format!("{nsid} returned {retry_status}")));
                } else {
                    let body_str = String::from_utf8_lossy(&retry_bytes);
                    return Err(CatmosError::Xrpc(format!(
                        "{nsid} returned {retry_status}: {body_str}"
                    )));
                }
            }
            retry_bytes
        } else {
            if !status.is_success() {
                if is_sensitive_device_endpoint {
                    return Err(CatmosError::Xrpc(format!("{nsid} returned {status}")));
                } else {
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    return Err(CatmosError::Xrpc(format!(
                        "{nsid} returned {status}: {body_str}"
                    )));
                }
            }
            body_bytes
        };

        serde_json::from_slice::<Resp>(&body_bytes)
            .map_err(|e| CatmosError::Xrpc(format!("Failed to parse {nsid} response: {e}")))
    }

    /// GET an XRPC query (e.g. `blue.catbird.chat.getConversations`).
    ///
    /// On 401/Unauthorized from AppPassword sessions, refreshes the jacquard
    /// session and retries exactly once.
    pub async fn xrpc_query<R: DeserializeOwned>(
        &self,
        nsid: &str,
        params: &[(&str, &str)],
    ) -> Result<R> {
        let bearer = self.current_bearer().await?;
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
            let (url, headers) = self.build_request(nsid, &new_bearer)?;
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
                if is_sensitive_device_endpoint {
                    return Err(CatmosError::Xrpc(format!("{nsid} returned {retry_status}")));
                } else {
                    let body_str = String::from_utf8_lossy(&retry_bytes);
                    return Err(CatmosError::Xrpc(format!(
                        "{nsid} returned {retry_status}: {body_str}"
                    )));
                }
            }
            retry_bytes
        } else {
            if !status.is_success() {
                if is_sensitive_device_endpoint {
                    return Err(CatmosError::Xrpc(format!("{nsid} returned {status}")));
                } else {
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    return Err(CatmosError::Xrpc(format!(
                        "{nsid} returned {status}: {body_str}"
                    )));
                }
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
                    "Failed to parse {nsid}: {e}\nBody: {}",
                    String::from_utf8_lossy(&body_bytes[..sample_len])
                ))
            }
        })
    }

    /// True if we should refresh & retry after the server returned this status
    /// code and body (AppPassword only — OAuth is refreshed server-side by nest).
    /// Only retries when the response is explicitly an ExpiredToken error.
    pub(crate) fn should_retry_after_refresh(&self, status: StatusCode, body: &[u8]) -> bool {
        self.token_session.is_some() && is_expired_token_response(status, body)
    }

    /// Return the active registered device ID for this account.
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
    /// Fetch the current bearer token for the active auth method.
    pub(crate) async fn current_bearer(&self) -> Result<String> {
        match (&self.auth, &self.token_session) {
            (AuthMethod::OAuth { session_cookie, .. }, _) => Ok(session_cookie.clone()),
            (AuthMethod::AppPassword { .. }, Some(sess)) => sess.current_bearer().await,
            (AuthMethod::AppPassword { .. }, None) => Err(CatmosError::AuthFailed(
                "AppPassword auth without a TokenSession — restart catmos".into(),
            )),
        }
    }

    /// Force a `refreshSession` call on the AppPassword token session, persist
    /// the new tokens, and return the fresh bearer. Fails if no token session.
    pub(crate) async fn refresh_bearer(&self) -> Result<String> {
        let sess = self
            .token_session
            .as_ref()
            .ok_or_else(|| CatmosError::AuthFailed("no TokenSession — cannot refresh".into()))?;
        tracing::info!("Refreshing app-password session tokens");
        sess.refresh(&self.db).await
    }

    // ── Conversation management ──────────────────────────────────────────

    /// Create a new MLS group conversation on the server.
    ///
    /// Per the MLS metadata cutover (Phase C), this **does not** ship a
    /// plaintext `metadata { name, description }` field on `createConvo`. The
    /// returned `Conversation` has `name: None` / `description: None`; the
    /// caller is expected to drive the encrypted-bootstrap path via
    /// `bootstrap_group_metadata_for_convo` (see `chat/metadata.rs`) once the
    /// local MLS group exists. `name` / `description` are persisted as part
    /// of `GroupMetadataV1` and uploaded as an opaque blob through
    /// `putGroupMetadataBlob`.
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

    /// Submit a `bootstrapResetGroup` call for the first-responder bootstrap
    /// path (spec §8.5 Phase 1, mls-ds endpoint added in task #17 / commit
    /// `mls-ds@da85949`). The MLS group at `new_group_id_hex` MUST already
    /// exist locally (created via `MLSContext::create_group_with_id` and its
    /// `group_info` blob exported via `MLSContext::export_group_info`).
    ///
    /// Why a dedicated endpoint vs. `createConvo` with a predetermined
    /// `groupId`: post-reset, the server holds a row at
    /// `(id=originalConvoId, group_id=newGroupId)` waiting to be bootstrapped.
    /// `createConvo` would INSERT a brand-new row at `id=newGroupId` and
    /// orphan the post-reset row. `bootstrapResetGroup` UPDATEs the existing
    /// row in place via `WHERE id=originalConvoId AND group_id=newGroupId AND
    /// group_info IS NULL`.
    ///
    /// Race-loser detection: server returns HTTP 409 with body
    /// `"AlreadyBootstrapped"` when the post-reset row's `group_info` was
    /// already set by another caller; classified by
    /// `recovery_ops::is_bootstrap_already_bootstrapped`.
    ///
    /// `welcome_message` is `None` because race-winners broadcast Welcome via
    /// the next `add_members` cycle (mirrors
    /// `catbird-mls/src/orchestrator/recovery.rs:1654`).
    #[allow(clippy::too_many_arguments)]
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

    /// Leave (remove self from) a conversation.
    pub async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        let req = serde_json::json!({
            "convoId": convo_id,
        });

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.chat.requestLeave", &req)
            .await?;

        Ok(())
    }

    /// List devices registered for the authenticated user.
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

    /// Get the current key package availability status.
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
                        target: 25,
                        needs_replenish: avail < 10,
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
                target: 50,
                needs_replenish: avail < 10,
            });
        }

        Ok(KeyPackageStatus {
            available: 0,
            target: 25,
            needs_replenish: true,
        })
    }

    // ── Join / Update / Member management ─────────────────────────────────

    // NOTE: the former `join_conversation` method lived here. It POSTed
    // `commitGroupChange` with `action: "externalCommit"` and every commit/
    // welcome/group_info field set to None — no MLS crypto was performed
    // locally, so the server always rejected it as `InvalidCommit`. The real
    // external-commit join flow is in `crate::mls::onboarding::MlsManager::
    // join_via_external_commit`, which fetches GroupInfo, constructs the
    // external commit via `MLSContext::create_external_commit`, and merges
    // locally on success. Removed in task #65 along with fixing the same
    // double-encoding wire bug in onboarding.rs. CLI `convo join` now routes
    // there directly.

    /// Update conversation metadata (name, description).
    ///
    /// This drives a client-side MLS commit (GroupContextExtensions update) via
    /// the three-phase `stage_commit` / `confirm_commit` / `discard_pending`
    /// API on `MLSContext` and posts to `commitGroupChange` with
    /// `action: "updateMetadata"`.
    ///
    /// Note: the generic `"commit" | "updateMetadata"` branch on the server
    /// rejects requests that set `welcome` or `memberDids`, so those stay
    /// `None`. The server also does not echo `newEpoch` reliably for this
    /// action, so we fence `confirm_commit` with the skip sentinel and trust
    /// the staged target epoch.
    pub async fn update_conversation(
        &self,
        convo_id: &str,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<()> {
        // Phase A.2 encrypted-only path. The previous plaintext-0xff00 +
        // FFICommitKind::UpdateMetadata route is retired; the MLS group
        // context only carries an encrypted MetadataReference (see
        // catbird-mls/src/metadata.rs), and the title/description/avatar
        // live in a ChaCha20-Poly1305 blob the DS holds opaquely.
        //
        // 1. Stage commit + derive post-commit metadata key + encrypt
        //    `GroupMetadataV1` payload + assemble artifacts in one FFI call.
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|_| CatmosError::Other(format!("Invalid hex group ID: {convo_id}")))?;
        let result = self.mls.with_context(|ctx| {
            ctx.update_group_metadata_encrypted(
                group_id_bytes.clone(),
                name.map(str::to_string),
                description.map(str::to_string),
                None, // avatar_blob_locator (separate flow when wired)
                None, // avatar_content_type
            )
        })?;

        // Track our own commit BEFORE shipping it so the incoming sync/WS
        // path doesn't reprocess (spec §5.4 — own-commit dedup).
        self.track_own_commit(&result.commit_bytes).await;

        // 2. Upload the encrypted blob FIRST. If the upload fails we must
        //    clear the local pending commit so the local epoch doesn't
        //    advance past a state other clients can't reach (no blob → no
        //    decryptable metadata).
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

        // 3. POST commitGroupChange. Server enforces non-add-action contract:
        //    welcome / memberDids must be None for updateMetadata.
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
                // 4. Merge locally — advances epoch, applies the new
                //    MetadataReference in AppDataDictionary 0x8001.
                if let Err(e) = self
                    .mls
                    .with_context(|ctx| ctx.merge_pending_commit(group_id_bytes.clone()))
                {
                    warn!("update_conversation: merge_pending_commit failed for {convo_id}: {e}");
                    return Err(e);
                }
                info!(
                    "Updated metadata for conversation {convo_id} \
                     (encrypted, version={}, locator={})",
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

    /// Add a member to a conversation.
    ///
    /// Drives a client-side MLS `addMembers` commit (three-phase:
    /// `stage_commit` → POST → `confirm_commit` on success, `discard_pending`
    /// on any failure). Fetches the target device's key packages from the
    /// server first, then constructs and ships the commit + Welcome.
    pub async fn add_member(&self, convo_id: &str, member_did: &str) -> Result<()> {
        // 1. Fetch key packages for the target DID (server returns one KP per
        //    registered device). Missing DIDs surface as an error.
        let kp_refs = self.fetch_key_packages(&[member_did.to_string()]).await?;
        if kp_refs.is_empty() {
            return Err(CatmosError::Other(format!(
                "No key packages available for {member_did}"
            )));
        }
        let key_packages: Vec<Vec<u8>> = kp_refs.iter().map(|k| k.key_package.clone()).collect();

        // 2. Stage the addMembers commit locally.
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

        // 3. POST commitGroupChange with commit + welcome + memberDids.
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
                // Server echoes `newEpoch` on the addMembers path (see
                // mls-ds `handle_add_members`). Use it to fence
                // confirm_commit, mirroring iOS. Fall back to the skip
                // sentinel for idempotency hits where the server returns 0.
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

    /// Remove a member from a conversation.
    ///
    /// Drives a client-side MLS `removeMembers` commit (three-phase). No
    /// Welcome is produced by this path.
    pub async fn remove_member(&self, convo_id: &str, member_did: &str) -> Result<()> {
        // 1. Stage the removeMembers commit locally.
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

        // 2. POST commitGroupChange with commit + memberDids. No welcome.
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
                // Server echoes `newEpoch` on the removeMembers path (see
                // mls-ds handler, returns Some(new_epoch as i64)). Fence
                // confirm_commit against it; fall back to skip sentinel for
                // idempotency hits.
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

    /// Record a SHA-256 of our outgoing commit ciphertext so the incoming
    /// sync / WebSocket paths can dedup the server-fanned echo (spec §5.4).
    async fn track_own_commit(&self, commit_bytes: &[u8]) {
        let hash: [u8; 32] = Sha256::digest(commit_bytes).into();
        let mut own = self.own_commits.lock().await;
        own.insert(hash, Instant::now());
        // Expire entries older than 5 minutes.
        own.retain(|_, ts| ts.elapsed() < std::time::Duration::from_secs(300));
    }

    /// Fetch key packages for the given DIDs from the server.
    ///
    /// The server returns one key package per registered device for each DID.
    /// Missing DIDs are surfaced in `missing` (we currently ignore that — the
    /// caller will just see an empty `key_packages` and can decide policy).
    pub(crate) async fn fetch_key_packages(
        &self,
        dids: &[String],
    ) -> Result<Vec<KeyPackageRefResp>> {
        // xrpc_query takes `&[(&str, &str)]`; `dids` is a repeated query
        // parameter per AT Protocol convention.
        let params: Vec<(&str, &str)> = dids.iter().map(|d| ("dids", d.as_str())).collect();
        let resp: GetKeyPackagesResp = self
            .xrpc_query("blue.catbird.chat.getKeyPackages", &params)
            .await?;
        Ok(resp.key_packages)
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
    /// Fetch group state from the server.
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

    // ── Blob operations ─────────────────────────────────────────────────

    /// Upload a file as an encrypted blob associated with a conversation.
    /// Returns the server-assigned blob ID.
    pub async fn upload_blob(&self, convo_id: &str, file_path: &str) -> Result<String> {
        let data = tokio::fs::read(file_path)
            .await
            .map_err(|e| CatmosError::Other(format!("Failed to read file {file_path}: {e}")))?;

        let actor_device_id = self.actor_device_id().await?;
        let nsid = "blue.catbird.chat.uploadBlob";
        let bearer = self.current_bearer().await?;
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
            let (url, headers) = self.build_request(nsid, &new_bearer)?;
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

    /// Download a blob by ID and write it to the given output path.
    pub async fn download_blob(&self, blob_id: &str, output_path: &str) -> Result<()> {
        let actor_device_id = self.actor_device_id().await?;
        let nsid = "blue.catbird.chat.getBlob";
        let bearer = self.current_bearer().await?;
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
            let (url, headers) = self.build_request(nsid, &new_bearer)?;
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

    /// Get the authenticated user's blob storage usage stats.
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

    /// Build the target URL and auth headers for an XRPC call, given a
    /// pre-resolved bearer token.
    ///
    /// - OAuth: routes through nest (confidential client proxy)
    /// - AppPassword: routes to user's PDS (`pds_url`) with `atproto-proxy` header
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
                }
                format!("{}/xrpc/{nsid}", pds_url.trim_end_matches('/'))
            }
        };

        Ok((url, headers))
    }
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
            br#"{"error":"InvalidRequest","message":"Bad payload"}"#
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
