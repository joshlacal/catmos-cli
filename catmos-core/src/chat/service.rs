use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use catbird_atproto::blue_catbird::mlsChat::commit_group_change::CommitGroupChange;
use catbird_atproto::catbird::mls_chat;
use catbird_mls::group_metadata::GroupMetadata;
use catbird_mls::orchestrator_bridge::FFICommitKind;

use crate::auth::{AuthMethod, TokenSession};
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
struct KeyPackageRefResp {
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
) -> CommitGroupChange<'static> {
    CommitGroupChange {
        convo_id: convo_id.to_string().into(),
        action: action.to_string().into(),
        commit: commit.map(bytes::Bytes::from),
        welcome: welcome.map(bytes::Bytes::from),
        group_info: group_info.map(bytes::Bytes::from),
        confirmation_tag: confirmation_tag.map(bytes::Bytes::from),
        member_dids: member_dids.map(|dids| {
            dids.into_iter()
                .map(catbird_atproto::types::string::Did::from)
                .collect()
        }),
        idempotency_key: idempotency_key.map(Into::into),
        device_id: None,
        epoch_authenticator: None,
        key_package_hashes: None,
        pending_addition_id: None,
        ..Default::default()
    }
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
    ///
    /// On 401/Unauthorized from AppPassword sessions, refreshes the jacquard
    /// session and retries exactly once.
    pub async fn xrpc_procedure<T: Serialize, R: DeserializeOwned>(
        &self,
        nsid: &str,
        input: &T,
    ) -> Result<R> {
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

        let resp = if self.should_retry_after_refresh(resp.status()) {
            let new_bearer = self.refresh_bearer().await?;
            let (url, headers) = self.build_request(nsid, &new_bearer)?;
            debug!("XRPC POST {nsid} retry after refresh -> {url}");
            self.http
                .post(&url)
                .headers(headers)
                .json(input)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?
        } else {
            resp
        };

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

        let resp = if self.should_retry_after_refresh(resp.status()) {
            let new_bearer = self.refresh_bearer().await?;
            let (url, headers) = self.build_request(nsid, &new_bearer)?;
            debug!("XRPC GET {nsid} retry after refresh -> {url}");
            self.http
                .get(&url)
                .headers(headers)
                .query(params)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?
        } else {
            resp
        };

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

    /// True if we should refresh & retry after the server returned this status
    /// code (AppPassword only — OAuth is refreshed server-side by nest).
    pub(crate) fn should_retry_after_refresh(&self, status: StatusCode) -> bool {
        self.token_session.is_some()
            && matches!(
                status,
                StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST
            )
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
        let sess = self.token_session.as_ref().ok_or_else(|| {
            CatmosError::AuthFailed("no TokenSession — cannot refresh".into())
        })?;
        tracing::info!("Refreshing app-password session tokens");
        sess.refresh(&self.db).await
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
                target: 50, // spec: KEY_PACKAGE_TARGET = 50
                needs_replenish: s.total_available < 10, // spec: KEY_PACKAGE_LOW_THRESHOLD = 10
            }),
            None => Ok(KeyPackageStatus {
                available: 0,
                target: 50,
                needs_replenish: true,
            }),
        }
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
        // 1. Build the GroupMetadata JSON blob that MLS will embed in the
        //    group-context extension (matches iOS `GroupMetadataPayload`).
        let metadata = GroupMetadata::new(
            name.map(str::to_string),
            description.map(str::to_string),
        );
        let metadata_json = metadata
            .to_extension_bytes()
            .map_err(|e| CatmosError::Other(format!("Failed to encode GroupMetadata: {e}")))?;

        // 2. Stage the updateMetadata commit locally (not yet merged, not yet
        //    sent to the DS).
        let did = self.did().to_string();
        let plan = self.mls.with_commit_context(|ctx| {
            ctx.stage_commit(
                convo_id.to_string(),
                FFICommitKind::UpdateMetadata {
                    group_info_extension: metadata_json,
                },
                did.as_bytes().to_vec(),
            )
        })?;

        // 3. POST commitGroupChange carrying the raw commit bytes. welcome /
        //    memberDids MUST be None for updateMetadata (server-side
        //    enforce_non_add_action_contract gate).
        let req = build_commit_group_change(
            convo_id,
            "updateMetadata",
            Some(plan.commit_bytes.clone()),
            None,
            None,
            None,
            None,
            Some(ulid::Ulid::new().to_string()),
        );

        // Track our own commit so the incoming sync/WS path doesn't
        // redundantly process it (spec §5.4 — own-commit dedup).
        self.track_own_commit(&plan.commit_bytes).await;

        let handle = plan.handle.clone();
        match self
            .xrpc_procedure::<_, CommitGroupChangeResp>(
                mls_chat::commit_group_change::NSID,
                &req,
            )
            .await
        {
            Ok(resp) if resp.success => {
                // commitGroupChange does not reliably echo newEpoch for the
                // `updateMetadata` path — fence with the skip sentinel and
                // trust the staged target epoch (mirrors iOS).
                let server_epoch = catbird_mls::mls_skip_server_epoch_fence();
                if let Err(e) = self
                    .mls
                    .with_commit_context(|ctx| ctx.confirm_commit(handle.clone(), server_epoch))
                {
                    warn!(
                        "update_conversation: confirm_commit failed for {convo_id}: {e} — \
                         discarding staged commit to avoid leaking pending state"
                    );
                    // TODO(#63): if `e` is an unflattened EpochMismatch, we
                    // could surface { local, remote } to the caller.
                    let _ = self
                        .mls
                        .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                    return Err(e);
                }
                info!("Updated metadata for conversation {convo_id}");
                Ok(())
            }
            Ok(_) => {
                // Server returned 200 but success=false — treat as failure.
                let _ = self
                    .mls
                    .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                Err(CatmosError::Xrpc(format!(
                    "commitGroupChange[updateMetadata] returned success=false for {convo_id}"
                )))
            }
            Err(e) => {
                // Server rejected the commit — discard the staged handle so
                // OpenMLS's one-pending-commit invariant is restored.
                let _ = self
                    .mls
                    .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
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
            CatmosError::Other(
                "stage_commit(AddMembers) did not return welcome bytes".to_string(),
            )
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
            .xrpc_procedure::<_, CommitGroupChangeResp>(
                mls_chat::commit_group_change::NSID,
                &req,
            )
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
                    warn!(
                        "add_member: confirm_commit failed for {convo_id}: {e} — discarding"
                    );
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
            .xrpc_procedure::<_, CommitGroupChangeResp>(
                mls_chat::commit_group_change::NSID,
                &req,
            )
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
                    warn!(
                        "remove_member: confirm_commit failed for {convo_id}: {e} — discarding"
                    );
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
        let params: Vec<(&str, &str)> =
            dids.iter().map(|d| ("dids", d.as_str())).collect();
        let resp: GetKeyPackagesResp = self
            .xrpc_query(mls_chat::get_key_packages::NSID, &params)
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
        let packages = self.mls.create_key_packages(&identity, 50)?;

        let now = chrono::Utc::now();
        let expires_str =
            (now + chrono::Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let key_packages: Vec<mls_chat::publish_key_packages::KeyPackageItem> = packages
            .iter()
            .map(|kp| {
                mls_chat::publish_key_packages::KeyPackageItemData {
                    cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
                    expires: expires_str.parse().expect("valid datetime"),
                    key_package: kp.key_package_data.clone(),
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
        let bearer = self.current_bearer().await?;
        let (url, headers) = self.build_request(nsid, &bearer)?;
        debug!("XRPC POST {nsid} -> {url}");

        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .query(&[("convoId", convo_id)])
            .header("content-type", "application/octet-stream")
            .body(data.clone())
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let resp = if self.should_retry_after_refresh(resp.status()) {
            let new_bearer = self.refresh_bearer().await?;
            let (url, headers) = self.build_request(nsid, &new_bearer)?;
            self.http
                .post(&url)
                .headers(headers)
                .query(&[("convoId", convo_id)])
                .header("content-type", "application/octet-stream")
                .body(data)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?
        } else {
            resp
        };

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
        let bearer = self.current_bearer().await?;
        let (url, headers) = self.build_request(nsid, &bearer)?;
        debug!("XRPC GET {nsid} -> {url}");

        let resp = self
            .http
            .get(&url)
            .headers(headers)
            .query(&[("blobId", blob_id)])
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let resp = if self.should_retry_after_refresh(resp.status()) {
            let new_bearer = self.refresh_bearer().await?;
            let (url, headers) = self.build_request(nsid, &new_bearer)?;
            self.http
                .get(&url)
                .headers(headers)
                .query(&[("blobId", blob_id)])
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?
        } else {
            resp
        };

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

    /// Build the target URL and auth headers for an XRPC call, given a
    /// pre-resolved bearer token.
    ///
    /// - OAuth: routes through nest (confidential client proxy)
    /// - AppPassword: routes directly to mls-ds for `blue.catbird.mlsChat.*` endpoints
    pub(crate) fn build_request(
        &self,
        nsid: &str,
        bearer: &str,
    ) -> Result<(String, HeaderMap)> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| CatmosError::AuthFailed(e.to_string()))?,
        );

        let url = match &self.auth {
            AuthMethod::OAuth { nest_url, .. } => format!("{nest_url}/xrpc/{nsid}"),
            AuthMethod::AppPassword { .. } => {
                // Route mlsChat calls directly to the MLS delivery service
                let base = if nsid.starts_with("blue.catbird.mlsChat.") {
                    &self.config.server.mls_url
                } else {
                    &self.config.server.nest_url
                };
                format!("{base}/xrpc/{nsid}")
            }
        };

        Ok((url, headers))
    }
}
