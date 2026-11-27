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
use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::payload_types::CommitKind;
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
use crate::CliOrchestrator;

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
        return text.contains(r#""error":"ExpiredToken"#)
            || text.contains(r#""error": "ExpiredToken"#);
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
            BytesEnvelope::DollarBytes { bytes } | BytesEnvelope::Base64String(bytes) => BASE64
                .decode(&bytes)
                .map_err(|e| D::Error::custom(format!("invalid $bytes base64: {e}"))),
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
    pub(crate) orchestrator: Arc<RwLock<Option<Arc<CliOrchestrator>>>>,
    #[cfg(test)]
    pub(crate) test_tempdir: Option<Arc<tempfile::TempDir>>,
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
            own_commits: Arc::new(Mutex::new(HashMap::new())),
            epoch_divergence_counts: Arc::new(Mutex::new(HashMap::new())),
            inventory_session: Arc::new(RwLock::new(None)),
            quarantine_events: tokio::sync::broadcast::channel(32).0,
            orchestrator: Arc::new(RwLock::new(None)),
            #[cfg(test)]
            test_tempdir: None,
        }
    }

    pub async fn conversations(&self) -> Vec<Conversation> {
        let guard = self.conversations.read().await;
        guard.clone()
    }

    pub fn subscribe_quarantine_events(&self) -> tokio::sync::broadcast::Receiver<QuarantineEvent> {
        self.quarantine_events.subscribe()
    }

    pub async fn set_orchestrator(&self, orchestrator: Arc<CliOrchestrator>) {
        *self.orchestrator.write().await = Some(orchestrator);
    }

    pub async fn orchestrator(&self) -> Option<Arc<CliOrchestrator>> {
        self.orchestrator.read().await.clone()
    }

    /// Read the shared runtime's durable access state without network activity.
    pub async fn canonical_conversation_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<catbird_mls::orchestrator::types::ConversationState>> {
        use catbird_mls::orchestrator::storage::MLSStorageBackend;
        let orchestrator = self.orchestrator().await
            .ok_or_else(|| CatmosError::Other("MLS orchestrator unavailable".into()))?;
        orchestrator.storage().get_conversation_state(conversation_id).await
            .map_err(|error| CatmosError::Other(error.to_string()))
    }

    /// Synchronize a canonical page, then display the authenticated retained
    /// history. Verified terminal states retain read-only local history without
    /// fetching more ciphertext. Other fetch errors remain visible.
    pub async fn load_canonical_message_history(
        &self,
        conversation_id: &str,
        limit: u32,
    ) -> Result<Vec<catbird_mls::orchestrator::types::Message>> {
        use catbird_mls::orchestrator::storage::MLSStorageBackend;
        let orchestrator = self.orchestrator().await.ok_or_else(|| {
            CatmosError::Other("MLS orchestrator unavailable".into())
        })?;
        let state = self.canonical_conversation_state(conversation_id).await?;
        use catbird_mls::orchestrator::types::ConversationState;
        if !matches!(state, Some(ConversationState::DeviceRemoved | ConversationState::Closed)) {
            orchestrator
                .fetch_messages(conversation_id, None, limit, None, None, None)
                .await
                .map_err(|error| CatmosError::Other(error.to_string()))?;
        }
        orchestrator
            .storage()
            .get_messages(conversation_id, limit, None)
            .await
            .map_err(|error| CatmosError::Other(error.to_string()))
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

    /// Resolve names, aliases, and old group IDs to the stable conversation ID.
    pub async fn resolve_convo(&self, input: &str) -> Result<String> {
        let durable = self.db.list_conversations().await?;
        let current = self.conversations().await;
        if exact_stable_match_for_sources(input, &durable, &current)?.is_some()
            || self.aliases.read().await.get(input).is_some()
            || durable.iter().chain(current.iter()).any(|convo| convo.group_id == input)
        {
            return self.resolve_conversation_ids(input).await.map(|ids| ids.0);
        }
        let candidates: HashSet<String> = durable.iter().chain(current.iter())
            .filter(|convo| {
                convo.name.as_deref() == Some(input)
                    || (!input.is_empty() && (convo.conversation_id.starts_with(input)
                        || convo.group_id.starts_with(input)))
            })
            .map(|convo| convo.conversation_id.clone())
            .collect();
        if candidates.len() > 1 {
            return Err(CatmosError::ConvoNotFound(
                format!("Ambiguous conversation {input}; use its full conversation ID"),
            ));
        }
        let canonical = candidates.iter().next().map(String::as_str).unwrap_or(input);
        self.resolve_conversation_ids(canonical).await.map(|ids| ids.0)
    }

    /// Resolve the current crypto group only for direct MLS debug operations.
    pub async fn resolve_mls_group_id(&self, input: &str) -> Result<String> {
        let conversation_id = self.resolve_convo(input).await?;
        self.resolve_conversation_ids(&conversation_id).await.map(|ids| ids.1)
    }

    /// Resolve a conversation input into its stable API/storage identity and
    /// its current MLS group identity.
    ///
    /// The stable conversation ID survives group resets, while `group_id`
    /// changes whenever the MLS group is replaced. Callers that perform both
    /// API/storage work and MLS work must keep these values separate. Exact
    /// stable IDs take precedence over legacy group IDs. A raw group ID is
    /// accepted only after its hex encoding is validated and no authoritative
    /// mapping is available.
    pub(crate) async fn resolve_conversation_ids(&self, input: &str) -> Result<(String, String)> {
        // An exact stable ID is authoritative even if a user-created alias
        // happens to use the same spelling. Resolve this before consulting
        // AliasStore so alias collisions cannot divert API/storage routing.
        let durable = self.db.list_conversations().await?;
        let current = self.conversations().await;
        if let Some(ids) = exact_stable_match_for_sources(input, &durable, &current)? {
            return Ok(ids);
        }

        let alias_target = self.aliases.read().await.get(input).cloned();
        let alias_input = alias_target.is_some();
        let lookup = alias_target.as_deref().unwrap_or(input);

        // The durable conversation row is updated by reset completion before
        // the in-memory cache is refreshed. Consult it first so a send racing
        // a reset cannot encrypt against a stale cached group ID.
        if let Some(ids) = conversation_ids_for_alias(input, &durable, &current)? {
            let ids = if alias_input {
                // An alias may still point at a pre-reset group in the cache.
                // Re-resolve the stable owner before rebinding the alias.
                let stable_id = ids.0.clone();
                conversation_ids_for_sources(&stable_id, &durable, &current)?.unwrap_or(ids)
            } else {
                ids
            };
            if ids.0 == lookup && can_use_legacy_group_fallback(lookup) {
                if let Some(historical) = self
                    .resolve_historical_group_input(lookup, &durable, &current)
                    .await?
                {
                    if alias_input {
                        self.rebind_alias(input, &historical.1).await;
                    }
                    return Ok(historical);
                }
            }
            if alias_input {
                self.rebind_alias(input, &ids.1).await;
            }
            return Ok(ids);
        }
        let source_match = match conversation_ids_for_sources(lookup, &durable, &current) {
            Ok(match_result) => match_result,
            Err(error) if can_use_legacy_group_fallback(lookup) => {
                if let Some(historical) = self
                    .resolve_historical_group_input(lookup, &durable, &current)
                    .await?
                {
                    if alias_input {
                        self.rebind_alias(input, &historical.1).await;
                    }
                    return Ok(historical);
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if let Some(ids) = source_match {
            let ids = if ids.0 != lookup {
                // A historical/legacy group input identified an owner. Use
                // the owner's exact stable ID to obtain its current group
                // rather than encrypting against the retired source.
                conversation_ids_for_sources(&ids.0, &durable, &current)?.unwrap_or(ids)
            } else if alias_input {
                // The raw alias target can resolve through a stale cached group;
                // use its stable owner to obtain the durable current group.
                let stable_id = ids.0.clone();
                conversation_ids_for_sources(&stable_id, &durable, &current)?.unwrap_or(ids)
            } else {
                ids
            };
            if ids.0 == lookup && can_use_legacy_group_fallback(lookup) {
                if let Some(historical) = self
                    .resolve_historical_group_input(lookup, &durable, &current)
                    .await?
                {
                    if alias_input {
                        self.rebind_alias(input, &historical.1).await;
                    }
                    return Ok(historical);
                }
            }
            if alias_input {
                self.rebind_alias(input, &ids.1).await;
            }
            return Ok(ids);
        }
        if can_use_legacy_group_fallback(lookup) {
            if let Some(ids) = self
                .resolve_historical_group_input(lookup, &durable, &current)
                .await?
            {
                let ids = if alias_input {
                    self.rebind_alias(input, &ids.1).await;
                    ids
                } else {
                    ids
                };
                return Ok(ids);
            }
        }

        // A stable ID absent from both local views may have been introduced or
        // remapped remotely. Refresh the authoritative conversation inventory
        // before deciding that it is missing. This also rebinds the in-memory
        // and durable rows for the next operation.
        // `fetch_conversations` bootstraps locally joined metadata, which in
        // turn resolves the stable/current pair. Box this refresh edge so the
        // resolver's authoritative-refresh path does not create an
        // infinitely-sized async future. The refreshed inventory is stored
        // before bootstrap runs, so a matching stable row terminates the
        // resolver without re-entering this branch.
        let refreshed = match Box::pin(self.fetch_conversations()).await {
            Ok(convos) => convos,
            Err(e) => {
                if !alias_input && can_use_legacy_group_fallback(lookup) {
                    return Ok((lookup.to_string(), lookup.to_string()));
                }
                return Err(CatmosError::ConvoNotFound(format!(
                    "no authoritative mapping for conversation {lookup}: {e}"
                )));
            }
        };
        let refreshed_durable = self.db.list_conversations().await?;
        if let Some(ids) = exact_stable_match_for_sources(input, &refreshed_durable, &refreshed)? {
            return Ok(ids);
        }
        if let Some(ids) = conversation_ids_for_alias(input, &refreshed_durable, &refreshed)? {
            let ids = if alias_input {
                let stable_id = ids.0.clone();
                conversation_ids_for_sources(&stable_id, &refreshed_durable, &refreshed)?
                    .unwrap_or(ids)
            } else {
                ids
            };
            if alias_input {
                self.rebind_alias(input, &ids.1).await;
            }
            return Ok(ids);
        }
        let source_match =
            match conversation_ids_for_sources(lookup, &refreshed_durable, &refreshed) {
                Ok(match_result) => match_result,
                Err(error) if can_use_legacy_group_fallback(lookup) => {
                    if let Some(historical) = self
                        .resolve_historical_group_input(lookup, &refreshed_durable, &refreshed)
                        .await?
                    {
                        if alias_input {
                            self.rebind_alias(input, &historical.1).await;
                        }
                        return Ok(historical);
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
        if let Some(ids) = source_match {
            let ids = if ids.0 != lookup {
                conversation_ids_for_sources(&ids.0, &refreshed_durable, &refreshed)?.unwrap_or(ids)
            } else if alias_input {
                let stable_id = ids.0.clone();
                conversation_ids_for_sources(&stable_id, &refreshed_durable, &refreshed)?
                    .unwrap_or(ids)
            } else {
                ids
            };
            if ids.0 == lookup && can_use_legacy_group_fallback(lookup) {
                if let Some(historical) = self
                    .resolve_historical_group_input(lookup, &refreshed_durable, &refreshed)
                    .await?
                {
                    if alias_input {
                        self.rebind_alias(input, &historical.1).await;
                    }
                    return Ok(historical);
                }
            }
            if alias_input {
                self.rebind_alias(input, &ids.1).await;
            }
            return Ok(ids);
        }
        if can_use_legacy_group_fallback(lookup) {
            if let Some(ids) = self
                .resolve_historical_group_input(lookup, &refreshed_durable, &refreshed)
                .await?
            {
                let ids = if alias_input {
                    self.rebind_alias(input, &ids.1).await;
                    ids
                } else {
                    ids
                };
                return Ok(ids);
            }
        }

        if !alias_input && can_use_legacy_group_fallback(lookup) {
            return Ok((lookup.to_string(), lookup.to_string()));
        }

        let label = if alias_input {
            format!("alias {input}")
        } else {
            format!("stable conversation {input}")
        };
        Err(CatmosError::ConvoNotFound(format!(
            "{label} has no current MLS group mapping"
        )))
    }

    async fn rebind_alias(&self, alias: &str, group_id: &str) {
        let already_bound = self
            .aliases
            .read()
            .await
            .get(alias)
            .is_some_and(|target| target == group_id);
        if already_bound {
            return;
        }

        let mut aliases = self.aliases.write().await;
        if let Err(e) = aliases.set(alias.to_string(), group_id.to_string()) {
            warn!(alias, group_id, error = %e, "failed to persist rebound conversation alias");
        }
    }

    async fn resolve_historical_group_input(
        &self,
        input: &str,
        durable: &[Conversation],
        current: &[Conversation],
    ) -> Result<Option<(String, String)>> {
        // Historical lookup is a legacy group-ID path; never allow an
        // arbitrary stable UUID or malformed alias target to become the MLS
        // source merely because a durable row happens to mention it.
        validate_group_id_hex(input)?;
        let matches = self.db.find_conversation_ids_by_group_id(input).await?;
        let owners: HashSet<String> = matches
            .into_iter()
            .map(|(conversation_id, _)| conversation_id)
            .collect();
        if owners.len() > 1 {
            return Err(CatmosError::Other(format!(
                "ambiguous historical MLS group mapping for {input}"
            )));
        }
        let Some(owner) = owners.into_iter().next() else {
            return Ok(None);
        };
        conversation_ids_for_sources(&owner, durable, current)?.map_or_else(
            || {
                Err(CatmosError::ConvoNotFound(format!(
                    "historical group {input} has no current MLS mapping for {owner}"
                )))
            },
            |ids| Ok(Some(ids)),
        )
    }

    pub async fn resolve_handle(&self, did: &str) -> Result<String> {
        let base_url = match &self.auth {
            AuthMethod::OAuth { nest_url, .. } => nest_url.clone(),
            AuthMethod::AppPassword { pds_url, .. } => pds_url.clone(),
        };
        let resp = self
            .http
            .get(format!(
                "{}/xrpc/app.bsky.actor.getProfile",
                base_url.trim_end_matches('/')
            ))
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
            self.refresh_bearer().await?;
            let fresh_bearer = self.get_service_token(nsid).await?;
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
            self.refresh_bearer().await?;
            let fresh_bearer = self.get_service_token(nsid).await?;
            let (url, mut headers) = self.build_request(nsid, &fresh_bearer)?;
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
        let mut query_params: Vec<(&str, &str)> = params.to_vec();
        let mut device_id_holder = String::new();
        if !params.iter().any(|(k, _)| *k == "actorDeviceId") {
            if let Ok(dev_id) = self.actor_device_id().await {
                device_id_holder = dev_id;
            }
        }
        if !device_id_holder.is_empty() {
            query_params.push(("actorDeviceId", &device_id_holder));
        }

        let bearer = self.get_service_token(nsid).await?;
        let (url, headers) = self.build_request(nsid, &bearer)?;
        debug!("XRPC GET {nsid} -> {url}");

        let resp = self
            .http
            .get(&url)
            .headers(headers)
            .query(&query_params)
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
            self.refresh_bearer().await?;
            let fresh_bearer = self.get_service_token(nsid).await?;
            let (url, headers) = self.build_request(nsid, &fresh_bearer)?;
            debug!("XRPC GET {nsid} retry after refresh -> {url}");
            let retry_resp = self
                .http
                .get(&url)
                .headers(headers)
                .query(&query_params)
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
            tracing::debug!(
                "XRPC {nsid} raw: {}",
                String::from_utf8_lossy(&body_bytes[..sample_len])
            );
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
        if let Some(orch) = self.orchestrator().await {
            if let Ok(Some(uuid)) = orch.credentials().get_device_uuid(self.did()).await {
                if !uuid.trim().is_empty() {
                    return Ok(uuid);
                }
            }
        }
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
        if let Some(id) = self.db.get_session_value("device_id").await? {
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
            (AuthMethod::AppPassword { pds_url, .. }, Some(session)) => {
                if !nsid.starts_with("blue.catbird.chat.") && !nsid.starts_with("blue.catbird.mlsChat.") {
                    return session.current_bearer().await;
                }
                let client = crate::device_records::public_client()?;
                let pds = crate::device_records::https_base(pds_url)?;
                let proxy = crate::mls::atproto_proxy_header_value();
                let audience = crate::auth::service_auth::audience(&proxy)?;
                crate::auth::service_auth::acquire(
                    &client, &pds, self.did(), audience, nsid,
                    session.current_bearer().await?, || session.refresh(&self.db),
                ).await
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
        if let Some(orchestrator) = self.orchestrator().await {
            let created = orchestrator.create_group(name, Some(members), description).await
                .map_err(|error| CatmosError::Other(error.to_string()))?;
            let conversation = Conversation {
                conversation_id: created.conversation_id,
                group_id: created.group_id,
                name: created.metadata.as_ref().and_then(|metadata| metadata.name.clone()),
                description: created.metadata.as_ref().and_then(|metadata| metadata.description.clone()),
                // Canonical create may adopt an existing conversation; the
                // current account and local clock are not creation evidence.
                creator: None,
                epoch: created.epoch,
                cipher_suite: MLS_CIPHER_SUITE.to_owned(),
                members: created.members.into_iter().map(|member| crate::types::Member {
                    did: member.did.clone(),
                    user_did: member.did,
                    device_id: None,
                    device_name: None,
                    is_admin: member.role == catbird_mls::orchestrator::types::MemberRole::Admin,
                    is_moderator: false,
                    joined_at: chrono::Utc::now(),
                }).collect(),
                created_at: None,
                last_message_at: created.updated_at,
                unread_count: 0,
                alias: None,
                metadata_version: None,
                metadata_blob_locator: None,
                avatar_blob_locator: None,
                avatar_bytes: None,
                avatar_content_type: None,
            };
            self.db.store_conversation(&conversation).await?;
            let mut conversations = self.conversations.write().await;
            conversations.retain(|existing| existing.conversation_id != conversation.conversation_id);
            conversations.push(conversation.clone());
            return Ok(conversation);
        }
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

        // The create response from older servers may omit the stable
        // conversation ID. Do not expose the MLS group ID as the UI/API
        // identity in that case: refresh the authoritative projection and
        // fail clearly if it still cannot be resolved.
        let mut convo = if resp
            .convo
            .conversation_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty() && id != group_id_hex)
        {
            super::messages::convo_resp_to_conversation(&resp.convo)?
        } else {
            select_created_conversation(self.fetch_conversations().await?, &group_id_hex)?
        };

        // Make the stable projection authoritative before any follow-up
        // metadata transition tries to resolve it. This also ensures a
        // successful create is immediately usable by the TUI.
        self.db.store_conversation(&convo).await?;
        {
            let mut conversations = self.conversations.write().await;
            if let Some(existing) = conversations
                .iter_mut()
                .find(|existing| existing.conversation_id == convo.conversation_id)
            {
                *existing = convo.clone();
            } else {
                conversations.push(convo.clone());
            }
        }

        if !name.trim().is_empty() || description.is_some() {
            self.update_conversation(&convo.conversation_id, Some(name), description)
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
                if let Err(e) = self
                    .publish_group_info(&convo.conversation_id, &group_info)
                    .await
                {
                    warn!(
                        "create_conversation: failed to publish GroupInfo for {group_id_hex}: {e}"
                    );
                }
            }
            Err(e) => {
                warn!("create_conversation: failed to export GroupInfo for {group_id_hex}: {e}");
            }
        }

        // Publish the stable projection before returning to callers. TUI and
        // later message operations must be able to resolve the returned
        // conversation immediately, without waiting for a later sync.
        self.db.store_conversation(&convo).await?;
        let mut conversations = self.conversations.write().await;
        if let Some(existing) = conversations
            .iter_mut()
            .find(|existing| existing.conversation_id == convo.conversation_id)
        {
            *existing = convo.clone();
        } else {
            conversations.push(convo.clone());
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
        let (stable_convo_id, _) = self.resolve_conversation_ids(original_convo_id).await?;
        validate_group_id_hex(new_group_id_hex)?;
        let mut req = serde_json::json!({
            "originalConvoId": stable_convo_id,
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
        let (stable_convo_id, _) = self.resolve_conversation_ids(convo_id).await?;
        let orchestrator = self.orchestrator().await.ok_or_else(|| {
            CatmosError::Other("MLS orchestrator unavailable; cannot leave conversation".into())
        })?;
        orchestrator.leave_group(&stable_convo_id).await
            .map_err(|error| CatmosError::Other(error.to_string()))
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
        let (stable_convo_id, group_id) = self.resolve_conversation_ids(convo_id).await?;
        let group_id_bytes = hex::decode(&group_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;
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
                Some(&stable_convo_id),
                &stable_convo_id,
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
            &stable_convo_id,
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
                    warn!("update_conversation: merge_pending_commit failed for {stable_convo_id}: {e}");
                    return Err(e);
                }
                info!(
                    "Updated metadata for conversation {stable_convo_id} (encrypted, version={}, locator={})",
                    result.metadata_version, result.metadata_blob_locator
                );
                Ok(())
            }
            Ok(_) => {
                let _ = self
                    .mls
                    .with_context(|ctx| ctx.clear_pending_commit(group_id_bytes.clone()));
                Err(CatmosError::Xrpc(format!(
                    "commitGroupChange[updateMetadata] returned success=false for {stable_convo_id}"
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
        let (stable_convo_id, group_id) = self.resolve_conversation_ids(convo_id).await?;
        let kp_refs = self.fetch_key_packages(&[member_did.to_string()]).await?;
        if kp_refs.is_empty() {
            return Err(CatmosError::Other(format!(
                "No key packages available for {member_did}"
            )));
        }
        let key_packages = kp_refs.into_iter()
            .map(|kp| catbird_mls::KeyPackageData { data: kp.key_package })
            .collect();

        let did = self.did().to_string();
        let plan = self.mls.with_commit_context(|ctx| {
            ctx.stage_commit(
                group_id.clone(),
                CommitKind::AddMembers {
                    member_dids: vec![member_did.to_string()],
                    key_packages,
                },
                did.as_bytes().to_vec(),
            )
        })?;

        let welcome_bytes = plan.welcome_bytes.clone().ok_or_else(|| {
            CatmosError::Other("stage_commit(AddMembers) did not return welcome bytes".to_string())
        })?;

        let req = build_commit_group_change(
            &stable_convo_id,
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
                    warn!(
                        "add_member: confirm_commit failed for {stable_convo_id}: {e} — discarding"
                    );
                    let _ = self
                        .mls
                        .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                    return Err(e);
                }
                info!(
                    "Added {member_did} to {stable_convo_id} (epoch hint: {:?})",
                    resp.new_epoch
                );
                Ok(())
            }
            Ok(_) => {
                let _ = self
                    .mls
                    .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                Err(CatmosError::Xrpc(format!(
                    "commitGroupChange[addMembers] returned success=false for {stable_convo_id}"
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
        if let Some(orchestrator) = self.orchestrator().await {
            return orchestrator
                .remove_accounts(convo_id, &[member_did.to_string()])
                .await
                .map_err(|error| CatmosError::Other(error.to_string()));
        }
        let (stable_convo_id, group_id) = self.resolve_conversation_ids(convo_id).await?;
        let did = self.did().to_string();
        let plan = self.mls.with_commit_context(|ctx| {
            ctx.stage_commit(
                group_id.clone(),
                CommitKind::RemoveMembers {
                    member_dids: vec![member_did.to_string()],
                },
                did.as_bytes().to_vec(),
            )
        })?;

        let req = build_commit_group_change(
            &stable_convo_id,
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
                    warn!("remove_member: confirm_commit failed for {stable_convo_id}: {e} — discarding");
                    let _ = self
                        .mls
                        .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                    return Err(e);
                }
                info!(
                    "Removed {member_did} from {stable_convo_id} (epoch hint: {:?})",
                    resp.new_epoch
                );
                Ok(())
            }
            Ok(_) => {
                let _ = self
                    .mls
                    .with_commit_context(|ctx| ctx.discard_pending(handle.clone()));
                Err(CatmosError::Xrpc(format!(
                    "commitGroupChange[removeMembers] returned success=false for {stable_convo_id}"
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
        let (stable_convo_id, _) = self.resolve_conversation_ids(convo_id).await?;
        if admin {
            let req = serde_json::json!({
                "convoId": stable_convo_id,
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

        let (stable_convo_id, group_id) = self.resolve_conversation_ids(convo_id).await?;
        validate_group_id_hex(&group_id)?;
        let group_id_bytes = hex::decode(&group_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let encrypt_result = self
            .mls
            .with_context(|ctx| ctx.encrypt_message(group_id_bytes.clone(), plaintext))?;

        let epoch = self.get_epoch(&group_id).unwrap_or(0);
        let msg_id = ulid::Ulid::new().to_string();
        let padded_size = encrypt_result.ciphertext.len() as i64;
        let confirmation_tag = self.get_confirmation_tag_b64(&group_id_bytes);

        let req = serde_json::json!({
            "convoId": stable_convo_id,
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
        let (stable_convo_id, _) = self.resolve_conversation_ids(convo_id).await?;
        let actor_device_id = self.actor_device_id().await?;
        let resp: serde_json::Value = self
            .xrpc_query(
                "blue.catbird.chat.getConversationState",
                &[
                    ("actorDeviceId", &actor_device_id),
                    ("convoId", &stable_convo_id),
                    ("conversationId", &stable_convo_id),
                ],
            )
            .await?;
        Ok(resp)
    }

    pub async fn upload_blob(&self, convo_id: &str, file_path: &str) -> Result<String> {
        let (stable_convo_id, _) = self.resolve_conversation_ids(convo_id).await?;
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
            ("convoId", stable_convo_id.as_str()),
            ("conversationId", stable_convo_id.as_str()),
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
            self.refresh_bearer().await?;
            let fresh_bearer = self.get_service_token(nsid).await?;
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
            self.refresh_bearer().await?;
            let fresh_bearer = self.get_service_token(nsid).await?;
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

        let deleted = resp
            .get("deleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let kp_deleted = resp
            .get("keyPackagesDeleted")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let convos_left = resp
            .get("conversationsLeft")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

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
        build_request_parts(&self.auth, &self.config, nsid, bearer)
    }
}

fn build_request_parts(auth: &AuthMethod, config: &Config, nsid: &str, bearer: &str) -> Result<(String, HeaderMap)> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {bearer}"))
            .map_err(|e| CatmosError::AuthFailed(e.to_string()))?,
    );

    let url = match auth {
        AuthMethod::OAuth { nest_url, .. } => format!("{nest_url}/xrpc/{nsid}"),
        AuthMethod::AppPassword { pds_url, .. } => {
            if nsid.starts_with("blue.catbird.chat.")
                || nsid.starts_with("blue.catbird.mlsChat.")
            {
                let proxy_val = crate::mls::atproto_proxy_header_value();
                if let Ok(hv) = HeaderValue::from_str(&proxy_val) {
                    headers.insert(
                        reqwest::header::HeaderName::from_static("atproto-proxy"),
                        hv,
                    );
                }
                let chat_base = std::env::var("ATPROTO_CHAT_HOST")
                    .unwrap_or_else(|_| config.server.mls_url.clone());
                format!("{}/xrpc/{nsid}", chat_base.trim_end_matches('/'))
            } else {
                format!("{}/xrpc/{nsid}", pds_url.trim_end_matches('/'))
            }
        }
    };

    Ok((url, headers))
}


/// Resolve an input against a fetched conversation list without performing
/// any I/O. The first value is stable for API/storage/UI routing; the second
/// is the current hex-encoded MLS group ID.
pub(crate) fn conversation_ids_for_input(
    input: &str,
    conversations: &[Conversation],
) -> Result<(String, String)> {
    if let Some(ids) = conversation_ids_for_input_exact(input, conversations)? {
        return Ok(ids);
    }
    if can_use_legacy_group_fallback(input) {
        return Ok((input.to_string(), input.to_string()));
    }
    Err(CatmosError::ConvoNotFound(format!(
        "conversation {input} has no stable/current group mapping"
    )))
}

fn conversation_ids_for_input_exact(
    input: &str,
    conversations: &[Conversation],
) -> Result<Option<(String, String)>> {
    let stable_matches: Vec<&Conversation> = conversations
        .iter()
        .filter(|conversation| conversation.conversation_id == input)
        .collect();
    if !stable_matches.is_empty() {
        let canonical_stable: Vec<&Conversation> = stable_matches
            .iter()
            .copied()
            .filter(|conversation| conversation.group_id != input)
            .collect();
        if !canonical_stable.is_empty() || !is_valid_legacy_group_id(input) {
            return unique_conversation_match(
                canonical_stable.into_iter().chain(
                    stable_matches
                        .into_iter()
                        .filter(|conversation| conversation.group_id == input),
                ),
                input,
                "stable conversation ID",
            );
        }
    }

    unique_group_match(
        conversations.iter().filter(|conversation| {
            conversation.group_id == input && is_valid_legacy_group_id(&conversation.group_id)
        }),
        input,
        "legacy MLS group ID",
    )
}

fn conversation_ids_for_sources(
    input: &str,
    primary: &[Conversation],
    secondary: &[Conversation],
) -> Result<Option<(String, String)>> {
    // Stable IDs have global precedence, even when a legacy group row in the
    // other source happens to use the same string. The durable projection is
    // authoritative over a stale in-memory cache when both contain the same
    // stable ID during reset completion.
    let primary_stable_matches: Vec<&Conversation> = primary
        .iter()
        .filter(|conversation| conversation.conversation_id == input)
        .collect();
    let stable_matches: Vec<&Conversation> = if primary_stable_matches.is_empty() {
        secondary
            .iter()
            .filter(|conversation| conversation.conversation_id == input)
            .collect()
    } else {
        primary_stable_matches
    };
    if !stable_matches.is_empty() {
        let canonical_stable: Vec<&Conversation> = stable_matches
            .iter()
            .copied()
            .filter(|conversation| conversation.group_id != input)
            .collect();
        if !canonical_stable.is_empty() || !is_valid_legacy_group_id(input) {
            return unique_conversation_match(
                canonical_stable.into_iter().chain(
                    stable_matches
                        .into_iter()
                        .filter(|conversation| conversation.group_id == input),
                ),
                input,
                "stable conversation ID",
            );
        }
    }

    let mut group_matches = Vec::new();
    group_matches.extend(primary.iter().filter(|conversation| {
        conversation.group_id == input && is_valid_legacy_group_id(&conversation.group_id)
    }));
    group_matches.extend(secondary.iter().filter(|conversation| {
        conversation.group_id == input && is_valid_legacy_group_id(&conversation.group_id)
    }));
    unique_group_match(group_matches.into_iter(), input, "legacy MLS group ID")
}

fn exact_stable_match_for_sources(
    input: &str,
    primary: &[Conversation],
    secondary: &[Conversation],
) -> Result<Option<(String, String)>> {
    let primary_stable_matches: Vec<&Conversation> = primary
        .iter()
        .filter(|conversation| conversation.conversation_id == input)
        .collect();
    let stable_matches: Vec<&Conversation> = if primary_stable_matches.is_empty() {
        secondary
            .iter()
            .filter(|conversation| conversation.conversation_id == input)
            .collect()
    } else {
        primary_stable_matches
    };
    if !stable_matches.is_empty() {
        let canonical_stable: Vec<&Conversation> = stable_matches
            .iter()
            .copied()
            .filter(|conversation| conversation.group_id != input)
            .collect();
        if !canonical_stable.is_empty() || !is_valid_legacy_group_id(input) {
            return unique_conversation_match(
                canonical_stable.into_iter().chain(
                    stable_matches
                        .into_iter()
                        .filter(|conversation| conversation.group_id == input),
                ),
                input,
                "stable conversation ID",
            );
        }
    }
    Ok(None)
}

fn conversation_ids_for_alias(
    alias: &str,
    primary: &[Conversation],
    secondary: &[Conversation],
) -> Result<Option<(String, String)>> {
    let matches = primary
        .iter()
        .chain(secondary.iter())
        .filter(|conversation| conversation.alias.as_deref() == Some(alias));
    unique_conversation_match(matches, alias, "conversation alias")
}

fn unique_conversation_match<'a, I>(
    matches: I,
    input: &str,
    kind: &str,
) -> Result<Option<(String, String)>>
where
    I: IntoIterator<Item = &'a Conversation>,
{
    let unique: HashSet<(String, String)> = matches
        .into_iter()
        .map(|conversation| {
            (
                conversation.conversation_id.clone(),
                conversation.group_id.clone(),
            )
        })
        .collect();
    for (_, group_id) in &unique {
        validate_group_id_hex(group_id)?;
    }
    if unique.len() > 1 {
        return Err(CatmosError::Other(format!(
            "ambiguous {kind} mapping for {input}"
        )));
    }
    Ok(unique.into_iter().next())
}

fn unique_group_match<'a, I>(
    matches: I,
    input: &str,
    kind: &str,
) -> Result<Option<(String, String)>>
where
    I: IntoIterator<Item = &'a Conversation>,
{
    unique_conversation_match(matches, input, kind)
}

fn is_valid_legacy_group_id(input: &str) -> bool {
    validate_group_id_hex(input).is_ok()
}

/// Validate an MLS group identifier at the boundary between API/storage
/// metadata and cryptographic operations. A stable conversation identifier is
/// never a valid substitute for a missing or malformed group ID.
pub(crate) fn validate_group_id_hex(input: &str) -> Result<()> {
    if input.is_empty() || input.trim() != input {
        return Err(CatmosError::Other(
            "MLS group ID must be non-empty exact hex".to_string(),
        ));
    }
    let bytes =
        hex::decode(input).map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(CatmosError::Other(
            "MLS group ID must contain between 1 and 255 bytes".to_string(),
        ));
    }
    Ok(())
}

fn can_use_legacy_group_fallback(input: &str) -> bool {
    is_valid_legacy_group_id(input) && !is_canonical_stable_uuid(input)
}

fn is_canonical_stable_uuid(input: &str) -> bool {
    input.contains('-') && uuid::Uuid::parse_str(input).is_ok()
}

/// Select the stable projection created for a newly-created MLS group.
/// Refreshes must produce exactly one candidate; silently taking the first
/// match can route a new group to the wrong stable conversation.
pub(crate) fn select_created_conversation(
    candidates: Vec<Conversation>,
    group_id_hex: &str,
) -> Result<Conversation> {
    validate_group_id_hex(group_id_hex)?;
    let matches: Vec<Conversation> = candidates
        .into_iter()
        .filter(|candidate| {
            candidate.group_id == group_id_hex
                && !candidate.conversation_id.trim().is_empty()
                && candidate.conversation_id != candidate.group_id
        })
        .collect();
    match matches.len() {
        1 => Ok(matches
            .into_iter()
            .next()
            .expect("one candidate was counted")),
        0 => Err(CatmosError::ConvoNotFound(format!(
            "created group {group_id_hex} has no unique stable conversation mapping"
        ))),
        count => Err(CatmosError::Other(format!(
            "created group {group_id_hex} has {count} stable conversation mappings"
        ))),
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
    use chrono::Utc;

    const KNOWN_BYTES: &[u8] = &[0, 1, 2, 3, 4, 0xde, 0xad, 0xbe, 0xef];
    const SINGLE_ENCODED: &str = "AAECAwTerb7v";
    const DOUBLE_ENCODED: &str = "QUFFQ0F3VGVyYjd2";

    #[test]
    fn renewed_blob_authorization_keeps_the_original_auth_method_destination() {
        let mut config = Config::default();
        config.server.mls_url = "https://chat.catbird.blue".into();
        let direct_chat = std::env::var("ATPROTO_CHAT_HOST").unwrap_or_else(|_| config.server.mls_url.clone());
        for (auth, expected) in [
            (AuthMethod::AppPassword { handle: "actor.catbird.blue".into(), did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(), pds_url: "https://pds.catbird.blue".into() }, direct_chat),
            (AuthMethod::OAuth { session_cookie: "test-session".into(), did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(), nest_url: "https://nest.catbird.blue".into() }, "https://nest.catbird.blue".into()),
        ] {
            let initial = build_request_parts(&auth, &config, "blue.catbird.chat.getBlob", "old-scoped-token").unwrap();
            let renewed = build_request_parts(&auth, &config, "blue.catbird.chat.getBlob", "renewed-scoped-token").unwrap();
            assert_eq!(initial.0, renewed.0);
            assert_eq!(renewed.0, format!("{}/xrpc/blue.catbird.chat.getBlob", expected.trim_end_matches('/')));
            assert_eq!(renewed.1[AUTHORIZATION], "Bearer renewed-scoped-token");
            assert!(!renewed.0.starts_with("https://pds.catbird.blue/"));
        }
    }

    #[tokio::test]
    async fn remove_member_preserves_canonical_failure_without_legacy_fallback() {
        use crate::orchestrator_api::CliApiClient;
        use crate::orchestrator_credentials::KeyringCredentialStore;
        use crate::orchestrator_storage::SqliteStorage;
        use catbird_mls::orchestrator::{MLSOrchestrator, OrchestratorConfig};

        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let temporary = tempfile::tempdir().unwrap();
        let db = Arc::new(
            Database::open_unencrypted(&temporary.path().join("chat.db"))
                .await
                .unwrap(),
        );
        let mls = Arc::new(
            MlsManager::new(&temporary.path().join("mls"), "did:plc:adaptertest").unwrap(),
        );
        let service = Arc::new(ChatService::new(
            AuthMethod::OAuth {
                session_cookie: "test-only".into(),
                did: "did:plc:adaptertest".into(),
                nest_url: "http://127.0.0.1:1".into(),
            },
            None,
            mls.clone(),
            db,
            Config::default(),
            Arc::new(RwLock::new(AliasStore::with_path(
                temporary.path().join("aliases.json"),
            ))),
        ));
        let storage = Arc::new(SqliteStorage::new(":memory:", "test-only").unwrap());
        let orchestrator = Arc::new(MLSOrchestrator::new(
            mls.context().clone(),
            storage,
            Arc::new(CliApiClient::new(service.clone())),
            Arc::new(KeyringCredentialStore::new()),
            OrchestratorConfig::default(),
        ));
        // An uninitialized canonical runtime rejects authentication before
        // resolving a group or staging a device-leaf removal. Its failure
        // must remain visible instead of falling through to the old path.
        service.set_orchestrator(orchestrator).await;
        let error = service
            .remove_member("not-a-local-group", "did:plc:target")
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            CatmosError::Other(
                catbird_mls::orchestrator::error::OrchestratorError::NotAuthenticated.to_string(),
            )
            .to_string(),
        );
        assert!(service.own_commits.lock().await.is_empty());
    }

    #[tokio::test]
    async fn canonical_history_survives_empty_repeat_fetch_and_preserves_fetch_errors() {
        use crate::orchestrator_api::CliApiClient;
        use crate::orchestrator_credentials::KeyringCredentialStore;
        use crate::orchestrator_storage::SqliteStorage;
        use catbird_mls::orchestrator::storage::MLSStorageBackend;
        use catbird_mls::orchestrator::{MLSOrchestrator, OrchestratorConfig};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = calls.clone();
        let app = axum::Router::new().route(
            "/xrpc/blue.catbird.chat.getEntries",
            axum::routing::get(move || {
                let calls = handler_calls.clone();
                async move {
                    if calls.fetch_add(1, Ordering::Relaxed) < 2 {
                        (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
                            "entries": [], "hasMore": false,
                        })))
                    } else {
                        (axum::http::StatusCode::SERVICE_UNAVAILABLE,
                         axum::Json(serde_json::json!({"error": "temporarily unavailable"})))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let temporary = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_unencrypted(&temporary.path().join("chat.db")).await.unwrap());
        db.store_session_value("mls_device_id", "70707070-7070-4070-b070-707070707070").await.unwrap();
        let mls = Arc::new(MlsManager::new(&temporary.path().join("mls"), "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa").unwrap());
        mls.context().set_content_root_key(vec![0x74; 32]).unwrap();
        let service = Arc::new(ChatService::new(
            AuthMethod::OAuth { session_cookie: "test-only".into(), did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(), nest_url: endpoint },
            None, mls.clone(), db, Config::default(),
            Arc::new(RwLock::new(AliasStore::with_path(temporary.path().join("aliases.json")))),
        ));
        let storage = Arc::new(SqliteStorage::new(temporary.path().join("orchestrator.db").to_str().unwrap(), "test-only").unwrap());
        storage.set_mls_context(mls.context().clone());
        storage.store_message(&catbird_mls::orchestrator::types::Message {
            id: "retained-message".into(), conversation_id: "history-conversation".into(),
            sender_did: "did:plc:peer".into(), text: "retained authenticated history".into(),
            timestamp: Utc::now(), epoch: 1, sequence_number: 0, is_own: false,
            delivery_status: None, payload_json: None,
        }).await.unwrap();
        let credentials = Arc::new(KeyringCredentialStore::new());
        credentials.store_server_device_id(service.did(), "70707070-7070-4070-b070-707070707070").await.unwrap();
        let orchestrator = Arc::new(MLSOrchestrator::new(
            mls.context().clone(), storage.clone(),
            Arc::new(CliApiClient::new(service.clone())),
            credentials, OrchestratorConfig::default(),
        ));
        orchestrator.initialize(service.did()).await.unwrap();
        service.set_orchestrator(orchestrator.clone()).await;
        for _ in 0..2 {
            let history = service.load_canonical_message_history("history-conversation", 50).await.unwrap();
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].text, "retained authenticated history");
        }
        let error = service.load_canonical_message_history("history-conversation", 50).await.unwrap_err();
        assert!(error.to_string().contains("503"), "{error}");
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        use catbird_mls::orchestrator::types::{ConversationState, SyncCursor};
        storage.ensure_conversation_exists(service.did(), "history-conversation", "000102030405060708090a0b0c0d0e0f").await.unwrap();
        let cursor = SyncCursor { conversations_cursor: Some("inventory-cursor".into()), messages_cursor: Some("message-cursor".into()) };
        storage.set_sync_cursor(service.did(), &cursor).await.unwrap();
        for (state, expected_send_error) in [
            (ConversationState::DeviceRemoved, "conversation_device_removed"),
            (ConversationState::Closed, "conversation_closed"),
        ] {
            storage.set_conversation_state("history-conversation", state.clone()).await.unwrap();
            orchestrator.initialize(service.did()).await.unwrap();
            for _ in 0..2 {
                let history = service.load_canonical_message_history("history-conversation", 50).await.unwrap();
                assert_eq!(history.len(), 1);
                assert_eq!(history[0].text, "retained authenticated history");
            }
            let send_error = orchestrator.send_message("history-conversation", "must remain blocked").await.unwrap_err();
            assert!(send_error.to_string().contains(expected_send_error), "{send_error}");
            assert_eq!(storage.get_conversation_state("history-conversation").await.unwrap(), Some(state));
            assert_eq!(calls.load(Ordering::Relaxed), 3, "terminal reads and sends must not reach getEntries");
            let unchanged = storage.get_sync_cursor(service.did()).await.unwrap();
            assert_eq!(unchanged.conversations_cursor, cursor.conversations_cursor);
            assert_eq!(unchanged.messages_cursor, cursor.messages_cursor);
        }
        server.abort();
    }

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

    #[test]
    fn conversation_id_resolution_preserves_legacy_group_input() {
        let conversation_id = "550e8400-e29b-41d4-a716-446655440000";
        let group_id = "000102030405060708090a0b0c0d0e0f";
        let conversation = Conversation {
            conversation_id: conversation_id.to_string(),
            group_id: group_id.to_string(),
            name: None,
            description: None,
            creator: Some("did:plc:test".to_string()),
            epoch: 0,
            cipher_suite: MLS_CIPHER_SUITE.to_string(),
            members: vec![],
            created_at: Some(Utc::now()),
            last_message_at: None,
            unread_count: 0,
            alias: None,
            metadata_version: None,
            metadata_blob_locator: None,
            avatar_blob_locator: None,
            avatar_bytes: None,
            avatar_content_type: None,
        };

        assert_eq!(
            conversation_ids_for_input(conversation_id, &[conversation.clone()])
                .expect("stable conversation mapping"),
            (conversation_id.to_string(), group_id.to_string())
        );
        assert_eq!(
            conversation_ids_for_input(group_id, &[conversation]).expect("legacy group mapping"),
            (conversation_id.to_string(), group_id.to_string())
        );
        assert_eq!(
            conversation_ids_for_input(group_id, &[]).expect("validated legacy group fallback"),
            (group_id.to_string(), group_id.to_string())
        );
    }

    #[test]
    fn conversation_id_resolution_rejects_missing_stable_id() {
        let stable_id = "550e8400-e29b-41d4-a716-446655440000";

        assert!(
            conversation_ids_for_input(stable_id, &[]).is_err(),
            "an unmatched stable ID must not be treated as an MLS group ID"
        );
    }

    #[test]
    fn conversation_id_resolution_prefers_stable_and_rejects_ambiguous_group() {
        let stable_id = "stable-conversation";
        let group_id = "000102030405060708090a0b0c0d0e0f";
        let collision = Conversation {
            conversation_id: "other-conversation".to_string(),
            group_id: stable_id.to_string(),
            name: None,
            description: None,
            creator: Some("did:plc:test".to_string()),
            epoch: 0,
            cipher_suite: MLS_CIPHER_SUITE.to_string(),
            members: vec![],
            created_at: Some(Utc::now()),
            last_message_at: None,
            unread_count: 0,
            alias: None,
            metadata_version: None,
            metadata_blob_locator: None,
            avatar_blob_locator: None,
            avatar_bytes: None,
            avatar_content_type: None,
        };
        let stable = Conversation {
            conversation_id: stable_id.to_string(),
            group_id: group_id.to_string(),
            ..collision.clone()
        };
        let ambiguous_a = Conversation {
            conversation_id: "ambiguous-a".to_string(),
            group_id: "00112233445566778899aabbccddeeff".to_string(),
            ..collision.clone()
        };
        let ambiguous_b = Conversation {
            conversation_id: "ambiguous-b".to_string(),
            group_id: "00112233445566778899aabbccddeeff".to_string(),
            ..collision.clone()
        };

        assert_eq!(
            conversation_ids_for_input(stable_id, &[collision.clone(), stable.clone()])
                .expect("exact stable ID mapping"),
            (stable_id.to_string(), group_id.to_string()),
            "exact stable ID must win over a legacy group-ID collision"
        );
        assert!(
            conversation_ids_for_input(
                "00112233445566778899aabbccddeeff",
                &[ambiguous_a, ambiguous_b]
            )
            .is_err(),
            "ambiguous legacy group IDs must fail closed"
        );
    }

    #[test]
    fn conversation_id_resolution_rejects_empty_or_malformed_mapped_group() {
        let stable_id = "550e8400-e29b-41d4-a716-446655440000";
        for group_id in ["", "not-hex", "0011zz"] {
            let conversation = Conversation {
                conversation_id: stable_id.to_string(),
                group_id: group_id.to_string(),
                name: None,
                description: None,
                creator: Some("did:plc:test".to_string()),
                epoch: 0,
                cipher_suite: MLS_CIPHER_SUITE.to_string(),
                members: vec![],
                created_at: Some(Utc::now()),
                last_message_at: None,
                unread_count: 0,
                alias: None,
                metadata_version: None,
                metadata_blob_locator: None,
                avatar_blob_locator: None,
                avatar_bytes: None,
                avatar_content_type: None,
            };

            assert!(
                conversation_ids_for_input(stable_id, &[conversation]).is_err(),
                "mapped group ID {group_id:?} must be rejected rather than used for MLS"
            );
        }
    }

    #[test]
    fn create_refresh_requires_exactly_one_stable_candidate() {
        let group_id = "000102030405060708090a0b0c0d0e0f";
        let candidate = |stable_id: &str| Conversation {
            conversation_id: stable_id.to_string(),
            group_id: group_id.to_string(),
            name: None,
            description: None,
            creator: Some("did:plc:test".to_string()),
            epoch: 0,
            cipher_suite: MLS_CIPHER_SUITE.to_string(),
            members: vec![],
            created_at: Some(Utc::now()),
            last_message_at: None,
            unread_count: 0,
            alias: None,
            metadata_version: None,
            metadata_blob_locator: None,
            avatar_blob_locator: None,
            avatar_bytes: None,
            avatar_content_type: None,
        };

        assert!(select_created_conversation(Vec::new(), group_id).is_err());
        assert!(
            select_created_conversation(vec![candidate("a"), candidate("b")], group_id).is_err()
        );
        assert_eq!(
            select_created_conversation(vec![candidate("stable")], group_id)
                .expect("one candidate")
                .conversation_id,
            "stable"
        );
    }
}
