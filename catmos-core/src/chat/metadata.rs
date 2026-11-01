//! Encrypted group metadata bootstrap + reset republish.
//!
//! Post-MLS-metadata-cutover, the server is cryptographically blind to
//! group title / description / avatar. The authoritative source on every
//! client is a local decrypted blob:
//!
//! 1. Server emits a `MetadataReference` (component `0x8001`) inside the
//!    MLS GroupContext's AppDataDictionary as part of every metadata-
//!    updating commit. The reference records `metadata_version`,
//!    `blob_locator`, and `ciphertext_hash` — all integrity-bound.
//! 2. The encrypted blob lives on the DS at
//!    `getGroupMetadataBlob(blobLocator | convoId+resetGeneration[+kind])`
//!    and is opaque to the server.
//! 3. AEAD key is derived from the MLS exporter at the post-commit epoch:
//!    `label = "blue.catbird/group-metadata/v1"`,
//!    `AAD = group_id || epoch || metadata_version` (`|| b"avatar"` for
//!    avatar blobs).
//!
//! After every Welcome / external-commit join / metadata-update commit
//! merge, the catmos-cli client must:
//! - call `MLSContext::get_current_metadata(group_id)` to derive the key,
//!   epoch, and read the `MetadataReference`,
//! - GET the blob via `getGroupMetadataBlob`,
//! - decrypt with `catbird_mls::metadata::decrypt_metadata_blob`,
//! - persist title / description / avatar bytes to local SQLite via
//!   `Database::update_decrypted_metadata`.
//!
//! Shape mirrors the iOS canonical implementation
//! (`MLSConversationManager+Metadata.swift::bootstrapMetadataAfterJoin`).
//!
//! `republish_metadata_after_reset` is the post-reset sibling: after a
//! group reset advances the conversation onto a fresh MLS group, the
//! resetting client re-encrypts current metadata against the new group's
//! exporter and uploads under `(convoId, resetGeneration, kind)` so
//! joining members can pick it up.

use catbird_mls::metadata::{self as mls_metadata, GroupMetadataV1, MetadataReference};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::StatusCode;
use tracing::{debug, info, warn};

use super::service::ChatService;
use crate::auth::AuthMethod;
use crate::error::{CatmosError, Result};
use crate::types::Conversation;

/// Decrypted metadata payload returned by `bootstrap_group_metadata`. Pure
/// data — the function persists it to the DB before returning so callers
/// rarely need to inspect the value, but it's exposed for tests and for
/// future e2e harness assertions.
#[derive(Debug, Clone)]
pub struct DecryptedMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub metadata_version: i64,
    pub metadata_blob_locator: String,
    pub avatar_blob_locator: Option<String>,
    pub avatar_bytes: Option<Vec<u8>>,
    pub avatar_content_type: Option<String>,
}

/// Result of `republish_metadata_after_reset` — the locator + version the
/// caller should declare on `bootstrapResetGroup` so joining members can
/// look up the fresh blob.
#[derive(Debug, Clone)]
pub struct RepublishedMetadata {
    pub metadata_blob_locator: String,
    pub metadata_version: i64,
}

const KIND_METADATA: &str = "metadata";
const KIND_AVATAR: &str = "avatar";

const MAX_BLOB_BYTES: usize = 1024 * 1024; // 1MB — matches DS BlobTooLarge limit.

impl ChatService {
    /// Bootstrap encrypted metadata for a conversation that has already
    /// joined the MLS group locally (post-Welcome / post-external-commit /
    /// post-metadata-update commit merge). On success, decrypted title /
    /// description / avatar are persisted via
    /// `Database::update_decrypted_metadata`.
    ///
    /// Returns `Ok(None)` when the group has no metadata reference yet
    /// (e.g. brand-new group whose creator hasn't published metadata).
    /// Returns `Ok(None)` when the server has no blob at the referenced
    /// locator (BlobNotFound) — treated as a transient absence the caller
    /// can retry on the next sync. All other errors propagate.
    pub async fn bootstrap_group_metadata(
        &self,
        convo_id: &str,
        group_id_hex: &str,
    ) -> Result<Option<DecryptedMetadata>> {
        let group_id_bytes = hex::decode(group_id_hex)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let info = match self
            .mls
            .with_context(|ctx| ctx.get_current_metadata(group_id_bytes.clone()))?
        {
            Some(i) => i,
            None => {
                debug!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    "bootstrap_group_metadata: no current metadata for group (group missing locally?)"
                );
                return Ok(None);
            }
        };

        // No reference => no published metadata yet. This is normal for a
        // freshly-created group whose creator hasn't called
        // updateGroupMetadata. Persist nothing; caller can retry later.
        let reference_json = match info.metadata_reference_json {
            Some(b) => b,
            None => {
                debug!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    epoch = info.epoch,
                    "bootstrap_group_metadata: AppDataDictionary[0x8001] absent — no metadata to fetch"
                );
                return Ok(None);
            }
        };

        let reference: MetadataReference =
            serde_json::from_slice(&reference_json).map_err(|e| {
                CatmosError::Other(format!(
                    "bootstrap_group_metadata: invalid MetadataReference JSON: {e}"
                ))
            })?;

        // Skip if we already hold this version. Saves a round-trip on the
        // common case of `fetch_conversations` repeatedly calling bootstrap.
        if let Some(existing) = self.cached_metadata_version(convo_id).await {
            if existing >= reference.metadata_version as i64 {
                debug!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    cached = existing,
                    fetched = reference.metadata_version,
                    "bootstrap_group_metadata: already at-or-ahead of fetched version, skipping"
                );
                return Ok(None);
            }
        }

        let key: [u8; 32] = info.metadata_key.as_slice().try_into().map_err(|_| {
            CatmosError::Other(
                "bootstrap_group_metadata: metadata_key was not 32 bytes".to_string(),
            )
        })?;

        let metadata_ct = match self
            .get_group_metadata_blob(
                Some(&reference.blob_locator),
                None,
                Some(group_id_hex),
                None,
                None,
                Some(KIND_METADATA),
            )
            .await
        {
            Ok(Some(b)) => b,
            Ok(None) => {
                debug!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    locator = %reference.blob_locator,
                    "bootstrap_group_metadata: server returned BlobNotFound for metadata locator (transient)"
                );
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        let payload = mls_metadata::decrypt_metadata_blob(
            &key,
            &group_id_bytes,
            info.epoch,
            reference.metadata_version,
            &metadata_ct,
        )
        .map_err(|e| {
            CatmosError::Other(format!(
                "bootstrap_group_metadata: decrypt_metadata_blob failed: {e}"
            ))
        })?;

        // Avatar fetch is best-effort: even if the metadata says there's an
        // avatar locator, we tolerate missing/decrypt-fail because the title
        // is the load-bearing piece of UX.
        let (avatar_bytes, avatar_locator, avatar_ct_type) = match &payload.avatar_blob_locator {
            Some(loc) => match self
                .get_group_metadata_blob(
                    Some(loc),
                    None,
                    Some(group_id_hex),
                    None,
                    None,
                    Some(KIND_AVATAR),
                )
                .await
            {
                Ok(Some(blob)) => match mls_metadata::decrypt_avatar_blob(
                    &key,
                    &group_id_bytes,
                    info.epoch,
                    reference.metadata_version,
                    &blob,
                ) {
                    Ok(bytes) => (
                        Some(bytes),
                        Some(loc.clone()),
                        payload.avatar_content_type.clone(),
                    ),
                    Err(e) => {
                        warn!(
                            convo = %&convo_id[..12.min(convo_id.len())],
                            locator = %loc,
                            error = %e,
                            "bootstrap_group_metadata: decrypt_avatar_blob failed (non-fatal)"
                        );
                        (None, Some(loc.clone()), payload.avatar_content_type.clone())
                    }
                },
                Ok(None) => (None, Some(loc.clone()), payload.avatar_content_type.clone()),
                Err(e) => {
                    warn!(
                        convo = %&convo_id[..12.min(convo_id.len())],
                        locator = %loc,
                        error = %e,
                        "bootstrap_group_metadata: avatar fetch failed (non-fatal)"
                    );
                    (None, Some(loc.clone()), payload.avatar_content_type.clone())
                }
            },
            None => (None, None, None),
        };

        let title = if payload.title.is_empty() {
            None
        } else {
            Some(payload.title.clone())
        };
        let description = if payload.description.is_empty() {
            None
        } else {
            Some(payload.description.clone())
        };

        if let Err(e) = self
            .db
            .update_decrypted_metadata(
                convo_id,
                title.as_deref(),
                description.as_deref(),
                Some(reference.metadata_version as i64),
                Some(&reference.blob_locator),
                avatar_locator.as_deref(),
                avatar_bytes.as_deref(),
                avatar_ct_type.as_deref(),
            )
            .await
        {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "bootstrap_group_metadata: update_decrypted_metadata failed"
            );
            return Err(e);
        }

        // Write through to the in-memory cache so the next render sees the
        // change without waiting for the next `fetch_conversations` cycle.
        self.merge_decrypted_metadata_into_cache(
            convo_id,
            title.clone(),
            description.clone(),
            Some(reference.metadata_version as i64),
            Some(reference.blob_locator.clone()),
            avatar_locator.clone(),
            avatar_bytes.clone(),
            avatar_ct_type.clone(),
        )
        .await;

        info!(
            convo = %&convo_id[..12.min(convo_id.len())],
            version = reference.metadata_version,
            has_avatar = avatar_bytes.is_some(),
            "bootstrap_group_metadata: persisted decrypted metadata"
        );

        Ok(Some(DecryptedMetadata {
            title,
            description,
            metadata_version: reference.metadata_version as i64,
            metadata_blob_locator: reference.blob_locator,
            avatar_blob_locator: avatar_locator,
            avatar_bytes,
            avatar_content_type: avatar_ct_type,
        }))
    }

    /// Re-encrypt and re-publish the conversation's existing metadata
    /// against the new group's epoch exporter after a reset. Best-effort:
    /// returns `Ok((None, None))` when there's nothing to republish (the
    /// local conversation has no decrypted metadata, the new group has no
    /// local MLS state, etc.) — the caller should treat that as
    /// "bootstrap without metadata declaration" rather than a hard error.
    ///
    /// On success returns the metadata locator + version so the caller can
    /// declare them on `bootstrapResetGroup`.
    pub async fn republish_metadata_after_reset(
        &self,
        convo_id: &str,
        new_group_id_bytes: &[u8],
        reset_generation: i64,
    ) -> Result<(Option<String>, Option<i64>)> {
        // Read pre-reset metadata from local cache (or DB fallback). After
        // the reset, this is the only authoritative source — the server's
        // pre-reset blob lives in the old group's epoch and key, useless to
        // joiners of the new group.
        let convo = match self.find_local_conversation(convo_id).await {
            Some(c) => c,
            None => {
                debug!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    "republish_metadata_after_reset: conversation not in local cache; nothing to republish"
                );
                return Ok((None, None));
            }
        };

        let title = convo.name.clone().unwrap_or_default();
        let description = convo.description.clone().unwrap_or_default();
        let avatar_bytes = convo.avatar_bytes.clone();
        let avatar_content_type = convo.avatar_content_type.clone();

        if title.is_empty() && description.is_empty() && avatar_bytes.is_none() {
            debug!(
                convo = %&convo_id[..12.min(convo_id.len())],
                "republish_metadata_after_reset: no decrypted metadata locally; skipping"
            );
            return Ok((None, None));
        }

        let group_id_hex = hex::encode(new_group_id_bytes);

        // Derive the metadata key against the NEW group at its current
        // epoch. The new group must already exist locally — caller is
        // responsible for `create_group_with_id` first (the bootstrap path
        // in `recovery_ops.rs::try_first_responder_bootstrap` does this).
        let info = match self
            .mls
            .with_context(|ctx| ctx.get_current_metadata(new_group_id_bytes.to_vec()))?
        {
            Some(i) => i,
            None => {
                warn!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    new_group = %group_id_hex,
                    "republish_metadata_after_reset: get_current_metadata returned None — new group not joined locally?"
                );
                return Ok((None, None));
            }
        };
        let key: [u8; 32] = info.metadata_key.as_slice().try_into().map_err(|_| {
            CatmosError::Other(
                "republish_metadata_after_reset: metadata_key was not 32 bytes".to_string(),
            )
        })?;

        // Bump version monotonically. Reset_generation already namespaces
        // (convoId, resetGeneration, version) on the server, so starting
        // back at 1 for a fresh generation is acceptable. We continue from
        // `convo.metadata_version + 1` to keep monotonicity intact for any
        // joiner who saw the pre-reset blob.
        let next_version = convo.metadata_version.unwrap_or(0).saturating_add(1).max(1);

        let avatar_locator = if avatar_bytes.is_some() {
            Some(uuid::Uuid::new_v4().to_string().to_lowercase())
        } else {
            None
        };

        let metadata_payload = GroupMetadataV1 {
            version: 1,
            title: title.clone(),
            description: description.clone(),
            avatar_blob_locator: avatar_locator.clone(),
            avatar_content_type: avatar_content_type.clone(),
            space_avatar: None,
        };

        let metadata_ct = mls_metadata::encrypt_metadata_blob(
            &key,
            new_group_id_bytes,
            info.epoch,
            next_version as u64,
            &metadata_payload,
        )
        .map_err(|e| {
            CatmosError::Other(format!(
                "republish_metadata_after_reset: encrypt_metadata_blob failed: {e}"
            ))
        })?;

        if metadata_ct.len() > MAX_BLOB_BYTES {
            return Err(CatmosError::Other(format!(
                "republish_metadata_after_reset: encrypted metadata blob too large ({} bytes)",
                metadata_ct.len()
            )));
        }

        let metadata_locator = uuid::Uuid::new_v4().to_string().to_lowercase();

        self.put_group_metadata_blob(
            &metadata_locator,
            Some(convo_id),
            &group_id_hex,
            Some(KIND_METADATA),
            Some(next_version),
            Some(reset_generation),
            metadata_ct,
        )
        .await?;

        if let (Some(bytes), Some(locator)) = (&avatar_bytes, &avatar_locator) {
            let avatar_ct = mls_metadata::encrypt_avatar_blob(
                &key,
                new_group_id_bytes,
                info.epoch,
                next_version as u64,
                bytes,
            )
            .map_err(|e| {
                CatmosError::Other(format!(
                    "republish_metadata_after_reset: encrypt_avatar_blob failed: {e}"
                ))
            })?;

            if avatar_ct.len() > MAX_BLOB_BYTES {
                warn!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    bytes = avatar_ct.len(),
                    "republish_metadata_after_reset: avatar exceeds 1MB; skipping upload"
                );
            } else if let Err(e) = self
                .put_group_metadata_blob(
                    locator,
                    Some(convo_id),
                    &group_id_hex,
                    Some(KIND_AVATAR),
                    Some(next_version),
                    Some(reset_generation),
                    avatar_ct,
                )
                .await
            {
                warn!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    locator = %locator,
                    error = %e,
                    "republish_metadata_after_reset: avatar upload failed (non-fatal)"
                );
            }
        }

        if let Err(e) = self
            .db
            .update_decrypted_metadata(
                convo_id,
                if title.is_empty() { None } else { Some(&title) },
                if description.is_empty() {
                    None
                } else {
                    Some(&description)
                },
                Some(next_version),
                Some(&metadata_locator),
                avatar_locator.as_deref(),
                avatar_bytes.as_deref(),
                avatar_content_type.as_deref(),
            )
            .await
        {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "republish_metadata_after_reset: update_decrypted_metadata failed (non-fatal)"
            );
        }

        info!(
            convo = %&convo_id[..12.min(convo_id.len())],
            new_group = %group_id_hex,
            reset_generation,
            version = next_version,
            "republish_metadata_after_reset: uploaded fresh metadata blob for new generation"
        );

        Ok((Some(metadata_locator), Some(next_version)))
    }

    /// Look up the cached `metadata_version` for `convo_id` from the
    /// in-memory conversation cache. Returns `None` when the conversation
    /// isn't cached or has no decrypted metadata yet.
    async fn cached_metadata_version(&self, convo_id: &str) -> Option<i64> {
        let convos = self.conversations.read().await;
        convos
            .iter()
            .find(|c| c.conversation_id == convo_id)
            .and_then(|c| c.metadata_version)
    }

    /// Read the local conversation snapshot (from in-memory cache, falling
    /// back to the encrypted SQLite DB).
    async fn find_local_conversation(&self, convo_id: &str) -> Option<Conversation> {
        {
            let convos = self.conversations.read().await;
            if let Some(c) = convos.iter().find(|c| c.conversation_id == convo_id) {
                return Some(c.clone());
            }
        }
        match self.db.list_conversations().await {
            Ok(rows) => rows.into_iter().find(|c| c.conversation_id == convo_id),
            Err(_) => None,
        }
    }

    /// Patch the in-memory cache with the decrypted-metadata fields for
    /// `convo_id`. Leaves all other fields untouched. No-op if the
    /// conversation isn't in the cache.
    #[allow(clippy::too_many_arguments)]
    async fn merge_decrypted_metadata_into_cache(
        &self,
        convo_id: &str,
        title: Option<String>,
        description: Option<String>,
        metadata_version: Option<i64>,
        metadata_blob_locator: Option<String>,
        avatar_blob_locator: Option<String>,
        avatar_bytes: Option<Vec<u8>>,
        avatar_content_type: Option<String>,
    ) {
        let mut convos = self.conversations.write().await;
        if let Some(c) = convos.iter_mut().find(|c| c.conversation_id == convo_id) {
            if title.is_some() {
                c.name = title;
            }
            if description.is_some() {
                c.description = description;
            }
            if metadata_version.is_some() {
                c.metadata_version = metadata_version;
            }
            if metadata_blob_locator.is_some() {
                c.metadata_blob_locator = metadata_blob_locator;
            }
            c.avatar_blob_locator = avatar_blob_locator;
            c.avatar_bytes = avatar_bytes;
            c.avatar_content_type = avatar_content_type;
        }
    }

    /// XRPC GET wrapper for `blue.catbird.chat.getBlob`.
    /// Returns `Ok(None)` when the server returns 404 / `BlobNotFound`,
    /// preserving the bootstrap helper's "transient absence" semantics.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn get_group_metadata_blob(
        &self,
        blob_locator: Option<&str>,
        convo_id: Option<&str>,
        group_id: Option<&str>,
        metadata_version: Option<i64>,
        reset_generation: Option<i64>,
        kind: Option<&str>,
    ) -> Result<Option<Vec<u8>>> {
        let _ = (convo_id, group_id, metadata_version, reset_generation, kind);
        let blob_id = match blob_locator {
            Some(id) if !id.trim().is_empty() => id,
            _ => return Ok(None),
        };
        const NSID: &str = "blue.catbird.chat.getBlob";
        let bearer = self.get_service_token(NSID).await?;
        let (url, headers) = self.build_request(NSID, &bearer)?;
        let actor_device_id = self.actor_device_id().await?;
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
            let (url, headers) = self.metadata_blob_request(NSID, &new_bearer)?;
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
            if retry_status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !retry_status.is_success() {
                let body_str = String::from_utf8_lossy(&retry_bytes);
                if body_str.contains("BlobNotFound") {
                    return Ok(None);
                }
                return Err(CatmosError::Xrpc(format!(
                    "{NSID} returned {retry_status}: {body_str}"
                )));
            }
            retry_bytes
        } else {
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !status.is_success() {
                let body_str = String::from_utf8_lossy(&body_bytes);
                if body_str.contains("BlobNotFound") {
                    return Ok(None);
                }
                return Err(CatmosError::Xrpc(format!(
                    "{NSID} returned {status}: {body_str}"
                )));
            }
            body_bytes
        };

        Ok(Some(body_bytes.to_vec()))
    }

    /// XRPC prepareBlobUpload + uploadBlob workflow.
    /// Clean-slate (`Spec §4.1` / `1A`): `mls-ds` `BlobStore` (`prepareBlobUpload` / `uploadBlob`)
    /// is retired; group metadata ciphertext travels inline inside `0x8001` AppDataDictionary
    /// (≤ 16 KiB) and avatars live in ATProto Spaces (`com.atproto.space.putBlob`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn put_group_metadata_blob(
        &self,
        blob_locator: &str,
        convo_id: Option<&str>,
        group_id: &str,
        kind: Option<&str>,
        metadata_version: Option<i64>,
        reset_generation: Option<i64>,
        body: Vec<u8>,
    ) -> Result<String> {
        let _ = (
            blob_locator,
            convo_id,
            group_id,
            kind,
            metadata_version,
            reset_generation,
            body,
        );
        Err(CatmosError::Other(
            "mls-ds BlobStore is retired in clean-slate (1A): group metadata is carried inline in 0x8001 AppDataDictionary and avatars use ATProto Spaces via CliUnifiedMlsClient".to_string(),
        ))
    }

    /// Build URL + auth headers for the metadata-blob endpoints.
    fn metadata_blob_request(&self, nsid: &str, bearer: &str) -> Result<(String, HeaderMap)> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| CatmosError::AuthFailed(e.to_string()))?,
        );

        let url = match &self.auth {
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
                }
                format!("{}/xrpc/{nsid}", pds_url.trim_end_matches('/'))
            }
        };

        Ok((url, headers))
    }
}
