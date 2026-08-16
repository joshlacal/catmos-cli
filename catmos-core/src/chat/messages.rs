use std::collections::{HashMap, HashSet};
use std::time::Instant;

use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use catbird_atproto::catbird::mls_chat;

use super::canonical;
use super::service::ChatService;
use crate::error::{CatmosError, Result};
use crate::types::{Conversation, Member, Message, MessageContent};

// ── MLS message payload (matches iOS MLSMessagePayload) ─────────────────

/// Encrypted message payload structure matching the iOS `MLSMessagePayload`.
/// Encoded to JSON before MLS encryption.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MlsMessagePayload {
    version: u32,
    message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reaction: Option<MlsReactionPayload>,
    // embed, readReceipt, typing, adminRoster, adminAction omitted for now
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MlsReactionPayload {
    message_id: String,
    emoji: String,
    action: String, // "add" or "remove"
}

#[allow(dead_code)]
impl MlsMessagePayload {
    fn text(content: &str) -> Self {
        Self {
            version: 1,
            message_type: "text".to_string(),
            text: Some(content.to_string()),
            reaction: None,
        }
    }

    fn reaction(message_id: &str, emoji: &str, action: &str) -> Self {
        Self {
            version: 1,
            message_type: "reaction".to_string(),
            text: None,
            reaction: Some(MlsReactionPayload {
                message_id: message_id.to_string(),
                emoji: emoji.to_string(),
                action: action.to_string(),
            }),
        }
    }
}

// ── Response deserialization helpers ────────────────────────────────────
//
// The Jacquard-generated output types use lifetime parameters and don't
// implement `DeserializeOwned`, so they can't be used directly with
// reqwest's `.json()` or `serde_json::from_str`. We deserialize responses
// as `serde_json::Value` and extract fields manually using the correct
// field names from the generated types.

/// Extract a `SendMessageOutput`-shaped response from JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendMessageResp {
    pub message_id: String,
    pub seq: i64,
    pub epoch: i64,
}

/// Extract a `GetConvosOutput`-shaped response from JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetConvosResp {
    pub conversations: Vec<ConvoViewResp>,
}

/// Thin deserialization wrapper matching the generated `ConvoView` field names.
///
/// Note: the server still emits a `metadata: { name, description }` field
/// during the rollout window (it is removed from the lexicon in Phase D of
/// the metadata cutover plan). We deserialize it tolerantly into
/// `serde_json::Value` so a stale field doesn't break parsing, but it is
/// **never read** — group titles are decrypted exclusively via
/// `bootstrap_group_metadata` (`chat/metadata.rs`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConvoViewResp {
    pub group_id: String,
    /// Stable conversation identifier (survives group resets).
    /// Falls back to group_id when not provided by the server.
    #[serde(default)]
    pub conversation_id: Option<String>,
    pub creator: String,
    pub epoch: i64,
    pub cipher_suite: String,
    pub members: Vec<MemberViewResp>,
    pub created_at: String,
    #[serde(default)]
    pub last_message_at: Option<String>,
    /// Tolerated for forward/backward compatibility during the cutover.
    /// Intentionally never read — see `convo_resp_to_conversation`.
    #[serde(default)]
    #[allow(dead_code)]
    pub metadata: Option<serde_json::Value>,
}

/// Thin deserialization wrapper matching the generated `MemberView` field names.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemberViewResp {
    pub did: String,
    pub user_did: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub device_name: Option<String>,
    pub is_admin: bool,
    #[serde(default)]
    pub is_moderator: Option<bool>,
    pub joined_at: String,
}

/// AT Protocol `$bytes` encoding: `{"$bytes":"base64..."}`
#[derive(Deserialize)]
pub(crate) struct AtBytes {
    #[serde(rename = "$bytes")]
    pub bytes: String,
}

/// Thin deserialization wrapper matching the generated `MessageView` field names.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MessageViewResp {
    pub id: String,
    pub convo_id: String,
    pub ciphertext: AtBytes,
    pub epoch: i64,
    pub seq: i64,
    pub created_at: String,
    #[serde(default)]
    pub message_type: Option<String>,
}

/// Extract a `GetMessagesOutput`-shaped response from JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetMessagesResp {
    pub messages: Vec<MessageViewResp>,
    #[serde(default)]
    pub last_seq: Option<i64>,
}

/// Extract a `CreateConvoOutput`-shaped response from JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateConvoResp {
    pub convo: ConvoViewResp,
}

// ── Conversions from response types to domain types ─────────────────────

/// Convert a `ConvoViewResp` into our domain `Conversation`.
///
/// **Title / description / avatar are intentionally `None`.** After the MLS
/// metadata cutover the server is cryptographically blind to group metadata,
/// so the only authoritative source is the locally-decrypted blob persisted
/// via `bootstrap_group_metadata` (see `chat/metadata.rs`). The DB layer's
/// `store_conversation` upsert uses `COALESCE(excluded.col, conversations.col)`
/// to preserve any decrypted metadata already written, so callers don't need
/// to merge by hand.
pub(crate) fn convo_resp_to_conversation(view: &ConvoViewResp) -> Conversation {
    let members = view.members.iter().map(member_resp_to_member).collect();

    Conversation {
        conversation_id: view
            .conversation_id
            .clone()
            .unwrap_or_else(|| view.group_id.clone()),
        group_id: view.group_id.clone(),
        // Encrypted-only path — never read view.metadata. The server returns
        // `metadata: None` post-cutover; reading it would be an empty fallback
        // anyway, but accepting any plaintext from the wire would normalise
        // the leak we just plugged.
        name: None,
        description: None,
        creator: view.creator.clone(),
        epoch: view.epoch as u64,
        cipher_suite: view.cipher_suite.clone(),
        members,
        created_at: chrono::DateTime::parse_from_rfc3339(&view.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        last_message_at: view.last_message_at.as_ref().and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        }),
        unread_count: 0,
        alias: None,
        metadata_version: None,
        metadata_blob_locator: None,
        avatar_blob_locator: None,
        avatar_bytes: None,
        avatar_content_type: None,
    }
}

/// Convert a `MemberViewResp` into our domain `Member`.
pub(crate) fn member_resp_to_member(view: &MemberViewResp) -> Member {
    Member {
        did: view.did.clone(),
        user_did: view.user_did.clone(),
        device_id: view.device_id.clone(),
        device_name: view.device_name.clone(),
        is_admin: view.is_admin,
        is_moderator: view.is_moderator.unwrap_or(false),
        joined_at: chrono::DateTime::parse_from_rfc3339(&view.joined_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    }
}

// ── Padding ─────────────────────────────────────────────────────────────

/// Strip trailing zero-byte padding.
fn unpad(data: &[u8]) -> &[u8] {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &data[..end]
}

// ── ChatService message methods ─────────────────────────────────────────

impl ChatService {
    /// Encrypt and send a text message to a conversation.
    ///
    /// On a 409 epoch conflict, syncs commits to advance the local epoch,
    /// re-encrypts at the new epoch, and retries once.
    pub async fn send_message(&self, convo_id: &str, text: &str) -> Result<Message> {
        // Layer 3 quarantine gate (catbird-mls f363fd1): if the conversation is
        // quarantined we refuse to send. No API call, no encrypt, no preSend
        // sync. The user must `:reset` (TUI) or call
        // `user_confirmed_manual_reset` to exit quarantine first.
        if self.is_quarantined(convo_id).await {
            return Err(CatmosError::Other(format!(
                "Conversation paused. Type :reset to continue. (convo={})",
                &convo_id[..12.min(convo_id.len())]
            )));
        }

        // Build the plaintext payload (matches iOS MLSMessagePayload format)
        let payload = MlsMessagePayload::text(text);
        let plaintext = serde_json::to_vec(&payload)?;

        // Sync commits before sending to ensure local epoch is current
        if let Err(e) = self.sync_conversation(convo_id).await {
            let convo_label = &convo_id[..12.min(convo_id.len())];
            debug!("send_message: pre-send sync failed for {convo_label}: {e}");
        }

        // Encrypt via MLS -- ciphertext padding is handled by the MLS layer
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let encrypt_result = self
            .mls
            .with_context(|ctx| ctx.encrypt_message(group_id_bytes.clone(), plaintext.clone()))?;

        // Track own commit for dedup (spec §5.4)
        {
            let hash: [u8; 32] = Sha256::digest(&encrypt_result.ciphertext).into();
            let mut own = self.own_commits.lock().await;
            own.insert(hash, Instant::now());
            // Expire entries older than 5 minutes
            own.retain(|_, ts| ts.elapsed() < std::time::Duration::from_secs(300));
        }

        let epoch = self.get_epoch(convo_id).unwrap_or(0);
        let msg_id = ulid::Ulid::new().to_string();
        let padded_size = encrypt_result.ciphertext.len() as i64;

        // Get local confirmation tag for divergence detection
        let confirmation_tag = self.get_confirmation_tag_b64(&group_id_bytes);

        // Build the generated SendMessage input using the convenience wrapper
        let req: mls_chat::send_message::Input = mls_chat::send_message::InputData {
            convo_id: convo_id.to_string(),
            ciphertext: encrypt_result.ciphertext.clone(),
            epoch: epoch as usize,
            msg_id: msg_id.clone(),
            padded_size,
            delivery: None,
            confirmation_tag: confirmation_tag.clone(),
        }
        .into();

        match self
            .xrpc_procedure::<_, SendMessageResp>(canonical::SEND_MESSAGE, &req)
            .await
        {
            Ok(resp) => {
                let msg = Message {
                    id: resp.message_id,
                    convo_id: convo_id.to_string(),
                    sender_did: Some(self.did().to_string()),
                    content: MessageContent::Text(text.to_string()),
                    epoch: resp.epoch as u64,
                    seq: resp.seq as u64,
                    created_at: Utc::now(),
                };
                self.db.store_message(&msg).await?;
                Ok(msg)
            }
            Err(e) if Self::is_tree_diverged(&e) => {
                let convo_label = &convo_id[..12.min(convo_id.len())];
                warn!("send_message: TreeStateDiverged for {convo_label}, syncing commits (spec §5.3)");

                // Spec §5.3: Lightweight sync — catch up WITHOUT External Commit.
                for _round in 0..3 {
                    if let Err(sync_err) = self.sync_conversation(convo_id).await {
                        warn!("send recovery sync failed for {convo_label}: {sync_err}");
                        break;
                    }
                }

                // Re-encrypt at new epoch and retry once
                let new_encrypt = self.mls.with_context(|ctx| {
                    ctx.encrypt_message(group_id_bytes.clone(), plaintext.clone())
                })?;
                let new_epoch = self.get_epoch(convo_id).unwrap_or(0);
                let new_tag = self.get_confirmation_tag_b64(&group_id_bytes);
                let new_padded = new_encrypt.ciphertext.len() as i64;

                let retry_req: mls_chat::send_message::Input = mls_chat::send_message::InputData {
                    convo_id: convo_id.to_string(),
                    ciphertext: new_encrypt.ciphertext,
                    epoch: new_epoch as usize,
                    msg_id: ulid::Ulid::new().to_string(),
                    padded_size: new_padded,
                    delivery: None,
                    confirmation_tag: new_tag,
                }
                .into();

                match self
                    .xrpc_procedure::<_, SendMessageResp>(canonical::SEND_MESSAGE, &retry_req)
                    .await
                {
                    Ok(resp) => {
                        info!("send_message: tree-diverged retry succeeded for {convo_label} at epoch {new_epoch}");
                        let msg = Message {
                            id: resp.message_id,
                            convo_id: convo_id.to_string(),
                            sender_did: Some(self.did().to_string()),
                            content: MessageContent::Text(text.to_string()),
                            epoch: resp.epoch as u64,
                            seq: resp.seq as u64,
                            created_at: Utc::now(),
                        };
                        self.db.store_message(&msg).await?;
                        Ok(msg)
                    }
                    Err(_) => {
                        // Spec §5.3: send-path recovery is lightweight sync
                        // only; on second failure flag NEEDS_REJOIN so the
                        // post-sync deferred-recovery loop (§8.5) handles
                        // the External Commit. NEVER EC inline from the send
                        // path.
                        warn!("send_message: retry also failed for {convo_label}, flagging NEEDS_REJOIN");
                        self.flag_needs_rejoin(convo_id).await;
                        Err(CatmosError::Other(
                            "Message will send when connection recovers".into(),
                        ))
                    }
                }
            }
            Err(e) if Self::is_epoch_conflict(&e) => {
                let convo_label = &convo_id[..12.min(convo_id.len())];
                warn!("send_message: 409 epoch conflict for {convo_label}, syncing and retrying");

                // Sync commits to advance local epoch
                if let Err(sync_err) = self.sync_conversation(convo_id).await {
                    warn!("send_message: sync failed during 409 recovery for {convo_label}: {sync_err}");
                }

                // Re-encrypt at the new epoch
                let new_epoch = self.get_epoch(convo_id).unwrap_or(0);
                let retry_encrypt = self
                    .mls
                    .with_context(|ctx| ctx.encrypt_message(group_id_bytes.clone(), plaintext))?;

                let retry_msg_id = ulid::Ulid::new().to_string();
                let retry_padded = retry_encrypt.ciphertext.len() as i64;
                let retry_tag = self.get_confirmation_tag_b64(&group_id_bytes);

                let retry_req: mls_chat::send_message::Input = mls_chat::send_message::InputData {
                    convo_id: convo_id.to_string(),
                    ciphertext: retry_encrypt.ciphertext,
                    epoch: new_epoch as usize,
                    msg_id: retry_msg_id,
                    padded_size: retry_padded,
                    delivery: None,
                    confirmation_tag: retry_tag,
                }
                .into();

                let resp: SendMessageResp = self
                    .xrpc_procedure(canonical::SEND_MESSAGE, &retry_req)
                    .await?;

                info!("send_message: retry succeeded for {convo_label} at epoch {new_epoch}");

                let msg = Message {
                    id: resp.message_id,
                    convo_id: convo_id.to_string(),
                    sender_did: Some(self.did().to_string()),
                    content: MessageContent::Text(text.to_string()),
                    epoch: resp.epoch as u64,
                    seq: resp.seq as u64,
                    created_at: Utc::now(),
                };
                self.db.store_message(&msg).await?;
                Ok(msg)
            }
            Err(e) => Err(e),
        }
    }

    /// Get the base64-encoded confirmation tag for a group, or None if unavailable.
    pub(crate) fn get_confirmation_tag_b64(&self, group_id_bytes: &[u8]) -> Option<String> {
        self.mls
            .with_context(|ctx| ctx.get_confirmation_tag(group_id_bytes.to_vec()))
            .map(|tag| base64::engine::general_purpose::STANDARD.encode(&tag))
            .ok()
    }

    /// Check whether an error indicates a 409 epoch conflict.
    fn is_epoch_conflict(err: &CatmosError) -> bool {
        let msg = err.to_string();
        msg.contains("returned 409") || msg.contains("EpochMismatch")
    }

    /// Check whether an error indicates a tree state divergence.
    fn is_tree_diverged(err: &CatmosError) -> bool {
        err.to_string().contains("TreeStateDiverged")
    }

    /// Check whether an error indicates the server rate-limited the request (429).
    fn is_rate_limited(err: &CatmosError) -> bool {
        let msg = err.to_string();
        msg.contains("returned 429") || msg.contains("RateLimited")
    }

    /// Decrypt a raw ciphertext for a conversation.
    /// Returns (plaintext_text, sender_did).
    pub fn decrypt_message(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
    ) -> Result<(String, Option<String>)> {
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let result = self
            .mls
            .with_context(|ctx| ctx.decrypt_message(group_id_bytes.clone(), ciphertext.to_vec()))?;

        let unpadded = unpad(&result.plaintext);
        let plaintext = String::from_utf8_lossy(unpadded).to_string();

        // Extract sender DID from credential identity
        let sender_did = if !result.sender_credential.identity.is_empty() {
            Some(String::from_utf8_lossy(&result.sender_credential.identity).to_string())
        } else {
            None
        };

        Ok((plaintext, sender_did))
    }

    /// Send a typing indicator (ephemeral message).
    pub async fn send_typing(&self, convo_id: &str, is_typing: bool) -> Result<()> {
        let action = if is_typing { "typing" } else { "typingStop" };

        // Use a 512-byte no-op ciphertext for ephemeral messages
        let noop = vec![0u8; 512];
        let msg_id = ulid::Ulid::new().to_string();

        let mut req: mls_chat::send_message::Input = mls_chat::send_message::InputData {
            convo_id: convo_id.to_string(),
            ciphertext: noop,
            epoch: 0,
            msg_id,
            padded_size: 512,
            delivery: Some("ephemeral".to_string()),
            confirmation_tag: None, // not needed for ephemeral messages
        }
        .into();
        req.action = Some(
            catbird_atproto::blue_catbird::mlsChat::send_message::SendMessageAction::from_value(
                action.to_string().into(),
            ),
        );

        let _: serde_json::Value = self.xrpc_procedure(canonical::SEND_MESSAGE, &req).await?;

        Ok(())
    }

    /// Fetch all conversations from the server, decrypt metadata, and cache locally.
    ///
    /// Resolves all unique member DIDs to handles and populates
    /// `self.handle_cache` so the TUI can display friendly names.
    pub async fn fetch_conversations(&self) -> Result<Vec<Conversation>> {
        let resp: GetConvosResp = self.xrpc_query(canonical::GET_CONVERSATIONS, &[]).await?;

        let mut convos: Vec<Conversation> = resp
            .conversations
            .iter()
            .map(convo_resp_to_conversation)
            .collect();

        // Hydrate locally-decrypted metadata into the freshly-built
        // Conversation values BEFORE the COALESCE-aware DB upsert below.
        // Without this step the in-memory cache published to the TUI
        // would briefly show empty titles between the API response and
        // the next bootstrap pass, causing visible flicker.
        match self.db.list_conversations().await {
            Ok(rows) => {
                use std::collections::HashMap;
                let local_by_id: HashMap<String, Conversation> = rows
                    .into_iter()
                    .map(|c| (c.conversation_id.clone(), c))
                    .collect();
                for c in convos.iter_mut() {
                    if let Some(local) = local_by_id.get(&c.conversation_id) {
                        c.name = local.name.clone();
                        c.description = local.description.clone();
                        c.metadata_version = local.metadata_version;
                        c.metadata_blob_locator = local.metadata_blob_locator.clone();
                        c.avatar_blob_locator = local.avatar_blob_locator.clone();
                        c.avatar_bytes = local.avatar_bytes.clone();
                        c.avatar_content_type = local.avatar_content_type.clone();
                    }
                }
            }
            Err(e) => debug!("fetch_conversations: list_conversations(local hydrate) failed: {e}"),
        }

        // Phase F: legacy 0xff00 plaintext fallback removed. Conversation
        // names / descriptions now come exclusively from the encrypted
        // bootstrap path (chat/metadata.rs::bootstrap_group_metadata)
        // which lifts decrypted state into the conversations row.

        // ── Resolve all unique user DIDs to handles ──────────────────────
        let my_did = self.did().to_string();

        // Collect all unique user DIDs across all conversations
        let all_user_dids: HashSet<String> = convos
            .iter()
            .flat_map(|c| c.members.iter().map(|m| m.user_did.clone()))
            .filter(|d| d != &my_did)
            .collect();

        debug!(
            "Resolving {} unique member DIDs to handles",
            all_user_dids.len()
        );

        // Resolve each DID to a handle (reuse existing cache entries)
        let mut new_handles: HashMap<String, String> = HashMap::new();
        {
            let existing = self.handle_cache.read().await;
            for did in &all_user_dids {
                if let Some(cached) = existing.get(did) {
                    new_handles.insert(did.clone(), cached.clone());
                }
            }
        }

        // Resolve any DIDs not already cached
        let uncached: Vec<&String> = all_user_dids
            .iter()
            .filter(|d| !new_handles.contains_key(d.as_str()))
            .collect();

        for did in uncached {
            match self.resolve_handle(did).await {
                Ok(handle) => {
                    new_handles.insert(did.clone(), handle);
                }
                Err(e) => {
                    debug!("Failed to resolve handle for {did}: {e}");
                    new_handles.insert(
                        did.clone(),
                        did.rsplit(':').next().unwrap_or(did).to_string(),
                    );
                }
            }
        }

        // Update the service-wide handle cache
        {
            let mut cache = self.handle_cache.write().await;
            cache.extend(new_handles.clone());
        }

        // For unnamed 1:1 conversations, use the resolved handle as the name
        for convo in &mut convos {
            if convo.name.is_some() {
                continue;
            }
            // Find unique user DIDs (excluding our own)
            let other_dids: Vec<&str> = convo
                .members
                .iter()
                .map(|m| m.user_did.as_str())
                .filter(|d| *d != my_did)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            if other_dids.len() == 1 {
                let other_did = other_dids[0];
                convo.name = Some(new_handles.get(other_did).cloned().unwrap_or_else(|| {
                    other_did
                        .rsplit(':')
                        .next()
                        .unwrap_or(other_did)
                        .to_string()
                }));
            }
        }

        // Persist to local DB
        for convo in &convos {
            if let Err(e) = self.db.store_conversation(convo).await {
                warn!("Failed to store conversation {}: {e}", convo.group_id);
            }
        }

        // Update cached conversations
        *self.conversations.write().await = convos.clone();

        // Encrypted-bootstrap pass: for every conversation we have local MLS
        // state for, fetch+decrypt the latest metadata blob and persist
        // title/description/avatar. Skips quickly when the local
        // metadata_version is already at-or-ahead of the server's
        // MetadataReference. Errors are logged, not fatal — the legacy
        // fallback above and the empty `name` carry the UX through to the
        // next refresh.
        for convo in &convos {
            let group_id_hex = convo.group_id.clone();
            let convo_id = convo.conversation_id.clone();
            let group_id_bytes = match hex::decode(&group_id_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let has_local_state = self
                .mls
                .with_context(|ctx| ctx.get_epoch(group_id_bytes.clone()))
                .is_ok();
            if !has_local_state {
                continue;
            }
            if let Err(e) = self
                .bootstrap_group_metadata(&convo_id, &group_id_hex)
                .await
            {
                debug!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    error = %e,
                    "fetch_conversations: bootstrap_group_metadata failed (non-fatal)"
                );
            }
        }

        // Sync alias display names
        let mut aliases = self.aliases.write().await;
        for convo in &convos {
            if let Some(ref alias) = convo.alias {
                if aliases.get(alias).is_none() {
                    let _ = aliases.set(alias.clone(), convo.group_id.clone());
                }
            }
        }

        Ok(convos)
    }

    /// Sync MLS state for a conversation by processing all commit messages
    /// in epoch/seq order. Pages through results to handle large backlogs.
    ///
    /// Call this before `fetch_messages` to ensure the local epoch is current.
    pub async fn sync_conversation(&self, convo_id: &str) -> Result<()> {
        let convo_label = &convo_id[..12.min(convo_id.len())];
        let gid_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        // Skip sync if we don't have local MLS state for this group — nothing to sync from
        let has_local_state = self
            .mls
            .with_context(|ctx| ctx.get_epoch(gid_bytes.clone()))
            .is_ok();
        if !has_local_state {
            debug!("sync {convo_label}: no local MLS state, skipping");
            return Ok(());
        }

        let mut current_epoch = {
            self.mls
                .with_context(|ctx| ctx.get_epoch(gid_bytes.clone()))
                .unwrap_or(0)
        };

        let mut total_processed = 0u32;

        loop {
            // Server stores each commit at the epoch it LANDS ON (post-apply),
            // and its get_messages filter is `epoch >= fromEpoch`. Requesting
            // `fromEpoch = current_epoch` would return the commit we already
            // applied to reach current_epoch, which then fails with a
            // forward-secrecy error (sender_epoch = current-1). Skip past it.
            let from_epoch = current_epoch.saturating_add(1).to_string();
            let resp: GetMessagesResp = self
                .xrpc_query(
                    canonical::GET_ENTRIES,
                    &[
                        ("convoId", convo_id),
                        ("type", "commit"),
                        ("fromEpoch", &from_epoch),
                        ("limit", "50"),
                    ],
                )
                .await?;

            if resp.messages.is_empty() {
                if total_processed == 0 {
                    debug!(
                        "sync {convo_label}: no commits to process (local epoch {current_epoch})"
                    );
                }
                break;
            }

            debug!(
                "sync {convo_label}: processing {} commits from epoch {current_epoch}",
                resp.messages.len()
            );

            let page_count = resp.messages.len();
            let mut consecutive_failures = 0u32;
            let epoch_before_page = current_epoch;

            for entry in &resp.messages {
                let ciphertext = base64::engine::general_purpose::STANDARD
                    .decode(&entry.ciphertext.bytes)
                    .map_err(|e| CatmosError::Other(format!("Invalid base64 ciphertext: {e}")))?;

                // Own-commit dedup (spec §5.4): skip commits we sent ourselves
                let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
                if self.own_commits.lock().await.remove(&hash).is_some() {
                    debug!(
                        "sync: skipping own commit {} epoch={}",
                        entry.id, entry.epoch
                    );
                    total_processed += 1;
                    consecutive_failures = 0;
                    continue;
                }

                // Task #47: three-phase receive — process_message stages the commit
                // (does NOT advance the epoch). We must then explicitly call
                // merge_incoming_commit to confirm, or discard_incoming_commit to
                // abandon. Auto-merge behavior moved out of catbird-mls in task #33.
                //
                // Policy here: always merge after successful stage. catmos-cli sees
                // commits only via server fan-out, so anything that deserialised and
                // staged cleanly is the canonical next epoch.
                let process_result = self
                    .mls
                    .with_context(|ctx| ctx.process_message(gid_bytes.clone(), ciphertext.clone()));
                match process_result {
                    Ok(catbird_mls::ProcessedContent::StagedCommit {
                        new_epoch,
                        commit_metadata,
                        ..
                    }) => {
                        // Track whether the staged commit announced a metadata
                        // update for the new epoch. After the merge succeeds we
                        // re-bootstrap so the locally-decrypted title/desc/avatar
                        // catch up to the new MetadataReference (per Phase B of
                        // the metadata cutover plan). `commit_metadata.is_some()`
                        // is the only signal — server can't tell us this.
                        let metadata_updated = commit_metadata.is_some();
                        // Confirm the merge so the local epoch actually advances.
                        match self.mls.with_context(|ctx| {
                            ctx.merge_incoming_commit(gid_bytes.clone(), new_epoch)
                        }) {
                            Ok(merged_epoch) => {
                                total_processed += 1;
                                consecutive_failures = 0;
                                self.note_healthy_peer_commit(convo_id).await;
                                debug!(
                                    "sync: staged+merged commit {} epoch={} (local now {merged_epoch})",
                                    entry.id, entry.epoch
                                );
                                if metadata_updated {
                                    // sync_conversation's `convo_id` parameter is actually
                                    // the hex group id (it's hex-decoded into gid_bytes
                                    // above). Resolve the stable conversation_id from the
                                    // in-memory cache so the DB row update lands on the
                                    // post-reset row when group_id != conversation_id.
                                    let stable_convo_id = self
                                        .conversations
                                        .read()
                                        .await
                                        .iter()
                                        .find(|c| c.group_id == convo_id)
                                        .map(|c| c.conversation_id.clone())
                                        .unwrap_or_else(|| convo_id.to_string());
                                    if let Err(e) = self
                                        .bootstrap_group_metadata(&stable_convo_id, convo_id)
                                        .await
                                    {
                                        warn!(
                                            "sync: bootstrap_group_metadata after metadata-update commit failed for {convo_label}: {e}"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                consecutive_failures += 1;
                                warn!(
                                    "sync: merge_incoming_commit failed for {} epoch={}: {e}",
                                    entry.id, entry.epoch
                                );
                                // Best-effort discard so we don't leak a staged handle.
                                let _ = self.mls.with_context(|ctx| {
                                    ctx.discard_incoming_commit(gid_bytes.clone(), new_epoch)
                                });
                                // §10 EPOCH_DIVERGENCE_THRESHOLD: bump per-convo
                                // counter; if hit, flag NEEDS_REJOIN and stop
                                // syncing this conversation (spec §8.2).
                                if self.note_epoch_divergence(convo_id).await {
                                    return Ok(());
                                }
                                if consecutive_failures >= 3 {
                                    debug!("sync {convo_label}: bailing after {consecutive_failures} consecutive merge failures");
                                    break;
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        // Proposal / ApplicationMessage delivered down the commit
                        // endpoint is unusual but harmless — nothing to merge.
                        total_processed += 1;
                        consecutive_failures = 0;
                        debug!(
                            "sync: non-commit processed for {} epoch={}",
                            entry.id, entry.epoch
                        );
                    }
                    Err(e) => {
                        let local_epoch = self
                            .mls
                            .with_context(|ctx| ctx.get_epoch(gid_bytes.clone()))
                            .ok();
                        if Self::classify_peer_bad_error(&e, local_epoch, current_epoch) {
                            let quarantined =
                                self.note_peer_bad_commit(convo_id, &entry.id, None).await;
                            debug!(
                                "sync: peer-bad commit {} epoch={} classified for quarantine: {e}",
                                entry.id, entry.epoch
                            );
                            if quarantined {
                                break;
                            }
                            continue;
                        }
                        consecutive_failures += 1;
                        debug!("sync: skip commit {} epoch={}: {e}", entry.id, entry.epoch);
                        // Bail early: if 3+ consecutive commits fail, the rest likely will too
                        if consecutive_failures >= 3 {
                            debug!("sync {convo_label}: bailing after {consecutive_failures} consecutive failures");
                            break;
                        }
                    }
                }
            }

            // Update current epoch for next page
            current_epoch = self
                .mls
                .with_context(|ctx| ctx.get_epoch(gid_bytes.clone()))
                .unwrap_or(current_epoch);

            // If epoch didn't advance, stop — we're stuck and need a rejoin, not more fetches
            if current_epoch == epoch_before_page {
                debug!("sync {convo_label}: epoch stuck at {current_epoch}, stopping");
                break;
            }

            // If we got fewer than the limit, we've reached the end
            if page_count < 50 {
                break;
            }
        }

        if total_processed > 0 {
            let final_epoch = self
                .mls
                .with_context(|ctx| ctx.get_epoch(gid_bytes))
                .unwrap_or(0);
            info!(
                "sync {convo_label}: done — {total_processed} commits applied, epoch now {final_epoch}"
            );
        }

        Ok(())
    }

    /// Load messages from the local SQLCipher database (no server round-trip).
    pub async fn load_local_messages(&self, convo_id: &str, limit: u32) -> Result<Vec<Message>> {
        self.db.get_messages(convo_id, limit, None).await
    }

    /// Fetch messages for a conversation from the server, decrypt each, and store locally.
    ///
    /// Automatically syncs commits first to ensure the local MLS epoch is current.
    pub async fn fetch_messages(&self, convo_id: &str, limit: u32) -> Result<Vec<Message>> {
        // Sync commits first to bring our epoch up to date
        if let Err(e) = self.sync_conversation(convo_id).await {
            warn!(
                "Failed to sync commits for {}: {e}",
                &convo_id[..12.min(convo_id.len())]
            );
        }

        // Get local epoch to skip old messages we can't decrypt
        let local_epoch = {
            let group_id_bytes = hex::decode(convo_id).unwrap_or_default();
            self.mls
                .with_context(|ctx| ctx.get_epoch(group_id_bytes))
                .ok()
        };

        // Only fetch messages newer than what we already have locally
        let since_seq = self.db.get_max_seq(convo_id).await.ok().flatten();
        let limit_str = limit.to_string();
        let since_seq_str = since_seq.map(|s| s.to_string());

        let mut params: Vec<(&str, &str)> = vec![
            ("convoId", convo_id),
            ("type", "app"),
            ("limit", &limit_str),
        ];
        if let Some(ref seq) = since_seq_str {
            params.push(("sinceSeq", seq));
        }

        let resp: GetMessagesResp = self.xrpc_query(canonical::GET_ENTRIES, &params).await?;

        let convo_label = &convo_id[..12.min(convo_id.len())];
        let mut messages = Vec::with_capacity(resp.messages.len());
        let mut consecutive_failures_at_epoch = 0u32;
        let mut last_failure_epoch: Option<u64> = None;

        for entry in &resp.messages {
            // Skip messages from epochs before we joined
            if let Some(our_epoch) = local_epoch {
                if (entry.epoch as u64) < our_epoch {
                    continue;
                }
            }

            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&entry.ciphertext.bytes)
                .map_err(|e| CatmosError::Other(format!("Invalid base64 ciphertext: {e}")))?;

            match self.decrypt_message(&entry.convo_id, &ciphertext) {
                Ok((plaintext, sender_did)) => {
                    // Reset failure counter on successful decrypt
                    consecutive_failures_at_epoch = 0;
                    last_failure_epoch = None;
                    // §8.2 reset both threshold counters on success.
                    self.reset_recovery_counters(&entry.convo_id).await;

                    let content = parse_message_content(&plaintext);
                    let msg = Message {
                        id: entry.id.clone(),
                        convo_id: entry.convo_id.clone(),
                        sender_did,
                        content,
                        epoch: entry.epoch as u64,
                        seq: entry.seq as u64,
                        created_at: chrono::DateTime::parse_from_rfc3339(&entry.created_at)
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                    };
                    if let Err(e) = self.db.store_message(&msg).await {
                        warn!("Failed to store message {}: {e}", msg.id);
                    }
                    messages.push(msg);
                }
                Err(e) => {
                    // Track consecutive decryption failures at the same epoch
                    let msg_epoch = entry.epoch as u64;
                    if last_failure_epoch == Some(msg_epoch) {
                        consecutive_failures_at_epoch += 1;
                    } else {
                        consecutive_failures_at_epoch = 1;
                        last_failure_epoch = Some(msg_epoch);
                    }

                    // §10 DECRYPTION_FAILURE_THRESHOLD: feed the per-convo
                    // counter; on threshold this flags NEEDS_REJOIN and we
                    // bail.
                    let threshold_hit = self.note_decrypt_failure(&entry.convo_id).await;
                    if threshold_hit || consecutive_failures_at_epoch == 3 {
                        warn!(
                            "Possible tree divergence for {convo_label} — \
                             {consecutive_failures_at_epoch} consecutive failures at epoch {msg_epoch} (local: {}). \
                             Skipping remaining messages.",
                            local_epoch.unwrap_or(0)
                        );
                        // Bail early — remaining messages at this epoch will also fail
                        break;
                    }

                    debug!(
                        "Failed to decrypt message {} in {}: {e}",
                        entry.id, entry.convo_id
                    );
                }
            }
        }

        // Return full message history from local DB (includes both old cached
        // messages and the newly fetched ones we just stored above).
        if since_seq.is_some() && !messages.is_empty() {
            // We only fetched incremental — return the full local view
            return self.db.get_messages(convo_id, limit, None).await;
        }

        Ok(messages)
    }

    /// Repair a diverged group via External Commit rejoin (spec §8.4).
    ///
    /// This is now a thin wrapper around `external_commit_rejoin` (in
    /// `recovery_ops.rs`) so all rejoin paths share the same `RecoveryTracker`
    /// gating: global `MIN_REJOIN_INTERVAL`, per-convo backoff
    /// (`REJOIN_BACKOFF`), `MAX_REJOIN_ATTEMPTS` cap with auto-transition to
    /// `UNRECOVERABLE_LOCAL`, and the `GROUPINFO_404_CIRCUIT_BREAKER`.
    pub async fn repair_group(&self, convo_id: &str) -> Result<()> {
        self.external_commit_rejoin(convo_id).await
    }
}

/// Parse a decrypted JSON payload into a `MessageContent`.
///
/// Supports the iOS `MLSMessagePayload` format (field `messageType`) and the
/// legacy catmos format (field `type`) for backwards compatibility.
fn parse_message_content(plaintext: &str) -> MessageContent {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(plaintext) {
        // Determine message type -- iOS uses "messageType", legacy used "type"
        let msg_type = v
            .get("messageType")
            .or_else(|| v.get("type"))
            .and_then(|t| t.as_str());

        match msg_type {
            Some("text") => {
                let text = v
                    .get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                MessageContent::Text(text)
            }
            Some("reaction") => {
                // iOS nests reaction data under a "reaction" key
                let reaction_obj = v.get("reaction");
                let (target, emoji, action_str) = if let Some(r) = reaction_obj {
                    (
                        r.get("messageId")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string(),
                        r.get("emoji")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string(),
                        r.get("action").and_then(|a| a.as_str()).unwrap_or("add"),
                    )
                } else {
                    // Legacy flat format fallback
                    (
                        v.get("targetMessageId")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string(),
                        v.get("emoji")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string(),
                        v.get("action").and_then(|a| a.as_str()).unwrap_or("add"),
                    )
                };

                let action = match action_str {
                    "remove" => crate::types::ReactionAction::Remove,
                    _ => crate::types::ReactionAction::Add,
                };
                MessageContent::Reaction {
                    target_message_id: target,
                    emoji,
                    action,
                }
            }
            Some("system") => {
                let text = v
                    .get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                MessageContent::System(text)
            }
            _ => MessageContent::Unknown,
        }
    } else {
        // Plain text fallback
        MessageContent::Text(plaintext.to_string())
    }
}
