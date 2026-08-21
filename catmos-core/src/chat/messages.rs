use std::collections::{HashMap, HashSet};
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

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
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MlsReactionPayload {
    message_id: String,
    emoji: String,
    action: String,
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

/// Extract a `SendMessageOutput`-shaped response from JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendMessageResp {
    pub message_id: String,
    pub seq: i64,
    pub epoch: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetConvosResp {
    #[serde(default)]
    pub conversations: Vec<ConvoViewResp>,
    #[serde(default)]
    pub items: Vec<serde_json::Value>,
    #[serde(default)]
    pub inventory_session_id: Option<String>,
    #[serde(default)]
    pub snapshot_event_cursor: Option<String>,
    #[serde(default)]
    pub has_more: Option<bool>,
    #[serde(default)]
    pub next_page_cursor: Option<String>,
}

/// Thin deserialization wrapper matching the generated `ConvoView` field names.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConvoViewResp {
    pub group_id: String,
    #[serde(default)]
    pub conversation_id: Option<String>,
    pub creator: String,
    pub epoch: i64,
    pub cipher_suite: String,
    pub members: Vec<MemberViewResp>,
    pub created_at: String,
    #[serde(default)]
    pub last_message_at: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub metadata: Option<serde_json::Value>,
}

/// Thin deserialization wrapper matching the generated `MemberView` field names.
#[derive(Deserialize, Debug)]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetEntriesResp {
    #[serde(default)]
    pub entries: Vec<ConversationEntryResp>,
    #[serde(default)]
    pub next_after_seq: i64,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub(crate) enum ConversationEntryResp {
    #[serde(rename = "blue.catbird.chat.defs#commitEntry")]
    Commit(CommitEntryResp),
    #[serde(rename = "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry")]
    Fulfillment(CommitEntryResp),
    #[serde(rename = "blue.catbird.chat.defs#leaveCommitFulfillmentEntry")]
    LeaveCommit(CommitEntryResp),
    #[serde(rename = "blue.catbird.chat.defs#applicationEntry")]
    Application(ApplicationEntryResp),
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommitEntryResp {
    #[serde(default)]
    pub conversation_id: String,
    #[serde(default)]
    pub entry_id: String,
    #[serde(default)]
    pub seq: i64,
    pub signed_request: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApplicationEntryResp {
    #[serde(default)]
    pub conversation_id: String,
    #[serde(default)]
    pub entry_id: String,
    #[serde(default)]
    pub seq: i64,
    #[serde(default)]
    pub received_at: Option<String>,
    pub signed_request: serde_json::Value,
}

fn extract_commit_bytes(entry: &CommitEntryResp) -> Option<Vec<u8>> {
    let body = entry.signed_request.get("body")?;
    let commit_val = body.get("commit")?;
    if let Some(s) = commit_val.as_str() {
        BASE64.decode(s).ok()
    } else if let Some(bytes_val) = commit_val.get("bytes").and_then(|v| v.as_str()) {
        BASE64.decode(bytes_val).ok()
    } else if let Some(b_obj) = commit_val.get("$bytes").and_then(|v| v.as_str()) {
        BASE64.decode(b_obj).ok()
    } else {
        None
    }
}

fn extract_application_ciphertext(entry: &ApplicationEntryResp) -> Option<Vec<u8>> {
    let body = entry.signed_request.get("body")?;
    let app_msg = body.get("applicationMessage")?;
    if let Some(s) = app_msg.as_str() {
        BASE64.decode(s).ok()
    } else if let Some(bytes_val) = app_msg.get("bytes").and_then(|v| v.as_str()) {
        BASE64.decode(bytes_val).ok()
    } else if let Some(ct_val) = app_msg.get("ciphertext").and_then(|v| v.as_str()) {
        BASE64.decode(ct_val).ok()
    } else if let Some(b_obj) = app_msg.get("$bytes").and_then(|v| v.as_str()) {
        BASE64.decode(b_obj).ok()
    } else {
        None
    }
}

fn is_replayed_or_own_commit_error(err: &CatmosError) -> bool {
    if let CatmosError::Mls(mls_err) = err {
        if mls_err.is_wrong_epoch() || mls_err.is_cannot_decrypt_own_message() {
            return true;
        }
        if let catbird_mls::MLSError::InvalidInput { message } = mls_err {
            if message.contains("forward secrecy prevents decrypting old epochs")
                || message.contains("Cannot decrypt message from epoch")
            {
                return true;
            }
        }
    }
    let msg = err.to_string();
    msg.contains("WrongEpoch")
        || msg.contains("CannotDecryptOwnMessage")
        || msg.contains("forward secrecy prevents decrypting old epochs")
        || msg.contains("Cannot decrypt message from epoch")
}

/// Extract a `CreateConvoOutput`-shaped response from JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateConvoResp {
    pub convo: ConvoViewResp,
}

// ── Conversions from response types to domain types ─────────────────────

/// Convert a `ConvoViewResp` into our domain `Conversation`.
pub(crate) fn convo_resp_to_conversation(view: &ConvoViewResp) -> Conversation {
    let members = view.members.iter().map(member_resp_to_member).collect();

    Conversation {
        conversation_id: view
            .conversation_id
            .clone()
            .unwrap_or_else(|| view.group_id.clone()),
        group_id: view.group_id.clone(),
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

/// Strip trailing zero-byte padding.
fn unpad(data: &[u8]) -> &[u8] {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &data[..end]
}

// ── ChatService message methods ─────────────────────────────────────────

impl ChatService {
    /// Encrypt and send a text message to a conversation.
    pub async fn send_message(&self, convo_id: &str, text: &str) -> Result<Message> {
        if self.is_quarantined(convo_id).await {
            return Err(CatmosError::Other(format!(
                "Conversation paused. Type :reset to continue. (convo={})",
                &convo_id[..12.min(convo_id.len())]
            )));
        }

        let payload = MlsMessagePayload::text(text);
        let plaintext = serde_json::to_vec(&payload)?;

        if let Err(e) = self.sync_conversation(convo_id).await {
            let convo_label = &convo_id[..12.min(convo_id.len())];
            debug!("send_message: pre-send sync failed for {convo_label}: {e}");
        }

        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let encrypt_result = self
            .mls
            .with_context(|ctx| ctx.encrypt_message(group_id_bytes.clone(), plaintext.clone()))?;

        {
            let hash: [u8; 32] = Sha256::digest(&encrypt_result.ciphertext).into();
            let mut own = self.own_commits.lock().await;
            own.insert(hash, Instant::now());
            own.retain(|_, ts| ts.elapsed() < std::time::Duration::from_secs(300));
        }

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

        match self
            .xrpc_procedure::<_, SendMessageResp>("blue.catbird.chat.sendMessage", &req)
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
                warn!("send_message: TreeStateDiverged for {convo_label}, syncing commits");

                for _round in 0..3 {
                    if let Err(sync_err) = self.sync_conversation(convo_id).await {
                        warn!("send recovery sync failed for {convo_label}: {sync_err}");
                        break;
                    }
                }

                let new_encrypt = self.mls.with_context(|ctx| {
                    ctx.encrypt_message(group_id_bytes.clone(), plaintext.clone())
                })?;
                let new_epoch = self.get_epoch(convo_id).unwrap_or(0);
                let new_tag = self.get_confirmation_tag_b64(&group_id_bytes);
                let new_padded = new_encrypt.ciphertext.len() as i64;

                let retry_req = serde_json::json!({
                    "convoId": convo_id,
                    "ciphertext": BASE64.encode(&new_encrypt.ciphertext),
                    "epoch": new_epoch,
                    "msgId": ulid::Ulid::new().to_string(),
                    "paddedSize": new_padded,
                    "confirmationTag": new_tag,
                });

                match self
                    .xrpc_procedure::<_, SendMessageResp>("blue.catbird.chat.sendMessage", &retry_req)
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

                if let Err(sync_err) = self.sync_conversation(convo_id).await {
                    warn!("send_message: sync failed during 409 recovery for {convo_label}: {sync_err}");
                }

                let new_epoch = self.get_epoch(convo_id).unwrap_or(0);
                let retry_encrypt = self
                    .mls
                    .with_context(|ctx| ctx.encrypt_message(group_id_bytes.clone(), plaintext))?;

                let retry_msg_id = ulid::Ulid::new().to_string();
                let retry_padded = retry_encrypt.ciphertext.len() as i64;
                let retry_tag = self.get_confirmation_tag_b64(&group_id_bytes);

                let retry_req = serde_json::json!({
                    "convoId": convo_id,
                    "ciphertext": BASE64.encode(&retry_encrypt.ciphertext),
                    "epoch": new_epoch,
                    "msgId": retry_msg_id,
                    "paddedSize": retry_padded,
                    "confirmationTag": retry_tag,
                });

                let resp: SendMessageResp = self
                    .xrpc_procedure("blue.catbird.chat.sendMessage", &retry_req)
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

    pub(crate) fn get_confirmation_tag_b64(&self, group_id_bytes: &[u8]) -> Option<String> {
        self.mls
            .with_context(|ctx| ctx.get_confirmation_tag(group_id_bytes.to_vec()))
            .map(|tag| base64::engine::general_purpose::STANDARD.encode(&tag))
            .ok()
    }

    fn is_epoch_conflict(err: &CatmosError) -> bool {
        let msg = err.to_string();
        msg.contains("returned 409") || msg.contains("EpochMismatch")
    }

    fn is_tree_diverged(err: &CatmosError) -> bool {
        err.to_string().contains("TreeStateDiverged")
    }

    #[allow(dead_code)]
    fn is_rate_limited(err: &CatmosError) -> bool {
        let msg = err.to_string();
        msg.contains("returned 429") || msg.contains("RateLimited")
    }

    pub fn decrypt_message(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
    ) -> Result<(String, Option<String>)> {
        let group_id_bytes = if let Ok(bytes) = hex::decode(convo_id) {
            bytes
        } else if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(convo_id) {
            bytes
        } else {
            return Err(CatmosError::Other(format!("Invalid group ID format: {convo_id}")));
        };
        let result = self
            .mls
            .with_context(|ctx| ctx.decrypt_message(group_id_bytes.clone(), ciphertext.to_vec()))?;

        let unpadded = unpad(&result.plaintext);
        let plaintext = String::from_utf8_lossy(unpadded).to_string();

        let sender_did = if !result.sender_credential.identity.is_empty() {
            Some(String::from_utf8_lossy(&result.sender_credential.identity).to_string())
        } else {
            None
        };

        Ok((plaintext, sender_did))
    }

    pub async fn send_typing(&self, convo_id: &str, is_typing: bool) -> Result<()> {
        let action = if is_typing { "typing" } else { "typingStop" };
        let noop = vec![0u8; 512];
        let msg_id = ulid::Ulid::new().to_string();

        let req = serde_json::json!({
            "convoId": convo_id,
            "ciphertext": BASE64.encode(&noop),
            "epoch": 0,
            "msgId": msg_id,
            "paddedSize": 512,
            "delivery": "ephemeral",
            "action": action,
        });

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.chat.sendMessage", &req)
            .await?;

        Ok(())
    }

    /// Fetch all conversations from the server, decrypt metadata, and cache locally.
    pub async fn fetch_conversations(&self) -> Result<Vec<Conversation>> {
        let actor_device_id = self.actor_device_id().await?;
        let mut convos: Vec<Conversation> = Vec::new();
        let mut page_cursor: Option<String> = None;

        loop {
            let mut params = vec![
                ("actorDeviceId", actor_device_id.as_str()),
                ("limit", "50"),
            ];
            let cursor_holder;
            if let Some(ref c) = page_cursor {
                cursor_holder = c.clone();
                params.push(("pageCursor", &cursor_holder));
            }

            let resp: serde_json::Value = self
                .xrpc_query("blue.catbird.chat.getConversations", &params)
                .await?;

            if let (Some(inv_session), Some(event_cursor)) = (
                resp.get("inventorySessionId").and_then(|v| v.as_str()),
                resp.get("snapshotEventCursor").and_then(|v| v.as_str()),
            ) {
                let mut sess = self.inventory_session.write().await;
                *sess = Some((inv_session.to_string(), event_cursor.to_string()));
            }

            if let Some(items) = resp.get("items").and_then(|v| v.as_array()) {
                for item in items {
                    let state_obj = match item.get("state") {
                        Some(s) => s,
                        None => continue,
                    };
                    let coords = match state_obj.get("coordinates") {
                        Some(c) => c,
                        None => continue,
                    };
                    let convo_id = match coords.get("conversationId").and_then(|v| v.as_str()) {
                        Some(id) => id.to_string(),
                        None => continue,
                    };
                    let epoch = coords.get("epoch").and_then(|v| v.as_i64()).unwrap_or(0) as u64;
                    let group_id = if let Some(gid_val) = coords.get("groupId") {
                        if let Some(s) = gid_val.as_str() {
                            if let Ok(b) = BASE64.decode(s) {
                                hex::encode(b)
                            } else {
                                s.to_string()
                            }
                        } else if let Some(b_obj) = gid_val.get("$bytes").and_then(|v| v.as_str()) {
                            if let Ok(b) = BASE64.decode(b_obj) {
                                hex::encode(b)
                            } else {
                                b_obj.to_string()
                            }
                        } else if let Some(arr) = gid_val.as_array() {
                            let bytes: Vec<u8> = arr.iter().filter_map(|b| b.as_u64().map(|n| n as u8)).collect();
                            hex::encode(bytes)
                        } else {
                            convo_id.clone()
                        }
                    } else {
                        convo_id.clone()
                    };
                    let cipher_suite = state_obj
                        .get("cipherSuite")
                        .and_then(|v| v.as_str())
                        .unwrap_or(crate::mls::MLS_CIPHER_SUITE)
                        .to_string();
                    let mut members = Vec::new();
                    let mut creator = String::new();
                    if let Some(participants) = state_obj.get("participants").and_then(|v| v.as_array()) {
                        for (idx, p) in participants.iter().enumerate() {
                            let user_did = p.get("userDid").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let role = p.get("role").and_then(|v| v.as_str()).unwrap_or("member");
                            let is_admin = role == "admin";
                            if is_admin && creator.is_empty() {
                                creator = user_did.clone();
                            } else if idx == 0 && creator.is_empty() {
                                creator = user_did.clone();
                            }
                            members.push(Member {
                                did: user_did.clone(),
                                user_did: user_did.clone(),
                                device_id: None,
                                device_name: None,
                                is_admin,
                                is_moderator: role == "moderator",
                                joined_at: Utc::now(),
                            });
                        }
                    }
                    let mut name = None;
                    let mut description = None;
                    let mut metadata_version = None;
                    if let Some(meta_obj) = state_obj.get("metadataSnapshot") {
                        if let Some(mv) = meta_obj.get("metadataVersion").and_then(|v| v.as_i64()) {
                            metadata_version = Some(mv);
                        }
                        let ct_b64 = meta_obj.get("ciphertext")
                            .and_then(|v| v.get("$bytes").and_then(|b| b.as_str()).or_else(|| v.as_str()));
                        let nonce_b64 = meta_obj.get("nonce")
                            .and_then(|v| v.get("$bytes").and_then(|b| b.as_str()).or_else(|| v.as_str()));
                        if let (Some(ct_str), Some(nonce_str)) = (ct_b64, nonce_b64) {
                            if let (Ok(ct), Ok(nonce_bytes)) = (BASE64.decode(ct_str), BASE64.decode(nonce_str)) {
                                if nonce_bytes.len() == 12 {
                                    let mut nonce_arr = [0u8; 12];
                                    nonce_arr.copy_from_slice(&nonce_bytes);
                                    let gid_bytes = hex::decode(&group_id).unwrap_or_default();
                                    if let Ok(epoch_key) = self.mls.with_context(|ctx| ctx.export_metadata_key(gid_bytes.clone(), epoch)) {
                                        if let Ok(key_arr) = <[u8; 32]>::try_from(epoch_key.as_slice()) {
                                            if let Ok(payload) = catbird_mls::metadata::decrypt_metadata_snapshot(&key_arr, &gid_bytes, epoch, metadata_version.unwrap_or(1) as u64, &nonce_arr, &ct) {
                                                if !payload.title.is_empty() {
                                                    name = Some(payload.title);
                                                }
                                                if !payload.description.is_empty() {
                                                    description = Some(payload.description);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    convos.push(Conversation {
                        conversation_id: convo_id,
                        group_id,
                        name,
                        description,
                        creator,
                        epoch,
                        cipher_suite,
                        members,
                        created_at: Utc::now(),
                        last_message_at: None,
                        unread_count: 0,
                        alias: None,
                        metadata_version,
                        metadata_blob_locator: None,
                        avatar_blob_locator: None,
                        avatar_bytes: None,
                        avatar_content_type: None,
                    });
                }
            } else if let Some(convo_arr) = resp.get("conversations").and_then(|v| v.as_array()) {
                if let Ok(legacy_resp) = serde_json::from_value::<GetConvosResp>(resp.clone()) {
                    for c_resp in &legacy_resp.conversations {
                        convos.push(convo_resp_to_conversation(c_resp));
                    }
                }
            }

            let has_more = resp.get("hasMore").and_then(|v| v.as_bool()).unwrap_or(false);
            let next_cursor = resp.get("nextPageCursor").and_then(|v| v.as_str()).map(String::from);
            if has_more && next_cursor.is_some() {
                page_cursor = next_cursor;
            } else {
                break;
            }
        }

        match self.db.list_conversations().await {
            Ok(rows) => {
                let local_by_id: HashMap<String, Conversation> = rows
                    .into_iter()
                    .map(|c| (c.conversation_id.clone(), c))
                    .collect();
                for c in convos.iter_mut() {
                    if let Some(local) = local_by_id.get(&c.conversation_id) {
                        if c.name.is_none() {
                            c.name = local.name.clone();
                        }
                        if c.description.is_none() {
                            c.description = local.description.clone();
                        }
                        if c.metadata_version.is_none() {
                            c.metadata_version = local.metadata_version;
                        }
                        c.metadata_blob_locator = local.metadata_blob_locator.clone();
                        c.avatar_blob_locator = local.avatar_blob_locator.clone();
                        c.avatar_bytes = local.avatar_bytes.clone();
                        c.avatar_content_type = local.avatar_content_type.clone();
                    }
                }
            }
            Err(e) => debug!("fetch_conversations: list_conversations(local hydrate) failed: {e}"),
        }

        let my_did = self.did().to_string();
        let all_user_dids: HashSet<String> = convos
            .iter()
            .flat_map(|c| c.members.iter().map(|m| m.user_did.clone()))
            .filter(|d| d != &my_did)
            .collect();

        debug!(
            "Resolving {} unique member DIDs to handles",
            all_user_dids.len()
        );

        let mut new_handles: HashMap<String, String> = HashMap::new();
        {
            let existing = self.handle_cache.read().await;
            for did in &all_user_dids {
                if let Some(cached) = existing.get(did) {
                    new_handles.insert(did.clone(), cached.clone());
                }
            }
        }

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

        {
            let mut cache = self.handle_cache.write().await;
            cache.extend(new_handles.clone());
        }

        for convo in &mut convos {
            if convo.name.is_some() {
                continue;
            }
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

        for convo in &convos {
            if let Err(e) = self.db.store_conversation(convo).await {
                warn!("Failed to store conversation {}: {e}", convo.group_id);
            }
        }

        *self.conversations.write().await = convos.clone();

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
    /// in seq order.
    pub async fn sync_conversation(&self, convo_id: &str) -> Result<()> {
        let (convo_uuid, gid_bytes) = if let Ok(parsed) = uuid::Uuid::parse_str(convo_id) {
            let uuid_str = parsed.to_string();
            let gid = self
                .conversations
                .read()
                .await
                .iter()
                .find(|c| c.conversation_id == uuid_str)
                .map(|c| hex::decode(&c.group_id).unwrap_or_default())
                .unwrap_or_else(|| hex::decode(convo_id).unwrap_or_default());
            (uuid_str, gid)
        } else {
            let gid = hex::decode(convo_id).unwrap_or_default();
            let uuid_str = self
                .conversations
                .read()
                .await
                .iter()
                .find(|c| c.group_id == convo_id)
                .map(|c| c.conversation_id.clone())
                .unwrap_or_else(|| convo_id.to_string());
            (uuid_str, gid)
        };

        let convo_label = &convo_id[..12.min(convo_id.len())];

        let local_epoch = match self
            .mls
            .with_context(|ctx| ctx.get_epoch(gid_bytes.clone())) {
            Ok(e) => e,
            Err(_) => {
                debug!("sync {convo_label}: no local MLS state, skipping");
                return Ok(());
            }
        };

        let server_epoch = self
            .conversations
            .read()
            .await
            .iter()
            .find(|c| c.conversation_id == convo_uuid || c.group_id == convo_id)
            .map(|c| c.epoch)
            .unwrap_or(local_epoch);

        let actor_device_id = self.actor_device_id().await?;
        let sync_seq_key = format!("sync_seq_{convo_id}");
        let max_synced = self
            .db
            .get_session_value(&sync_seq_key)
            .await
            .ok()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let max_msg_seq = self.db.get_max_seq(convo_id).await.ok().flatten().unwrap_or(0);
        let mut after_seq = if local_epoch < server_epoch {
            0
        } else {
            max_synced.max(max_msg_seq)
        };
        let mut total_processed = 0u32;

        loop {
            let after_seq_str = after_seq.to_string();
            let resp: serde_json::Value = self
                .xrpc_query(
                    "blue.catbird.chat.getEntries",
                    &[
                        ("actorDeviceId", &actor_device_id),
                        ("conversationId", &convo_uuid),
                        ("afterSeq", &after_seq_str),
                        ("limit", "100"),
                    ],
                )
                .await?;

            let entries_resp: GetEntriesResp = match serde_json::from_value(resp) {
                Ok(r) => r,
                Err(e) => {
                    debug!("sync {convo_label}: getEntries parse empty or error: {e}");
                    break;
                }
            };

            if entries_resp.entries.is_empty() {
                break;
            }

            debug!(
                "sync {convo_label}: processing {} entries from seq {after_seq}",
                entries_resp.entries.len()
            );

            for entry in &entries_resp.entries {
                let commit_entry = match entry {
                    ConversationEntryResp::Commit(c)
                    | ConversationEntryResp::Fulfillment(c)
                    | ConversationEntryResp::LeaveCommit(c) => c,
                    _ => continue,
                };

                let ciphertext = match extract_commit_bytes(commit_entry) {
                    Some(c) => c,
                    None => continue,
                };

                let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
                if self.own_commits.lock().await.remove(&hash).is_some() {
                    debug!("sync: skipping own commit {}", commit_entry.entry_id);
                    total_processed += 1;
                    continue;
                }

                let process_result = self
                    .mls
                    .with_context(|ctx| ctx.process_message(gid_bytes.clone(), ciphertext.clone()));
                match process_result {
                    Ok(catbird_mls::ProcessedContent::StagedCommit {
                        new_epoch,
                        commit_metadata,
                        ..
                    }) => {
                        let metadata_updated = commit_metadata.is_some();
                        match self.mls.with_context(|ctx| {
                            ctx.merge_incoming_commit(gid_bytes.clone(), new_epoch)
                        }) {
                            Ok(merged_epoch) => {
                                total_processed += 1;
                                self.note_healthy_peer_commit(convo_id).await;
                                debug!(
                                    "sync: staged+merged commit {} (local epoch now {merged_epoch})",
                                    commit_entry.entry_id
                                );
                                if metadata_updated {
                                    if let Err(e) = self
                                        .bootstrap_group_metadata(&convo_uuid, convo_id)
                                        .await
                                    {
                                        warn!("sync: bootstrap_group_metadata failed for {convo_label}: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("sync: merge_incoming_commit failed for {} epoch={}: {e}", commit_entry.entry_id, new_epoch);
                                let _ = self.mls.with_context(|ctx| {
                                    ctx.discard_incoming_commit(gid_bytes.clone(), new_epoch)
                                });
                                if !is_replayed_or_own_commit_error(&e) {
                                    if self.note_epoch_divergence(convo_id).await {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        if !is_replayed_or_own_commit_error(&e) {
                            warn!("sync: process_message failed for {}: {e}", commit_entry.entry_id);
                            if self.note_epoch_divergence(convo_id).await {
                                return Ok(());
                            }
                        } else {
                            debug!("sync: silent skip for already-applied/own commit {} ({e})", commit_entry.entry_id);
                        }
                    }
                }
            }

            let _ = self
                .db
                .store_session_value(&sync_seq_key, &entries_resp.next_after_seq.to_string())
                .await;
            if entries_resp.has_more && entries_resp.next_after_seq > after_seq {
                after_seq = entries_resp.next_after_seq;
            } else {
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
    pub async fn fetch_messages(&self, convo_id: &str, limit: u32) -> Result<Vec<Message>> {
        if let Err(e) = self.sync_conversation(convo_id).await {
            warn!(
                "Failed to sync commits for {}: {e}",
                &convo_id[..12.min(convo_id.len())]
            );
        }

        let convo_uuid = if let Ok(parsed) = uuid::Uuid::parse_str(convo_id) {
            parsed.to_string()
        } else {
            self.conversations
                .read()
                .await
                .iter()
                .find(|c| c.group_id == convo_id)
                .map(|c| c.conversation_id.clone())
                .unwrap_or_else(|| convo_id.to_string())
        };

        let sync_seq_key = format!("sync_seq_{convo_id}");
        let max_synced = self
            .db
            .get_session_value(&sync_seq_key)
            .await
            .ok()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let max_msg_seq = self.db.get_max_seq(convo_id).await.ok().flatten().unwrap_or(0);
        let after_seq = max_synced.max(max_msg_seq);
        let after_seq_str = after_seq.to_string();
        let limit_str = limit.to_string();
        let actor_device_id = self.actor_device_id().await?;

        let resp: serde_json::Value = self
            .xrpc_query(
                "blue.catbird.chat.getEntries",
                &[
                    ("actorDeviceId", &actor_device_id),
                    ("conversationId", &convo_uuid),
                    ("afterSeq", &after_seq_str),
                    ("limit", &limit_str),
                ],
            )
            .await?;

        let entries_resp: GetEntriesResp = match serde_json::from_value(resp) {
            Ok(r) => r,
            Err(e) => {
                debug!("fetch_messages: getEntries parse empty or error: {e}");
                return self.db.get_messages(convo_id, limit, None).await;
            }
        };

        let mut messages = Vec::new();
        for entry in &entries_resp.entries {
            let app_entry = match entry {
                ConversationEntryResp::Application(a) => a,
                _ => continue,
            };

            let ciphertext = match extract_application_ciphertext(app_entry) {
                Some(c) => c,
                None => continue,
            };

            let gid = if let Ok(_parsed) = uuid::Uuid::parse_str(convo_id) {
                self.conversations
                    .try_read()
                    .ok()
                    .and_then(|cs| cs.iter().find(|c| c.conversation_id == convo_id).map(|c| c.group_id.clone()))
                    .unwrap_or_else(|| convo_id.to_string())
            } else {
                convo_id.to_string()
            };
            match self.decrypt_message(&gid, &ciphertext) {
                Ok((plaintext, sender_did)) => {
                    self.reset_recovery_counters(convo_id).await;
                    let content = parse_message_content(&plaintext);
                    let created_at = app_entry
                        .received_at
                        .as_deref()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(Utc::now);
                    let msg = Message {
                        id: app_entry.entry_id.clone(),
                        convo_id: convo_id.to_string(),
                        sender_did,
                        content,
                        epoch: 0,
                        seq: app_entry.seq as u64,
                        created_at,
                    };
                    if let Err(e) = self.db.store_message(&msg).await {
                        warn!("Failed to store message {}: {e}", msg.id);
                    }
                    let _ = self
                        .db
                        .store_session_value(&sync_seq_key, &app_entry.seq.to_string())
                        .await;
                    messages.push(msg);
                }
                Err(e) => {
                    debug!("fetch_messages: decrypt error for {convo_id}: {e}");
                }
            }
        }

        self.db.get_messages(convo_id, limit, None).await
    }

    /// Repair a diverged group via External Commit rejoin (spec §8.4).
    pub async fn repair_group(&self, convo_id: &str) -> Result<()> {
        self.external_commit_rejoin(convo_id).await
    }
}

/// Parse a decrypted JSON payload into a `MessageContent`.
fn parse_message_content(plaintext: &str) -> MessageContent {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(plaintext) {
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
        MessageContent::Text(plaintext.to_string())
    }
}
