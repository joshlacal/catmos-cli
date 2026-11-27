use std::collections::{HashMap, HashSet};
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use super::service::{validate_group_id_hex, ChatService};
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
    pub entries: Vec<ConversationEntryResp>,
    #[serde(default)]
    pub next_after_seq: i64,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub(crate) enum ConversationEntryResp {
    #[serde(
        rename = "blue.catbird.chat.defs#commitEntry",
        alias = "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
        alias = "blue.catbird.chat.defs#leaveCommitFulfillmentEntry"
    )]
    Commit(CommitEntryResp),
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

fn extract_commit_bytes(entry: &CommitEntryResp) -> Result<Vec<u8>> {
    let artifact = entry.signed_request.get("body").and_then(|body| body.get("commit"))
        .ok_or_else(|| CatmosError::Xrpc("Commit entry omitted its MLS artifact".into()))?;
    super::entries::artifact_bytes(artifact, "commit")
}


fn is_replayed_or_own_commit_error(err: &CatmosError) -> bool {
    if let CatmosError::Mls(mls_err) = err {
        if mls_err.is_wrong_epoch() {
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
pub(crate) fn convo_resp_to_conversation(view: &ConvoViewResp) -> Result<Conversation> {
    validate_group_id_hex(&view.group_id)?;
    let conversation_id = view
        .conversation_id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            CatmosError::ConvoNotFound(
                "conversation response omitted stable conversation ID".to_string(),
            )
        })?
        .to_string();
    if conversation_id == view.group_id {
        return Err(CatmosError::ConvoNotFound(
            "conversation response reused the MLS group ID as its stable conversation ID"
                .to_string(),
        ));
    }
    let members = view.members.iter().map(member_resp_to_member).collect();

    Ok(Conversation {
        conversation_id,
        group_id: view.group_id.clone(),
        name: None,
        description: None,
        creator: (!view.creator.trim().is_empty()).then(|| view.creator.clone()),
        epoch: view.epoch as u64,
        cipher_suite: view.cipher_suite.clone(),
        members,
        created_at: chrono::DateTime::parse_from_rfc3339(&view.created_at)
            .ok()
            .map(|dt| dt.with_timezone(&Utc)),
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
    })
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

/// Decode the protocol's groupId envelope without ever falling back to the
/// stable conversation ID. Raw exact hex remains accepted for legacy servers;
/// all other string values must be valid base64 bytes that become non-empty
/// group hex.
fn parse_group_id_value(value: &serde_json::Value) -> Result<String> {
    let group_id = if let Some(raw) = value.as_str() {
        if validate_group_id_hex(raw).is_ok() {
            raw.to_string()
        } else {
            let bytes = BASE64
                .decode(raw)
                .map_err(|e| CatmosError::Other(format!("invalid group ID base64: {e}")))?;
            hex::encode(bytes)
        }
    } else if let Some(encoded) = value.get("$bytes").and_then(|bytes| bytes.as_str()) {
        hex::encode(
            BASE64
                .decode(encoded)
                .map_err(|e| CatmosError::Other(format!("invalid group ID $bytes base64: {e}")))?,
        )
    } else if let Some(array) = value.as_array() {
        let mut bytes = Vec::with_capacity(array.len());
        for item in array {
            let byte = item.as_u64().ok_or_else(|| {
                CatmosError::Other("group ID byte array contains a non-byte value".to_string())
            })?;
            let byte = u8::try_from(byte).map_err(|_| {
                CatmosError::Other("group ID byte array contains a value above 255".to_string())
            })?;
            bytes.push(byte);
        }
        hex::encode(bytes)
    } else {
        return Err(CatmosError::Other(
            "getConversations response omitted group ID".to_string(),
        ));
    };
    validate_group_id_hex(&group_id)?;
    Ok(group_id)
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
        let stable_convo_id = self.resolve_conversation_ids(convo_id).await?.0;

        if let Some(orchestrator) = self.orchestrator().await {
            let sent = orchestrator.send_message(&stable_convo_id, text).await
                .map_err(|error| CatmosError::Other(error.to_string()))?;
            let message = Message {
                id: sent.id,
                convo_id: sent.conversation_id,
                sender_did: Some(sent.sender_did),
                content: MessageContent::Text(sent.text),
                epoch: sent.epoch,
                seq: sent.sequence_number,
                created_at: sent.timestamp,
            };
            self.db.store_message(&message).await?;
            return Ok(message);
        }

        if self.is_quarantined(&stable_convo_id).await {
            return Err(CatmosError::Other(format!(
                "Conversation paused. Type :reset to continue. (convo={})",
                &stable_convo_id[..12.min(stable_convo_id.len())]
            )));
        }

        let payload = MlsMessagePayload::text(text);
        let plaintext = serde_json::to_vec(&payload)?;

        if let Err(e) = self.sync_conversation(&stable_convo_id).await {
            let convo_label = &stable_convo_id[..12.min(stable_convo_id.len())];
            debug!("send_message: pre-send sync failed for {convo_label}: {e}");
        }

        // A reset can remap the stable conversation while the pre-send sync
        // is in flight. Re-read the durable/current binding immediately before
        // touching MLS so encryption never uses a stale group ID.
        let (_, group_id) = self.resolve_conversation_ids(&stable_convo_id).await?;

        let group_id_bytes = hex::decode(&group_id)
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

        let epoch = self.get_epoch(&group_id).unwrap_or(0);
        let msg_id = ulid::Ulid::new().to_string();
        let padded_size = encrypt_result.ciphertext.len() as i64;
        let confirmation_tag = self.get_confirmation_tag_b64(&group_id_bytes);

        let req = serde_json::json!({
            "convoId": stable_convo_id.clone(),
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
                    convo_id: stable_convo_id.clone(),
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
                let convo_label = &stable_convo_id[..12.min(stable_convo_id.len())];
                warn!("send_message: TreeStateDiverged for {convo_label}, syncing commits");

                for _round in 0..3 {
                    if let Err(sync_err) = self.sync_conversation(&stable_convo_id).await {
                        warn!("send recovery sync failed for {convo_label}: {sync_err}");
                        break;
                    }
                }

                let (_, group_id) = self.resolve_conversation_ids(&stable_convo_id).await?;
                let retry_group_id_bytes = hex::decode(&group_id)
                    .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

                let new_encrypt = self.mls.with_context(|ctx| {
                    ctx.encrypt_message(retry_group_id_bytes.clone(), plaintext.clone())
                })?;
                let new_epoch = self.get_epoch(&group_id).unwrap_or(0);
                let new_tag = self.get_confirmation_tag_b64(&retry_group_id_bytes);
                let new_padded = new_encrypt.ciphertext.len() as i64;

                let retry_req = serde_json::json!({
                    "convoId": stable_convo_id.clone(),
                    "ciphertext": BASE64.encode(&new_encrypt.ciphertext),
                    "epoch": new_epoch,
                    "msgId": ulid::Ulid::new().to_string(),
                    "paddedSize": new_padded,
                    "confirmationTag": new_tag,
                });

                match self
                    .xrpc_procedure::<_, SendMessageResp>(
                        "blue.catbird.chat.sendMessage",
                        &retry_req,
                    )
                    .await
                {
                    Ok(resp) => {
                        info!("send_message: tree-diverged retry succeeded for {convo_label} at epoch {new_epoch}");
                        let msg = Message {
                            id: resp.message_id,
                            convo_id: stable_convo_id.clone(),
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
                        self.flag_needs_rejoin(&stable_convo_id).await;
                        Err(CatmosError::Other(
                            "Message will send when connection recovers".into(),
                        ))
                    }
                }
            }
            Err(e) if Self::is_epoch_conflict(&e) => {
                let convo_label = &stable_convo_id[..12.min(stable_convo_id.len())];
                warn!("send_message: 409 epoch conflict for {convo_label}, syncing and retrying");

                if let Err(sync_err) = self.sync_conversation(&stable_convo_id).await {
                    warn!("send_message: sync failed during 409 recovery for {convo_label}: {sync_err}");
                }

                let (_, group_id) = self.resolve_conversation_ids(&stable_convo_id).await?;
                let retry_group_id_bytes = hex::decode(&group_id)
                    .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

                let new_epoch = self.get_epoch(&group_id).unwrap_or(0);
                let retry_encrypt = self.mls.with_context(|ctx| {
                    ctx.encrypt_message(retry_group_id_bytes.clone(), plaintext)
                })?;

                let retry_msg_id = ulid::Ulid::new().to_string();
                let retry_padded = retry_encrypt.ciphertext.len() as i64;
                let retry_tag = self.get_confirmation_tag_b64(&retry_group_id_bytes);

                let retry_req = serde_json::json!({
                    "convoId": stable_convo_id.clone(),
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
                    convo_id: stable_convo_id,
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
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

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
        let (stable_convo_id, _) = self.resolve_conversation_ids(convo_id).await?;
        let action = if is_typing { "typing" } else { "typingStop" };
        let noop = vec![0u8; 512];
        let msg_id = ulid::Ulid::new().to_string();

        let req = serde_json::json!({
            "convoId": stable_convo_id,
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
        self.fetch_conversations_with_states().await.map(|(conversations, _)| conversations)
    }

    /// Preserve the exact server snapshot until the shared orchestrator can
    /// apply invitation consent gates. Local/legacy rows carry no snapshot.
    pub(crate) async fn fetch_conversations_with_states(&self) -> Result<(
        Vec<Conversation>,
        HashMap<String, petrel_catbird::generated::blue::catbird::chat::defs::ConversationState>,
    )> {
        let actor_device_id = self.actor_device_id().await?;
        let mut convos: Vec<Conversation> = Vec::new();
        let mut canonical_states = HashMap::new();
        let mut page_cursor: Option<String> = None;

        loop {
            let mut params = vec![("actorDeviceId", actor_device_id.as_str()), ("limit", "50")];
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
                        Some(id) if !id.trim().is_empty() => id.to_string(),
                        None => continue,
                        Some(_) => {
                            return Err(CatmosError::ConvoNotFound(
                                "getConversations response contained an empty stable conversation ID"
                                    .to_string(),
                            ));
                        }
                    };
                    let epoch = coords.get("epoch").and_then(|v| v.as_i64()).unwrap_or(0) as u64;
                    let group_id =
                        parse_group_id_value(coords.get("groupId").ok_or_else(|| {
                            CatmosError::Other(format!(
                                "conversation {convo_id} response omitted group ID"
                            ))
                        })?)?;
                    if convo_id == group_id {
                        return Err(CatmosError::ConvoNotFound(
                            "getConversations response reused the MLS group ID as its stable conversation ID"
                                .to_string(),
                        ));
                    }
                    let canonical_state = catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
                        state_obj.to_string().as_bytes(),
                    ).map_err(|error| {
                        CatmosError::Xrpc(format!("invalid canonical conversation state: {error}"))
                    })?;
                    if canonical_states.insert(convo_id.clone(), canonical_state).is_some() {
                        return Err(CatmosError::Xrpc("duplicate canonical conversation state".into()));
                    }
                    let cipher_suite = state_obj
                        .get("cipherSuite")
                        .and_then(|v| v.as_str())
                        .unwrap_or(crate::mls::MLS_CIPHER_SUITE)
                        .to_string();
                    let mut members = Vec::new();
                    if let Some(participants) =
                        state_obj.get("participants").and_then(|v| v.as_array())
                    {
                        for p in participants {
                            let user_did = p
                                .get("userDid")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let role = p.get("role").and_then(|v| v.as_str()).unwrap_or("member");
                            let is_admin = role == "admin";
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
                    convos.push(Conversation {
                        conversation_id: convo_id,
                        group_id,
                        name: None,
                        description: None,
                        creator: None,
                        epoch,
                        cipher_suite,
                        members,
                        created_at: None,
                        last_message_at: None,
                        unread_count: 0,
                        alias: None,
                        metadata_version: None,
                        metadata_blob_locator: None,
                        avatar_blob_locator: None,
                        avatar_bytes: None,
                        avatar_content_type: None,
                    });
                }
            } else if resp
                .get("conversations")
                .and_then(|v| v.as_array())
                .is_some()
            {
                let legacy_resp =
                    serde_json::from_value::<GetConvosResp>(resp.clone()).map_err(|e| {
                        CatmosError::Xrpc(format!("invalid getConversations response: {e}"))
                    })?;
                for c_resp in &legacy_resp.conversations {
                    convos.push(convo_resp_to_conversation(c_resp)?);
                }
            }

            let has_more = resp
                .get("hasMore")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let next_cursor = resp
                .get("nextPageCursor")
                .and_then(|v| v.as_str())
                .map(String::from);
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

        // Canonical joins/decryption may have metadata in the shared runtime
        // or its store while this host projection has not seen it yet.
        if let Some(orchestrator) = self.orchestrator().await {
            use catbird_mls::orchestrator::storage::MLSStorageBackend;
            let runtime_views = orchestrator.conversations().lock().await.clone();
            for conversation in &mut convos {
                if conversation.name.is_some() && conversation.description.is_some() {
                    continue;
                }
                let local = match runtime_views.get(&conversation.conversation_id)
                    .filter(|view| view.group_id == conversation.group_id && view.metadata.is_some())
                {
                    Some(view) => Some(view.clone()),
                    None => match orchestrator.storage().get_conversation(self.did(), &conversation.conversation_id).await {
                        Ok(local) => local,
                        Err(error) => {
                            debug!(conversation = %conversation.conversation_id, %error, "Optional local title hydration failed");
                            None
                        }
                    },
                };
                if let Some(local) = local.filter(|local| local.group_id == conversation.group_id) {
                    if let Some(metadata) = local.metadata {
                        if conversation.name.is_none() { conversation.name = metadata.name; }
                        if conversation.description.is_none() { conversation.description = metadata.description; }
                    }
                }
            }
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

        Ok((convos, canonical_states))
    }

    /// Sync MLS state for a conversation by processing all commit messages
    /// in seq order.
    pub async fn sync_conversation(&self, convo_id: &str) -> Result<()> {
        let (stable_convo_id, group_id_hex) = self.resolve_conversation_ids(convo_id).await?;
        let gid_bytes = hex::decode(&group_id_hex)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let convo_label = &stable_convo_id[..12.min(stable_convo_id.len())];

        let has_local_state = self
            .mls
            .with_context(|ctx| ctx.get_epoch(gid_bytes.clone()))
            .is_ok();
        if !has_local_state {
            debug!("sync {convo_label}: no local MLS state, skipping");
            return Ok(());
        }

        let actor_device_id = self.actor_device_id().await?;
        let sync_seq_key = format!("sync_seq_{stable_convo_id}");
        let max_synced = self
            .db
            .get_session_value(&sync_seq_key)
            .await
            .ok()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let stable_max_msg_seq = self
            .db
            .get_max_seq(&stable_convo_id)
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
        let legacy_max_msg_seq = if group_id_hex != stable_convo_id {
            self.db
                .get_max_seq(&group_id_hex)
                .await
                .ok()
                .flatten()
                .unwrap_or(0)
        } else {
            0
        };
        let mut after_seq = max_synced.max(stable_max_msg_seq.max(legacy_max_msg_seq));
        let mut total_processed = 0u32;

        loop {
            let after_seq_str = after_seq.to_string();
            let resp: serde_json::Value = self
                .xrpc_query(
                    "blue.catbird.chat.getEntries",
                    &[
                        ("actorDeviceId", &actor_device_id),
                        ("conversationId", &stable_convo_id),
                        ("afterSeq", &after_seq_str),
                        ("limit", "100"),
                    ],
                )
                .await?;

            let entries_resp: GetEntriesResp = serde_json::from_value(resp)
                .map_err(|error| CatmosError::Xrpc(format!("Invalid conversation entries: {error}")))?;

            if entries_resp.entries.is_empty() {
                break;
            }

            debug!(
                "sync {convo_label}: processing {} entries from seq {after_seq}",
                entries_resp.entries.len()
            );

            for entry in &entries_resp.entries {
                let commit_entry = match entry {
                    ConversationEntryResp::Commit(c) => c,
                    _ => continue,
                };

                let ciphertext = extract_commit_bytes(commit_entry)?;

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
                                self.note_healthy_peer_commit(&stable_convo_id).await;
                                debug!(
                                    "sync: staged+merged commit {} (local epoch now {merged_epoch})",
                                    commit_entry.entry_id
                                );
                                if metadata_updated {
                                    if let Err(e) = self
                                        .bootstrap_group_metadata(&stable_convo_id, &group_id_hex)
                                        .await
                                    {
                                        warn!("sync: bootstrap_group_metadata failed for {convo_label}: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "sync: merge_incoming_commit failed for {} epoch={}: {e}",
                                    commit_entry.entry_id, new_epoch
                                );
                                let _ = self.mls.with_context(|ctx| {
                                    ctx.discard_incoming_commit(gid_bytes.clone(), new_epoch)
                                });
                                if !is_replayed_or_own_commit_error(&e) {
                                    if self.note_epoch_divergence(&stable_convo_id).await {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        if !is_replayed_or_own_commit_error(&e) {
                            warn!(
                                "sync: process_message failed for {}: {e}",
                                commit_entry.entry_id
                            );
                            if self.note_epoch_divergence(&stable_convo_id).await {
                                return Ok(());
                            }
                        } else {
                            debug!(
                                "sync: silent skip for already-applied/own commit {} ({e})",
                                commit_entry.entry_id
                            );
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
        let (stable_convo_id, group_id) = self.resolve_conversation_ids(convo_id).await?;
        let mut source_ids = self
            .db
            .list_conversation_group_ids(&stable_convo_id)
            .await?;
        if !source_ids.iter().any(|source| source == &stable_convo_id) {
            source_ids.push(stable_convo_id.clone());
        }
        if !source_ids.iter().any(|source| source == &group_id) {
            source_ids.push(group_id);
        }

        let mut buckets = Vec::with_capacity(source_ids.len());
        for source_id in source_ids {
            // Do not apply the UI limit to an individual source: old reset
            // buckets and the current stable bucket must be unioned,
            // deduplicated, and sorted by confirmed sequence before truncation.
            buckets.push(self.db.get_messages(&source_id, u32::MAX, None).await?);
        }
        merge_message_buckets(buckets, &stable_convo_id, limit)
    }

    /// Fetch messages for a conversation from the server, decrypt each, and store locally.
    pub async fn fetch_messages(&self, convo_id: &str, limit: u32) -> Result<Vec<Message>> {
        let (stable_convo_id, _) = self.resolve_conversation_ids(convo_id).await?;

        if let Err(e) = self.sync_conversation(&stable_convo_id).await {
            warn!(
                "Failed to sync commits for {}: {e}",
                &stable_convo_id[..12.min(stable_convo_id.len())]
            );
        }

        // A reset can complete while commit sync is in flight. Use the
        // post-sync durable/current binding for MLS decryption.
        let (_, group_id) = self.resolve_conversation_ids(&stable_convo_id).await?;

        let sync_seq_key = format!("sync_seq_{stable_convo_id}");
        let max_synced = self
            .db
            .get_session_value(&sync_seq_key)
            .await
            .ok()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let stable_max_msg_seq = self
            .db
            .get_max_seq(&stable_convo_id)
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
        let legacy_max_msg_seq = if group_id != stable_convo_id {
            self.db
                .get_max_seq(&group_id)
                .await
                .ok()
                .flatten()
                .unwrap_or(0)
        } else {
            0
        };
        let after_seq = max_synced.max(stable_max_msg_seq.max(legacy_max_msg_seq));
        let after_seq_str = after_seq.to_string();
        let limit_str = limit.to_string();
        let actor_device_id = self.actor_device_id().await?;

        let resp: serde_json::Value = self
            .xrpc_query(
                "blue.catbird.chat.getEntries",
                &[
                    ("actorDeviceId", &actor_device_id),
                    ("conversationId", &stable_convo_id),
                    ("afterSeq", &after_seq_str),
                    ("limit", &limit_str),
                ],
            )
            .await?;

        let entries_resp: GetEntriesResp = serde_json::from_value(resp)
            .map_err(|error| CatmosError::Xrpc(format!("Invalid conversation entries: {error}")))?;
        debug!(
            "fetch_messages {}: afterSeq={after_seq} entries={} application={}",
            &stable_convo_id[..12.min(stable_convo_id.len())],
            entries_resp.entries.len(),
            entries_resp
                .entries
                .iter()
                .filter(|e| matches!(e, ConversationEntryResp::Application(_)))
                .count()
        );

        let mut messages = Vec::new();
        for entry in &entries_resp.entries {
            let app_entry = match entry {
                ConversationEntryResp::Application(a) => a,
                _ => continue,
            };

            let envelope = catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(
                &serde_json::json!({
                    "$type": "blue.catbird.chat.defs#applicationEntry",
                    "entryId": app_entry.entry_id, "conversationId": app_entry.conversation_id,
                    "seq": app_entry.seq, "receivedAt": app_entry.received_at,
                    "signedRequest": app_entry.signed_request,
                }), &stable_convo_id,
            ).map_err(|error| CatmosError::Xrpc(error.to_string()))?
                .ok_or_else(|| CatmosError::Xrpc("Application entry has no MLS envelope".into()))?;
            let ciphertext = envelope.ciphertext;

            match self.decrypt_message(&group_id, &ciphertext) {
                Ok((plaintext, sender_did)) => {
                    self.reset_recovery_counters(&stable_convo_id).await;
                    let content = parse_message_content(&plaintext);
                    let created_at = envelope.timestamp;
                    let msg = Message {
                        id: app_entry.entry_id.clone(),
                        convo_id: stable_convo_id.clone(),
                        sender_did,
                        content,
                        epoch: envelope.server_epoch.expect("canonical envelope epoch"),
                        seq: envelope.server_sequence.expect("canonical envelope sequence"),
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
                    debug!("fetch_messages: decrypt error for {stable_convo_id}: {e}");
                }
            }
        }

        self.load_local_messages(&stable_convo_id, limit).await
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

/// Merge stable-keyed and legacy group-keyed rows without rewriting either
/// database bucket. The field-encrypted payload is bound to the stored
/// `convo_id`, so only the in-memory routing ID is normalized for the TUI.
fn merge_message_buckets(
    buckets: Vec<Vec<Message>>,
    stable_convo_id: &str,
    limit: u32,
) -> Result<Vec<Message>> {
    let mut by_id = HashMap::new();
    for bucket in buckets {
        for message in bucket {
            if let Some(existing) = by_id.get(&message.id) {
                if !same_message_payload(existing, &message) {
                    return Err(CatmosError::Storage(format!(
                        "conflicting duplicate message ID {} across conversation buckets",
                        message.id
                    )));
                }
                continue;
            }
            by_id.insert(message.id.clone(), message);
        }
    }

    let mut messages: Vec<Message> = by_id.into_values().collect();
    messages.sort_by(|left, right| {
        crate::types::message_order_key(left.seq, &left.created_at, &left.id)
            .cmp(&crate::types::message_order_key(right.seq, &right.created_at, &right.id))
    });

    let keep = limit as usize;
    if messages.len() > keep {
        messages.drain(..messages.len() - keep);
    }
    for message in &mut messages {
        message.convo_id = stable_convo_id.to_string();
    }
    Ok(messages)
}

fn same_message_payload(left: &Message, right: &Message) -> bool {
    left.sender_did == right.sender_did
        && serde_json::to_value(&left.content).ok() == serde_json::to_value(&right.content).ok()
        && left.epoch == right.epoch
        && left.seq == right.seq
        && left.created_at == right.created_at
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMethod;
    use crate::mls::MlsManager;
    use crate::storage::aliases::AliasStore;
    use crate::storage::config::Config;
    use crate::storage::db::Database;
    use crate::types::{Conversation, Message, MessageContent};
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use tokio::sync::RwLock;

    async fn mock_get_entries() -> axum::Json<Value> {
        axum::Json(serde_json::json!({"entries": []}))
    }

    async fn mock_send_message(
        axum::extract::State(captured): axum::extract::State<Arc<Mutex<Option<Value>>>>,
        axum::Json(body): axum::Json<Value>,
    ) -> axum::Json<Value> {
        *captured.lock().expect("capture lock") = Some(body);
        axum::Json(serde_json::json!({
            "messageId": "server-message",
            "seq": 1,
            "epoch": 0,
        }))
    }

    async fn mock_create_conversation() -> axum::Json<Value> {
        axum::Json(serde_json::json!({
            "convo": {
                "conversationId": "550e8400-e29b-41d4-a716-446655440000",
                "groupId": "000102030405060708090a0b0c0d0e0f",
                "creator": "did:plc:test",
                "epoch": 0,
                "cipherSuite": crate::mls::MLS_CIPHER_SUITE,
                "members": [],
                "createdAt": "2026-01-01T00:00:00Z"
            }
        }))
    }

    async fn mock_submit_transition() -> axum::Json<Value> {
        axum::Json(serde_json::json!({"success": true, "newEpoch": 0}))
    }

    async fn test_service() -> ChatService {
        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let root = Arc::new(tempfile::tempdir().expect("temporary MLS directory"));
        let mls_dir = root.path().to_path_buf();
        let db_path = root.path().join("chat.db");
        let mls = Arc::new(MlsManager::new(&mls_dir, "did:plc:test").expect("MLS manager"));
        let db = Arc::new(
            Database::open_unencrypted(&db_path)
                .await
                .expect("chat database"),
        );
        let mut service = ChatService::new(
            AuthMethod::OAuth {
                session_cookie: "test-cookie".to_string(),
                did: "did:plc:test".to_string(),
                nest_url: "http://127.0.0.1:1".to_string(),
            },
            None,
            mls,
            db,
            Config::default(),
            Arc::new(RwLock::new(AliasStore::with_path(
                root.path().join("aliases.json"),
            ))),
        );
        // `MlsManager` writes to its directory during later send/sync calls;
        // retain the fixture owner on the service instead of leaking it.
        service.test_tempdir = Some(root);
        service
    }

    fn fixture_conversation(conversation_id: &str, group_id: &str) -> Conversation {
        Conversation {
            conversation_id: conversation_id.to_string(),
            group_id: group_id.to_string(),
            name: None,
            description: None,
            creator: Some("did:plc:test".to_string()),
            epoch: 0,
            cipher_suite: crate::mls::MLS_CIPHER_SUITE.to_string(),
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
        }
    }

    fn canonical_state_fixture(id: &str, group: &str, pending_invitee: bool) -> Value {
        let mut state: Value = serde_json::from_str(include_str!("../../tests/fixtures/canonical-conversation-state.json")).unwrap();
        state["coordinates"]["conversationId"] = serde_json::json!(id);
        state["coordinates"]["groupId"] = serde_json::json!({"$bytes": BASE64.encode(hex::decode(group).unwrap())});
        state["coordinates"]["epoch"] = serde_json::json!(0);
        state["metadataSnapshot"]["coordinate"]["conversationId"] = serde_json::json!({"$bytes": BASE64.encode(uuid::Uuid::parse_str(id).unwrap().as_bytes())});
        state["metadataSnapshot"]["coordinate"]["groupId"] = state["coordinates"]["groupId"].clone();
        state["metadataSnapshot"]["coordinate"]["epoch"] = serde_json::json!(0);
        if !pending_invitee { state["participants"].as_array_mut().unwrap().truncate(1); }
        state
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn canonical_inventory_does_not_invent_or_rehydrate_creation_metadata() {
        let mut service = test_service().await;
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let group = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let old_creator = "did:plc:previously-guessed";
        let old_date = "2026-09-05T02:34:00+00:00";
        let mut cached = fixture_conversation(id, group);
        cached.creator = Some(old_creator.to_owned());
        cached.created_at = Some(chrono::DateTime::parse_from_rfc3339(old_date).unwrap().with_timezone(&Utc));
        service.db.store_conversation(&cached).await.unwrap();
        service.db.store_session_value("mls_device_id", "device-1").await.unwrap();
        service.handle_cache.write().await.insert("did:plc:first-member".into(), "first.test".into());
        let response = serde_json::json!({
            "items": [{"state": canonical_state_fixture(id, group, false)}]
        });
        let router = axum::Router::new().route(
            "/xrpc/blue.catbird.chat.getConversations",
            axum::routing::get(move || { let response = response.clone(); async move { axum::Json(response) } }),
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        service.auth = AuthMethod::OAuth {
            session_cookie: "test-cookie".into(), did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(), nest_url: format!("http://{address}"),
        };
        for _ in 0..2 {
            let rows = service.fetch_conversations().await.unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].creator, None);
            assert_eq!(rows[0].created_at, None);
            let json = serde_json::to_value(&rows[0]).unwrap();
            assert!(json.get("creator").is_none());
            assert!(json.get("created_at").is_none());
            let cached = service.db.list_conversations().await.unwrap();
            assert_eq!(cached[0].creator, None);
            assert_eq!(cached[0].created_at, None);
        }
        // Unknown inventory preserves the old database bytes without treating
        // those unproven values as evidence in cache or native projections.
        let preserved: (String, String) = sqlx::query_as(
            "SELECT creator, created_at FROM conversations WHERE conversation_id = ?1",
        ).bind(id).fetch_one(service.db.pool_for_test()).await.unwrap();
        assert_eq!(preserved, (old_creator.to_owned(), old_date.to_owned()));
        let api = crate::orchestrator_api::CliApiClient::new(Arc::new(service));
        use catbird_mls::orchestrator::api_client::MLSAPIClient;
        let native = api.get_conversations(10, None).await.unwrap();
        assert_eq!(native.conversations[0].created_at, None);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn canonical_inventory_preserves_known_titles_across_distinct_local_stores() {
        use crate::orchestrator_api::CliApiClient;
        use crate::orchestrator_credentials::KeyringCredentialStore;
        use crate::orchestrator_storage::SqliteStorage;
        use catbird_mls::orchestrator::storage::MLSStorageBackend;
        use catbird_mls::orchestrator::{MLSOrchestrator, OrchestratorConfig};
        let mut service = test_service().await;
        service.db.store_session_value("mls_device_id", "device-1").await.unwrap();
        let group = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let ids = [
            "550e8400-e29b-41d4-a716-446655440001",
            "550e8400-e29b-41d4-a716-446655440002",
            "550e8400-e29b-41d4-a716-446655440003",
        ];
        let mut host = fixture_conversation(ids[1], group);
        host.name = Some("Known host title".into());
        service.db.store_conversation(&host).await.unwrap();
        let response = serde_json::json!({"items": ids.iter().map(|id| serde_json::json!({
            "state": canonical_state_fixture(id, group, false)
        })).collect::<Vec<_>>()});
        let router = axum::Router::new().route("/xrpc/blue.catbird.chat.getConversations",
            axum::routing::get(move || { let value = response.clone(); async move { axum::Json(value) } }));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        service.auth = AuthMethod::OAuth {
            session_cookie: "test-cookie".into(), did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(), nest_url: format!("http://{address}"),
        };
        let service = Arc::new(service);
        let native_dir = tempfile::tempdir().unwrap();
        let native_path = native_dir.path().join("title-store.db");
        let storage = Arc::new(SqliteStorage::new(native_path.to_str().unwrap(), "test-only").unwrap());
        for (index, id) in ids.iter().enumerate() {
            let stored_group = if index == 2 { "111102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" } else { group };
            storage.ensure_conversation_exists(service.did(), id, stored_group).await.unwrap();
            storage.update_metadata_json(id, r#"{"name":"Known native title","description":"Known description","avatar_url":null}"#, 1, "local", None, None).unwrap();
        }
        let orchestrator = Arc::new(MLSOrchestrator::new(
            service.mls.context().clone(), storage.clone(), Arc::new(CliApiClient::new(service.clone())),
            Arc::new(KeyringCredentialStore::new()), OrchestratorConfig::default(),
        ));
        let mut runtime_view = storage.get_conversation(service.did(), ids[0]).await.unwrap().unwrap();
        runtime_view.metadata.as_mut().unwrap().name = Some("Known runtime title".into());
        orchestrator.conversations().lock().await.insert(ids[0].into(), runtime_view);
        service.set_orchestrator(orchestrator.clone()).await;
        let rows = service.fetch_conversations().await.unwrap();
        assert_eq!(rows[0].name.as_deref(), Some("Known runtime title"));
        assert_eq!(rows[1].name.as_deref(), Some("Known host title"));
        assert_eq!(rows[2].name, None, "different group metadata must not bleed into current inventory");
        // The host persists a known title before a later inventory/cache miss.
        orchestrator.conversations().lock().await.clear();
        storage.update_metadata_json(ids[0], "{}", 2, "local", None, None).unwrap();
        let repeated = service.fetch_conversations().await.unwrap();
        assert_eq!(repeated[0].name.as_deref(), Some("Known runtime title"));
        assert_eq!(repeated[1].name.as_deref(), Some("Known host title"));
        let reloaded = service.db.list_conversations().await.unwrap();
        assert_eq!(reloaded.iter().find(|row| row.conversation_id == ids[0]).unwrap().name.as_deref(), Some("Known runtime title"));
        // An unavailable optional native metadata table cannot turn a valid
        // server inventory into an error or erase known host titles.
        let failing_store = rusqlite::Connection::open(&native_path).unwrap();
        failing_store.pragma_update(None, "key", "test-only").unwrap();
        failing_store.execute_batch("DROP TABLE conversations;").unwrap();
        // Refresh the reader connection's SQLite schema cache after the
        // external fixture DDL before asserting its prepare failure.
        let _ = storage.get_conversation(service.did(), ids[0]).await;
        assert!(storage.get_conversation(service.did(), ids[0]).await.is_err());
        let without_optional_metadata = service.fetch_conversations().await.unwrap();
        assert_eq!(without_optional_metadata.len(), 3);
        assert_eq!(without_optional_metadata[0].name.as_deref(), Some("Known runtime title"));
        assert_eq!(without_optional_metadata[1].name.as_deref(), Some("Known host title"));
        assert_eq!(without_optional_metadata[2].name, None);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn canonical_inventory_preserves_pending_and_active_admission_state_through_cli() {
        use catbird_mls::orchestrator::api_client::MLSAPIClient;
        use catbird_mls::orchestrator::canonical_transport::{decode_conversation_state, encode_conversation_state};
        let mut service = test_service().await;
        service.db.store_session_value("mls_device_id", "22222222-2222-4222-9222-222222222222").await.unwrap();
        service.handle_cache.write().await.insert("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(), "creator.test".into());
        let wire: Value = serde_json::from_str(include_str!("../../tests/fixtures/canonical-conversation-state.json")).unwrap();
        let shared = Arc::new(Mutex::new(wire));
        let response = shared.clone();
        let router = axum::Router::new().route("/xrpc/blue.catbird.chat.getConversations",
            axum::routing::get(move || {
                let state = response.lock().unwrap().clone();
                async move { axum::Json(serde_json::json!({"items": [{"state": state}]})) }
            }));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        service.auth = AuthMethod::OAuth {
            session_cookie: "test-cookie".into(), did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(), nest_url: format!("http://{address}"),
        };
        let api = crate::orchestrator_api::CliApiClient::new(Arc::new(service));
        for (status, version) in [("pending", 41), ("active", 42)] {
            let expected = {
                let mut state = shared.lock().unwrap();
                state["participants"][1]["status"] = serde_json::json!(status);
                state["coordinates"]["stateVersion"] = serde_json::json!(version);
                state["snapshotSeq"] = serde_json::json!(version + 4);
                decode_conversation_state(state.to_string().as_bytes()).unwrap()
            };
            let page = api.get_conversations(10, None).await.unwrap();
            let view = &page.conversations[0];
            assert_eq!(view.canonical_state.as_ref(), Some(&expected));
            assert_eq!(view.epoch, expected.coordinates.epoch as u64);
            assert_eq!(view.canonical_state.as_ref().unwrap().participants[1].leaf_count, 0);
            assert_eq!(decode_conversation_state(&encode_conversation_state(view.canonical_state.as_ref().unwrap()).unwrap()).unwrap(), expected);
        }
        shared.lock().unwrap()["participants"][1]["status"] = serde_json::json!("unknown");
        assert!(api.get_conversations(10, None).await.is_err());
        server.abort();
    }

    #[test]
    fn explicit_legacy_creation_metadata_is_preserved_without_clock_fallback() {
        let mut view = ConvoViewResp {
            conversation_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            group_id: "000102030405060708090a0b0c0d0e0f".into(),
            creator: "did:plc:creator".into(), epoch: 0,
            cipher_suite: crate::mls::MLS_CIPHER_SUITE.into(), members: vec![],
            created_at: "2026-09-05T02:34:00Z".into(), last_message_at: None, metadata: None,
        };
        let explicit = convo_resp_to_conversation(&view).unwrap();
        assert_eq!(explicit.creator.as_deref(), Some("did:plc:creator"));
        assert_eq!(explicit.created_at.unwrap().to_rfc3339(), "2026-09-05T02:34:00+00:00");
        view.creator.clear();
        view.created_at = "invalid date".into();
        let absent = convo_resp_to_conversation(&view).unwrap();
        assert_eq!(absent.creator, None);
        assert_eq!(absent.created_at, None);
    }

    #[tokio::test]
    async fn send_message_resolves_stable_conversation_id_before_mls_hex_decode() {
        let service = test_service().await;
        let conversation_id = uuid::Uuid::new_v4().to_string();
        let group_id = "000102030405060708090a0b0c0d0e0f";
        let conversation = fixture_conversation(&conversation_id, group_id);
        service
            .db
            .store_conversation(&conversation)
            .await
            .expect("store conversation");
        *service.conversations.write().await = vec![conversation];

        let error = service
            .send_message(&conversation_id, "hello")
            .await
            .expect_err("test MLS context has no group state");

        assert!(
            !error.to_string().contains("Invalid group ID hex"),
            "stable conversation IDs must be resolved before MLS hex decoding: {error}"
        );
    }

    #[test]
    fn service_mapper_preserves_every_commit_bearing_v2_entry() {
        use catbird_mls::chat_v2::wire::{COMMIT_ENTRY_KIND, LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND, LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND};
        for kind in [COMMIT_ENTRY_KIND, LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND, LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND] {
            let value = serde_json::json!({
                "$type": kind, "conversationId": "conversation", "entryId": "entry", "seq": 1,
                "signedRequest": {"body": {"commit": {"bytes": {"$bytes": BASE64.encode(b"commit")}}}},
            });
            let mapped: ConversationEntryResp = serde_json::from_value(value).unwrap();
            let ConversationEntryResp::Commit(commit) = mapped else { panic!("commit was dropped: {kind}") };
            assert_eq!(extract_commit_bytes(&commit).unwrap(), b"commit");
        }
        assert!(serde_json::from_value::<GetEntriesResp>(serde_json::json!({})).is_err());
    }

    #[tokio::test]
    async fn leave_without_orchestrator_preserves_conversation_and_reports_failure() {
        let service = test_service().await;
        let stable = "550e8400-e29b-41d4-a716-446655440000";
        let conversation = fixture_conversation(stable, "000102030405060708090a0b0c0d0e0f");
        service.db.store_conversation(&conversation).await.unwrap();
        *service.conversations.write().await = vec![conversation];
        let error = service.leave_conversation(stable).await.unwrap_err();
        assert!(error.to_string().contains("orchestrator unavailable"));
        assert_eq!(service.db.list_conversations().await.unwrap().len(), 1);
        assert_eq!(service.conversations().await.len(), 1);
    }

    #[tokio::test]
    async fn cli_resolution_keeps_stable_ids_and_rejects_ambiguous_names() {
        let service = test_service().await;
        let stable = "550e8400-e29b-41d4-a716-446655440000";
        let group = "000102030405060708090a0b0c0d0e0f";
        let mut first = fixture_conversation(stable, group);
        first.name = Some("friends".into());
        service.db.store_conversation(&first).await.unwrap();
        *service.conversations.write().await = vec![first.clone()];
        service.aliases.write().await.set("old-device".into(), group.into()).unwrap();
        for input in [stable, group, "friends", "old-device", "550e8400"] {
            assert_eq!(service.resolve_convo(input).await.unwrap(), stable);
        }
        assert_eq!(service.resolve_mls_group_id("friends").await.unwrap(), group);
        let mut second = fixture_conversation(
            "550e8400-e29b-41d4-a716-446655440001", "111102030405060708090a0b0c0d0e0f",
        );
        second.name = first.name.clone();
        service.db.store_conversation(&second).await.unwrap();
        service.conversations.write().await.push(second);
        for input in ["friends", "550e8400"] {
            assert!(service.resolve_convo(input).await.unwrap_err().to_string().contains("Ambiguous"));
        }
        assert_eq!(service.resolve_convo(stable).await.unwrap(), stable);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn send_uses_current_group_for_mls_and_stable_id_for_api_and_storage() {
        let mut service = test_service().await;
        let conversation_id = "550e8400-e29b-41d4-a716-446655440000";
        let group_id = "000102030405060708090a0b0c0d0e0f";
        let conversation = fixture_conversation(conversation_id, group_id);
        service
            .db
            .store_conversation(&conversation)
            .await
            .expect("store conversation");
        *service.conversations.write().await = vec![conversation];
        service
            .db
            .store_session_value("mls_device_id", "device-1")
            .await
            .expect("store device ID");

        // Provision only the current group ID. If the stable conversation ID
        // reaches MLS, encryption fails before the mock send endpoint runs.
        service
            .mls
            .with_context(|ctx| {
                ctx.create_group_with_id(
                    b"did:plc:test".to_vec(),
                    hex::decode(group_id).expect("group ID bytes"),
                    None,
                )
            })
            .expect("create MLS group");

        let captured = Arc::new(Mutex::new(None));
        let router = axum::Router::new()
            .route(
                "/xrpc/blue.catbird.chat.getEntries",
                axum::routing::get(mock_get_entries),
            )
            .route(
                "/xrpc/blue.catbird.chat.sendMessage",
                axum::routing::post(mock_send_message),
            )
            .with_state(Arc::clone(&captured));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock XRPC server");
        let address = listener.local_addr().expect("mock server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve mock XRPC");
        });
        service.auth = AuthMethod::OAuth {
            session_cookie: "test-cookie".to_string(),
            did: "did:plc:test".to_string(),
            nest_url: format!("http://{address}"),
        };

        let message = service
            .send_message(conversation_id, "hello")
            .await
            .expect("send through mock XRPC");
        server.abort();

        let request = captured
            .lock()
            .expect("capture lock")
            .clone()
            .expect("send request captured");
        assert_eq!(request["convoId"], conversation_id);
        assert!(request["ciphertext"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert_eq!(message.convo_id, conversation_id);
        let stored = service
            .db
            .get_messages(conversation_id, 1, None)
            .await
            .expect("load stored message");
        assert_eq!(stored[0].convo_id, conversation_id);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reaction_uses_current_group_for_mls_and_stable_id_for_api() {
        let mut service = test_service().await;
        let conversation_id = "550e8400-e29b-41d4-a716-446655440000";
        let group_id = "000102030405060708090a0b0c0d0e0f";
        let conversation = fixture_conversation(conversation_id, group_id);
        service
            .db
            .store_conversation(&conversation)
            .await
            .expect("store conversation");
        *service.conversations.write().await = vec![conversation];

        service
            .mls
            .with_context(|ctx| {
                ctx.create_group_with_id(
                    b"did:plc:test".to_vec(),
                    hex::decode(group_id).expect("group ID bytes"),
                    None,
                )
            })
            .expect("create MLS group");

        let captured = Arc::new(Mutex::new(None));
        let router = axum::Router::new()
            .route(
                "/xrpc/blue.catbird.chat.sendMessage",
                axum::routing::post(mock_send_message),
            )
            .with_state(Arc::clone(&captured));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock reaction server");
        let address = listener.local_addr().expect("mock reaction server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve mock reaction server");
        });
        service.auth = AuthMethod::OAuth {
            session_cookie: "test-cookie".to_string(),
            did: "did:plc:test".to_string(),
            nest_url: format!("http://{address}"),
        };

        service
            .send_reaction(conversation_id, "message-1", "🔥", false)
            .await
            .expect("send reaction through mock XRPC");
        server.abort();

        let request = captured
            .lock()
            .expect("capture lock")
            .clone()
            .expect("reaction request captured");
        assert_eq!(request["convoId"], conversation_id);
        assert!(request["ciphertext"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }

    async fn mock_get_conversations_missing_group_id() -> axum::Json<Value> {
        axum::Json(serde_json::json!({
            "items": [{
                "state": {
                    "coordinates": {
                        "conversationId": "550e8400-e29b-41d4-a716-446655440000",
                        "epoch": 0
                    },
                    "participants": []
                }
            }]
        }))
    }

    async fn mock_get_conversations_malformed_group_id() -> axum::Json<Value> {
        axum::Json(serde_json::json!({
            "items": [{
                "state": {
                    "coordinates": {
                        "conversationId": "550e8400-e29b-41d4-a716-446655440000",
                        "groupId": "not-hex",
                        "epoch": 0
                    },
                    "participants": []
                }
            }]
        }))
    }

    async fn fetch_conversations_error_for_route(
        handler: axum::routing::MethodRouter,
    ) -> CatmosError {
        let mut service = test_service().await;
        service
            .db
            .store_session_value("mls_device_id", "device-1")
            .await
            .expect("store device ID");
        let router = axum::Router::new().route("/xrpc/blue.catbird.chat.getConversations", handler);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind malformed conversation server");
        let address = listener.local_addr().expect("conversation server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve malformed conversation server");
        });
        service.auth = AuthMethod::OAuth {
            session_cookie: "test-cookie".to_string(),
            did: "did:plc:test".to_string(),
            nest_url: format!("http://{address}"),
        };

        let error = service
            .fetch_conversations()
            .await
            .expect_err("malformed conversation projection must fail closed");
        server.abort();
        error
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fetch_conversations_rejects_missing_group_id_without_stable_fallback() {
        let error = fetch_conversations_error_for_route(axum::routing::get(
            mock_get_conversations_missing_group_id,
        ))
        .await;
        assert!(
            error.to_string().contains("group ID"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fetch_conversations_rejects_malformed_group_id() {
        let error = fetch_conversations_error_for_route(axum::routing::get(
            mock_get_conversations_malformed_group_id,
        ))
        .await;
        assert!(
            error.to_string().contains("group ID"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn conversation_projection_rejects_group_id_reused_as_stable_id() {
        let group_id = "000102030405060708090a0b0c0d0e0f";
        let view = ConvoViewResp {
            group_id: group_id.to_string(),
            conversation_id: Some(group_id.to_string()),
            creator: "did:plc:test".to_string(),
            epoch: 0,
            cipher_suite: crate::mls::MLS_CIPHER_SUITE.to_string(),
            members: vec![],
            created_at: Utc::now().to_rfc3339(),
            last_message_at: None,
            metadata: None,
        };

        assert!(
            convo_resp_to_conversation(&view).is_err(),
            "a raw MLS group ID must not be accepted as the stable conversation ID"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_adopts_stable_projection_before_returning() {
        let mut service = test_service().await;
        let router = axum::Router::new()
            .route(
                "/xrpc/blue.catbird.chat.createConversation",
                axum::routing::post(mock_create_conversation),
            )
            .route(
                "/xrpc/blue.catbird.chat.submitTransition",
                axum::routing::post(mock_submit_transition),
            );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock create server");
        let address = listener.local_addr().expect("mock create server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve mock create server");
        });
        service.auth = AuthMethod::OAuth {
            session_cookie: "test-cookie".to_string(),
            did: "did:plc:test".to_string(),
            nest_url: format!("http://{address}"),
        };

        let created = service
            .create_conversation("", &[], None)
            .await
            .expect("create conversation");
        server.abort();

        assert_eq!(
            created.conversation_id,
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(
            service
                .db
                .list_conversations()
                .await
                .expect("list adopted conversation")
                .iter()
                .map(|conversation| conversation.conversation_id.as_str())
                .collect::<Vec<_>>(),
            vec!["550e8400-e29b-41d4-a716-446655440000"]
        );
        assert_eq!(
            service
                .conversations()
                .await
                .first()
                .map(|conversation| conversation.conversation_id.as_str()),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[tokio::test]
    async fn conversation_resolution_re_reads_durable_group_after_reset_remap() {
        let service = test_service().await;
        let conversation_id = "550e8400-e29b-41d4-a716-446655440000";
        let old_group_id = "000102030405060708090a0b0c0d0e0f";
        let new_group_id = "00112233445566778899aabbccddeeff";
        let old_conversation = fixture_conversation(conversation_id, old_group_id);
        service
            .db
            .store_conversation(&old_conversation)
            .await
            .expect("store initial conversation");
        *service.conversations.write().await = vec![old_conversation];

        let new_conversation = fixture_conversation(conversation_id, new_group_id);
        service
            .db
            .store_conversation(&new_conversation)
            .await
            .expect("store reset remap");

        let ids = service
            .resolve_conversation_ids(conversation_id)
            .await
            .expect("stable conversation remains resolvable");
        assert_eq!(ids, (conversation_id.to_string(), new_group_id.to_string()));
    }

    #[tokio::test]
    async fn conversation_resolution_rejects_missing_stable_id_after_refresh_failure() {
        let service = test_service().await;
        let stable_id = "550e8400-e29b-41d4-a716-446655440000";

        let error = service
            .resolve_conversation_ids(stable_id)
            .await
            .expect_err("unmatched stable ID must fail closed");
        assert!(
            error.to_string().contains("no authoritative mapping"),
            "missing stable IDs should report an authoritative mapping failure: {error}"
        );
    }

    #[tokio::test]
    async fn sync_conversation_propagates_malformed_current_group() {
        let service = test_service().await;
        let stable_id = "550e8400-e29b-41d4-a716-446655440000";
        service
            .db
            .store_conversation(&fixture_conversation(stable_id, "not-hex"))
            .await
            .expect("store malformed mapping fixture");

        let error = service
            .sync_conversation(stable_id)
            .await
            .expect_err("sync must not silently decode a malformed group ID");
        assert!(
            error.to_string().contains("group ID"),
            "sync should expose the malformed mapping error: {error}"
        );
    }

    #[tokio::test]
    async fn conversation_resolution_rebinds_stale_alias_to_current_group() {
        let service = test_service().await;
        let conversation_id = "550e8400-e29b-41d4-a716-446655440000";
        let old_group_id = "000102030405060708090a0b0c0d0e0f";
        let group_id = "00112233445566778899aabbccddeeff";
        let old_conversation = fixture_conversation(conversation_id, old_group_id);
        service
            .db
            .store_conversation(&old_conversation)
            .await
            .expect("store stale conversation");
        *service.conversations.write().await = vec![old_conversation];
        let current_conversation = fixture_conversation(conversation_id, group_id);
        service
            .db
            .store_conversation(&current_conversation)
            .await
            .expect("store current conversation");
        let mut aliases = AliasStore::with_path(
            service
                .test_tempdir
                .as_ref()
                .expect("owned test fixture")
                .path()
                .join("aliases.json"),
        );
        aliases
            .set("work".to_string(), old_group_id.to_string())
            .expect("persist stale alias fixture");
        *service.aliases.write().await = aliases;

        let result = service.resolve_conversation_ids("work").await;
        let ids = result.expect("stale alias resolves through durable conversation metadata");
        assert_eq!(ids, (conversation_id.to_string(), group_id.to_string()));
        assert_eq!(
            service.aliases.read().await.get("work").cloned(),
            Some(group_id.to_string())
        );
    }

    #[tokio::test]
    async fn load_local_messages_merges_stable_and_legacy_buckets_before_limit() {
        let service = test_service().await;
        let conversation_id = "550e8400-e29b-41d4-a716-446655440000";
        let group_id = "000102030405060708090a0b0c0d0e0f";
        let conversation = fixture_conversation(conversation_id, group_id);
        service
            .db
            .store_conversation(&conversation)
            .await
            .expect("store conversation");
        let legacy_conversation = fixture_conversation(group_id, group_id);
        service
            .db
            .store_conversation(&legacy_conversation)
            .await
            .expect("store legacy conversation bucket");
        *service.conversations.write().await = vec![conversation];

        let now = Utc::now();
        for (id, convo_id, seq, offset) in [
            ("legacy-1", group_id, 1, -3),
            ("legacy-2", group_id, 2, -2),
            ("stable-3", conversation_id, 3, -1),
        ] {
            service
                .db
                .store_message(&Message {
                    id: id.to_string(),
                    convo_id: convo_id.to_string(),
                    sender_did: Some("did:plc:test".to_string()),
                    content: MessageContent::Text(id.to_string()),
                    epoch: 0,
                    seq,
                    created_at: now + chrono::Duration::minutes(offset),
                })
                .await
                .expect("store message");
        }

        let messages = service
            .load_local_messages(conversation_id, 3)
            .await
            .expect("load merged history");
        assert_eq!(
            messages
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            vec!["legacy-1", "legacy-2", "stable-3"]
        );
        assert!(messages
            .iter()
            .all(|message| message.convo_id == conversation_id));
        let legacy_stored = service
            .db
            .get_messages(group_id, 3, None)
            .await
            .expect("load legacy bucket directly");
        assert!(legacy_stored
            .iter()
            .all(|message| message.convo_id == group_id));
    }

    #[tokio::test]
    async fn load_local_messages_reopens_two_reset_history_with_source_aad_and_hmac() {
        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let root = tempfile::tempdir().expect("temporary history directory");
        let db_path = root.path().join("history.db");
        let stable_id = "550e8400-e29b-41d4-a716-446655440000";
        let groups = [
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "102132435465768798a9bacbdcedfe0f",
        ];
        let db = Arc::new(
            Database::open_unencrypted(&db_path)
                .await
                .expect("open history database"),
        );
        db.set_content_root_key(vec![0x44; 32]);
        let mls = Arc::new(
            MlsManager::new(&root.path().join("mls"), "did:plc:test").expect("MLS manager"),
        );
        let service = ChatService::new(
            AuthMethod::OAuth {
                session_cookie: "test-cookie".to_string(),
                did: "did:plc:test".to_string(),
                nest_url: "http://127.0.0.1:1".to_string(),
            },
            None,
            mls,
            Arc::clone(&db),
            Config::default(),
            Arc::new(RwLock::new(AliasStore::with_path(
                root.path().join("aliases.json"),
            ))),
        );
        let now = Utc::now();
        for (index, group_id) in groups.iter().enumerate() {
            db.store_conversation(&fixture_conversation(stable_id, group_id))
                .await
                .expect("store reset projection");
            // The legacy schema keeps a foreign key from each message source
            // bucket to a conversation row.  Keep a source projection for
            // the historical group as well; the alias table is what binds
            // it back to the stable owner after reopening.
            db.store_conversation(&fixture_conversation(group_id, group_id))
                .await
                .expect("store source projection");
            db.store_message(&Message {
                id: format!("history-{}", index + 1),
                convo_id: group_id.to_string(),
                sender_did: Some("did:plc:test".to_string()),
                content: MessageContent::Text(format!("history-{}", index + 1)),
                epoch: index as u64,
                seq: index as u64 + 1,
                created_at: now + chrono::Duration::minutes(index as i64),
            })
            .await
            .expect("store source-keyed message");
        }
        db.store_message(&Message {
            id: "history-4".to_string(),
            convo_id: groups[2].to_string(),
            sender_did: Some("did:plc:test".to_string()),
            content: MessageContent::Text("history-4".to_string()),
            epoch: 3,
            seq: 4,
            created_at: now + chrono::Duration::minutes(3),
        })
        .await
        .expect("store second message in latest source bucket");

        drop(service);
        drop(db);

        let reopened_db = Arc::new(
            Database::open_unencrypted(&db_path)
                .await
                .expect("reopen history database"),
        );
        reopened_db.set_content_root_key(vec![0x44; 32]);
        let reopened = ChatService::new(
            AuthMethod::OAuth {
                session_cookie: "test-cookie".to_string(),
                did: "did:plc:test".to_string(),
                nest_url: "http://127.0.0.1:1".to_string(),
            },
            None,
            Arc::new(
                MlsManager::new(&root.path().join("reopened-mls"), "did:plc:test")
                    .expect("reopened MLS manager"),
            ),
            Arc::clone(&reopened_db),
            Config::default(),
            Arc::new(RwLock::new(AliasStore::with_path(
                root.path().join("reopened-aliases.json"),
            ))),
        );

        let legacy_ids = reopened
            .resolve_conversation_ids(groups[0])
            .await
            .expect("legacy source resolves through stable owner");
        assert_eq!(
            legacy_ids,
            (stable_id.to_string(), groups[2].to_string()),
            "legacy history input must route to the current group"
        );

        let history = reopened
            .load_local_messages(stable_id, 3)
            .await
            .expect("load all retained reset buckets");
        assert_eq!(
            history
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            vec!["history-2", "history-3", "history-4"]
        );
        assert!(history.iter().all(|message| message.convo_id == stable_id));

        let source_history = reopened_db
            .get_messages(groups[0], 10, None)
            .await
            .expect("decrypt first source bucket with original AAD");
        assert_eq!(source_history[0].convo_id, groups[0]);
        assert_eq!(
            reopened_db
                .get_messages(groups[2], 1, None)
                .await
                .expect("latest-page read")
                .len(),
            1
        );
        let before_latest = reopened_db
            .get_messages(groups[2], 10, Some(3))
            .await
            .expect("before-sequence page read");
        assert!(before_latest.is_empty(), "seq 3 is excluded by the cursor");
        let before_end = reopened_db
            .get_messages(groups[2], 10, Some(4))
            .await
            .expect("before-end page read");
        assert_eq!(before_end[0].id, "history-3");

        sqlx::query("UPDATE messages SET entry_hmac = zeroblob(32) WHERE id = ?1")
            .bind("history-2")
            .execute(reopened_db.pool_for_test())
            .await
            .expect("tamper test row");
        assert!(reopened_db.get_messages(groups[1], 10, None).await.is_err());
    }

    #[test]
    fn merge_message_buckets_deduplicates_before_limit_without_rewriting_aad_ids() {
        let stable_convo_id = "550e8400-e29b-41d4-a716-446655440000";
        let legacy_convo_id = "000102030405060708090a0b0c0d0e0f";
        let now = Utc::now();
        let message = |id: &str, convo_id: &str, seq: u64, offset: i64, text: &str| Message {
            id: id.to_string(),
            convo_id: convo_id.to_string(),
            sender_did: Some("did:plc:test".to_string()),
            content: MessageContent::Text(text.to_string()),
            epoch: 0,
            seq,
            created_at: now + chrono::Duration::minutes(offset),
        };

        let merged = merge_message_buckets(
            vec![
                vec![
                    message("duplicate", stable_convo_id, 2, -2, "stable copy"),
                    message("newest", stable_convo_id, 3, -1, "newest"),
                ],
                vec![
                    message("oldest", legacy_convo_id, 1, -3, "oldest"),
                    message("duplicate", legacy_convo_id, 2, -2, "stable copy"),
                ],
            ],
            stable_convo_id,
            3,
        )
        .expect("identical duplicate IDs are safe to merge");

        assert_eq!(
            merged
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            vec!["oldest", "duplicate", "newest"]
        );
        assert_eq!(merged[1].convo_id, stable_convo_id);
        assert!(matches!(
            &merged[1].content,
            MessageContent::Text(text) if text == "stable copy"
        ));
        assert_eq!(
            merged.len(),
            3,
            "duplicate IDs must count once before limit"
        );
    }

    #[test]
    fn merge_message_buckets_uses_confirmed_sequence_then_pending_timestamp() {
        let now = Utc::now();
        let message = |id: &str, seq, offset| Message {
            id: id.into(), convo_id: "source-bucket".into(), sender_did: Some("did:plc:test".into()),
            content: MessageContent::Text(id.into()), epoch: 1, seq,
            created_at: now + chrono::Duration::milliseconds(offset),
        };
        let merged = merge_message_buckets(vec![
            vec![message("own-10", 10, 500), message("pending-between-b", 0, 450), message("pending-after", 0, 1000)],
            vec![message("peer-11", 11, 409), message("pending-before", 0, 0), message("pending-between-a", 0, 450)],
        ], "stable-conversation", 50).unwrap();
        assert_eq!(merged.iter().map(|message| message.id.as_str()).collect::<Vec<_>>(),
            ["own-10", "peer-11", "pending-before", "pending-between-a", "pending-between-b", "pending-after"]);
        assert!(merged.iter().all(|message| message.convo_id == "stable-conversation"));
    }

    #[test]
    fn merge_message_buckets_rejects_conflicting_duplicate_ids() {
        let message = |convo_id: &str, text: &str| Message {
            id: "duplicate".to_string(),
            convo_id: convo_id.to_string(),
            sender_did: Some("did:plc:test".to_string()),
            content: MessageContent::Text(text.to_string()),
            epoch: 0,
            seq: 1,
            created_at: Utc::now(),
        };

        let result = merge_message_buckets(
            vec![
                vec![message("stable", "one")],
                vec![message("legacy", "two")],
            ],
            "stable",
            10,
        );
        assert!(
            result.is_err(),
            "conflicting duplicate IDs must fail closed"
        );
    }
}
