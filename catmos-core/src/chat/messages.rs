use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::warn;

use catbird_atproto::catbird::mls_chat;

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
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConvoViewResp {
    pub group_id: String,
    pub creator: String,
    pub epoch: i64,
    pub cipher_suite: String,
    pub members: Vec<MemberViewResp>,
    pub created_at: String,
    #[serde(default)]
    pub last_message_at: Option<String>,
    #[serde(default)]
    pub metadata: Option<ConvoMetadataResp>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConvoMetadataResp {
    pub name: Option<String>,
    pub description: Option<String>,
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
        group_id: view.group_id.clone(),
        name: view.metadata.as_ref().and_then(|m| m.name.clone()),
        description: view.metadata.as_ref().and_then(|m| m.description.clone()),
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
    pub async fn send_message(&self, convo_id: &str, text: &str) -> Result<Message> {
        // Build the plaintext payload (matches iOS MLSMessagePayload format)
        let payload = MlsMessagePayload::text(text);
        let plaintext = serde_json::to_vec(&payload)?;

        // Encrypt via MLS -- ciphertext padding is handled by the MLS layer
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let encrypt_result = self.mls.with_context(|ctx| {
            ctx.encrypt_message(group_id_bytes.clone(), plaintext.clone())
        })?;

        let epoch = self.get_epoch(convo_id).unwrap_or(0);
        let msg_id = ulid::Ulid::new().to_string();
        let padded_size = encrypt_result.ciphertext.len() as i64;

        // Build the generated SendMessage input using the convenience wrapper
        let req: mls_chat::send_message::Input =
            mls_chat::send_message::InputData {
                convo_id: convo_id.to_string(),
                ciphertext: encrypt_result.ciphertext.clone(),
                epoch: epoch as usize,
                msg_id: msg_id.clone(),
                padded_size,
                delivery: None,
            }
            .into();

        let resp: SendMessageResp = self
            .xrpc_procedure(mls_chat::send_message::NSID, &req)
            .await?;

        let msg = Message {
            id: resp.message_id,
            convo_id: convo_id.to_string(),
            sender_did: Some(self.did().to_string()),
            content: MessageContent::Text(text.to_string()),
            epoch: resp.epoch as u64,
            seq: resp.seq as u64,
            created_at: Utc::now(),
        };

        // Store locally
        self.db.store_message(&msg).await?;

        Ok(msg)
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
        let action = if is_typing {
            "typing"
        } else {
            "typingStop"
        };

        // Use a 512-byte no-op ciphertext for ephemeral messages
        let noop = vec![0u8; 512];
        let msg_id = ulid::Ulid::new().to_string();

        let mut req: mls_chat::send_message::Input =
            mls_chat::send_message::InputData {
                convo_id: convo_id.to_string(),
                ciphertext: noop,
                epoch: 0,
                msg_id,
                padded_size: 512,
                delivery: Some("ephemeral".to_string()),
            }
            .into();
        req.action = Some(action.into());

        let _: serde_json::Value = self
            .xrpc_procedure(mls_chat::send_message::NSID, &req)
            .await?;

        Ok(())
    }

    /// Fetch all conversations from the server, decrypt metadata, and cache locally.
    pub async fn fetch_conversations(&self) -> Result<Vec<Conversation>> {
        let resp: GetConvosResp = self
            .xrpc_query(mls_chat::get_convos::NSID, &[])
            .await?;

        let convos: Vec<Conversation> = resp
            .conversations
            .iter()
            .map(convo_resp_to_conversation)
            .collect();

        // Persist to local DB
        for convo in &convos {
            if let Err(e) = self.db.store_conversation(convo).await {
                warn!("Failed to store conversation {}: {e}", convo.group_id);
            }
        }

        // Update cached conversations
        *self.conversations.write().await = convos.clone();

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

    /// Fetch messages for a conversation from the server, decrypt each, and store locally.
    pub async fn fetch_messages(
        &self,
        convo_id: &str,
        limit: u32,
    ) -> Result<Vec<Message>> {
        let limit_str = limit.to_string();
        let resp: GetMessagesResp = self
            .xrpc_query(
                mls_chat::get_messages::NSID,
                &[("convoId", convo_id), ("limit", &limit_str)],
            )
            .await?;

        let mut messages = Vec::with_capacity(resp.messages.len());
        for entry in &resp.messages {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&entry.ciphertext.bytes)
                .map_err(|e| CatmosError::Other(format!("Invalid base64 ciphertext: {e}")))?;

            match self.decrypt_message(&entry.convo_id, &ciphertext) {
                Ok((plaintext, sender_did)) => {
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
                    warn!(
                        "Failed to decrypt message {} in {}: {e}",
                        entry.id, entry.convo_id
                    );
                    // Store as unknown content so we don't lose the message record
                    let msg = Message {
                        id: entry.id.clone(),
                        convo_id: entry.convo_id.clone(),
                        sender_did: None,
                        content: MessageContent::System(format!("[Decryption failed: {e}]")),
                        epoch: entry.epoch as u64,
                        seq: entry.seq as u64,
                        created_at: chrono::DateTime::parse_from_rfc3339(&entry.created_at)
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                    };
                    if let Err(e) = self.db.store_message(&msg).await {
                        warn!("Failed to store message: {e}");
                    }
                    messages.push(msg);
                }
            }
        }

        Ok(messages)
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
                        r.get("action")
                            .and_then(|a| a.as_str())
                            .unwrap_or("add"),
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
                        v.get("action")
                            .and_then(|a| a.as_str())
                            .unwrap_or("add"),
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
