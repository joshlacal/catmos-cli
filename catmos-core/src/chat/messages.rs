use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::warn;

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

// ── XRPC request/response structs ───────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendMessageRequest {
    group_id: String,
    ciphertext: String, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendMessageResponse {
    message_id: String,
    seq: u64,
    epoch: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetConvosResponse {
    conversations: Vec<ConvoEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConvoEntry {
    group_id: String,
    name: Option<String>,
    description: Option<String>,
    creator: String,
    epoch: u64,
    cipher_suite: Option<String>,
    members: Option<Vec<MemberEntry>>,
    created_at: Option<String>,
    last_message_at: Option<String>,
    unread_count: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberEntry {
    did: String,
    user_did: Option<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    is_admin: Option<bool>,
    is_moderator: Option<bool>,
    joined_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetMessagesResponse {
    messages: Vec<MessageEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageEntry {
    message_id: String,
    group_id: String,
    sender_did: Option<String>,
    ciphertext: String, // base64
    epoch: u64,
    seq: u64,
    created_at: Option<String>,
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

        // Encrypt via MLS — ciphertext padding is handled by the MLS layer
        let group_id_bytes = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;

        let encrypt_result = self.mls.with_context(|ctx| {
            ctx.encrypt_message(group_id_bytes.clone(), plaintext.clone())
        })?;

        let ciphertext_b64 = BASE64.encode(&encrypt_result.ciphertext);

        // Send via XRPC
        let req = SendMessageRequest {
            group_id: convo_id.to_string(),
            ciphertext: ciphertext_b64,
            delivery: None,
            action: None,
        };
        let resp: SendMessageResponse = self
            .xrpc_procedure("blue.catbird.mlsChat.sendMessage", &req)
            .await?;

        let msg = Message {
            id: resp.message_id,
            convo_id: convo_id.to_string(),
            sender_did: Some(self.did().to_string()),
            content: MessageContent::Text(text.to_string()),
            epoch: resp.epoch,
            seq: resp.seq,
            created_at: Utc::now(),
        };

        // Store locally
        self.db.store_message(&msg)?;

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
        let ciphertext_b64 = BASE64.encode(&noop);

        let req = SendMessageRequest {
            group_id: convo_id.to_string(),
            ciphertext: ciphertext_b64,
            delivery: Some("ephemeral".to_string()),
            action: Some(action.to_string()),
        };

        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.mlsChat.sendMessage", &req)
            .await?;

        Ok(())
    }

    /// Fetch all conversations from the server, decrypt metadata, and cache locally.
    pub async fn fetch_conversations(&self) -> Result<Vec<Conversation>> {
        let resp: GetConvosResponse = self
            .xrpc_query("blue.catbird.mlsChat.getConvos", &[])
            .await?;

        let mut convos = Vec::with_capacity(resp.conversations.len());
        for entry in resp.conversations {
            let members = entry
                .members
                .unwrap_or_default()
                .into_iter()
                .map(|m| Member {
                    did: m.did,
                    user_did: m.user_did.unwrap_or_default(),
                    device_id: m.device_id,
                    device_name: m.device_name,
                    is_admin: m.is_admin.unwrap_or(false),
                    is_moderator: m.is_moderator.unwrap_or(false),
                    joined_at: m
                        .joined_at
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(Utc::now),
                })
                .collect();

            let convo = Conversation {
                group_id: entry.group_id,
                name: entry.name,
                description: entry.description,
                creator: entry.creator,
                epoch: entry.epoch,
                cipher_suite: entry
                    .cipher_suite
                    .unwrap_or_else(|| "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into()),
                members,
                created_at: entry
                    .created_at
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now),
                last_message_at: entry.last_message_at.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                }),
                unread_count: entry.unread_count.unwrap_or(0),
                alias: None,
            };

            // Persist to local DB
            if let Err(e) = self.db.store_conversation(&convo) {
                warn!("Failed to store conversation {}: {e}", convo.group_id);
            }

            convos.push(convo);
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
        let resp: GetMessagesResponse = self
            .xrpc_query(
                "blue.catbird.mlsChat.getMessages",
                &[("groupId", convo_id), ("limit", &limit_str)],
            )
            .await?;

        let mut messages = Vec::with_capacity(resp.messages.len());
        for entry in resp.messages {
            let ciphertext = BASE64
                .decode(&entry.ciphertext)
                .map_err(|e| CatmosError::Other(format!("Invalid base64 ciphertext: {e}")))?;

            match self.decrypt_message(&entry.group_id, &ciphertext) {
                Ok((plaintext, sender_did)) => {
                    let content = parse_message_content(&plaintext);
                    let msg = Message {
                        id: entry.message_id,
                        convo_id: entry.group_id,
                        sender_did: sender_did.or(entry.sender_did),
                        content,
                        epoch: entry.epoch,
                        seq: entry.seq,
                        created_at: entry
                            .created_at
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(Utc::now),
                    };
                    if let Err(e) = self.db.store_message(&msg) {
                        warn!("Failed to store message {}: {e}", msg.id);
                    }
                    messages.push(msg);
                }
                Err(e) => {
                    warn!(
                        "Failed to decrypt message {} in {}: {e}",
                        entry.message_id, entry.group_id
                    );
                    // Store as unknown content so we don't lose the message record
                    let msg = Message {
                        id: entry.message_id,
                        convo_id: entry.group_id,
                        sender_did: entry.sender_did,
                        content: MessageContent::System(format!("[Decryption failed: {e}]")),
                        epoch: entry.epoch,
                        seq: entry.seq,
                        created_at: entry
                            .created_at
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(Utc::now),
                    };
                    if let Err(e) = self.db.store_message(&msg) {
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
        // Determine message type — iOS uses "messageType", legacy used "type"
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
