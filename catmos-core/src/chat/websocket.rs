use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite;
use tracing::{debug, error, info, warn};

use super::service::ChatService;
use crate::error::{CatmosError, Result};

/// Events emitted by the WebSocket subscription.
#[derive(Debug, Clone)]
pub enum WsEvent {
    /// A new message was received (convo_id, plaintext, sender_did).
    Message {
        convo_id: String,
        plaintext: String,
        sender_did: Option<String>,
        message_id: String,
        epoch: u64,
        seq: u64,
    },
    /// Typing indicator (convo_id, sender_did, is_typing).
    Typing {
        convo_id: String,
        sender_did: String,
        is_typing: bool,
    },
    /// A member joined a conversation.
    MemberJoined {
        convo_id: String,
        member_did: String,
    },
    /// A member left a conversation.
    MemberLeft {
        convo_id: String,
        member_did: String,
    },
    /// The MLS epoch advanced for a conversation.
    EpochAdvanced { convo_id: String, new_epoch: u64 },
    /// A reaction was received.
    Reaction {
        convo_id: String,
        message_id: String,
        emoji: String,
        sender_did: String,
    },
    /// An error occurred on the WebSocket.
    Error(String),
    /// The WebSocket is reconnecting.
    Reconnecting,
}

// ── Server-side event types ─────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionTicketResponse {
    ticket: String,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ServerEvent {
    #[serde(rename = "message")]
    Message {
        group_id: String,
        message_id: String,
        sender_did: Option<String>,
        ciphertext: String,
        epoch: u64,
        seq: u64,
    },
    #[serde(rename = "typing")]
    Typing {
        group_id: String,
        sender_did: String,
        is_typing: bool,
    },
    #[serde(rename = "memberJoined")]
    MemberJoined {
        group_id: String,
        member_did: String,
    },
    #[serde(rename = "memberLeft")]
    MemberLeft {
        group_id: String,
        member_did: String,
    },
    #[serde(rename = "epochAdvanced")]
    EpochAdvanced {
        group_id: String,
        new_epoch: u64,
    },
    #[serde(rename = "reaction")]
    Reaction {
        group_id: String,
        message_id: String,
        emoji: String,
        sender_did: String,
    },
}

impl ChatService {
    /// Subscribe to real-time events via WebSocket.
    ///
    /// Returns an unbounded receiver that emits `WsEvent`s. The WebSocket
    /// reader runs in a background task and will emit `Reconnecting` / `Error`
    /// events if the connection drops.
    pub async fn subscribe(&self) -> Result<mpsc::UnboundedReceiver<WsEvent>> {
        // 1. Get a subscription ticket
        let ticket_resp: SubscriptionTicketResponse = self
            .xrpc_query("blue.catbird.mlsChat.getSubscriptionTicket", &[])
            .await?;
        let ticket = ticket_resp.ticket;

        // 2. Build WebSocket URL
        let ws_base = self
            .config
            .server
            .mls_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let ws_url = format!(
            "{ws_base}/xrpc/blue.catbird.mlsChat.subscribe?ticket={ticket}"
        );

        debug!("Connecting WebSocket to {ws_url}");

        // 3. Connect
        let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| CatmosError::WebSocket(format!("Connection failed: {e}")))?;

        info!("WebSocket connected");

        let (mut write, mut read) = ws_stream.split();
        let (tx, rx) = mpsc::unbounded_channel();

        // Clone what the background task needs
        let mls = self.mls.clone();

        // 4. Spawn reader task
        tokio::spawn(async move {
            while let Some(msg_result) = read.next().await {
                match msg_result {
                    Ok(tungstenite::Message::Text(text)) => {
                        match serde_json::from_str::<ServerEvent>(&text) {
                            Ok(event) => {
                                let ws_event = process_server_event(event, &mls);
                                if tx.send(ws_event).is_err() {
                                    debug!("WsEvent receiver dropped, stopping reader");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse WebSocket event: {e} — raw: {text}");
                            }
                        }
                    }
                    Ok(tungstenite::Message::Ping(data)) => {
                        if let Err(e) = write.send(tungstenite::Message::Pong(data)).await {
                            warn!("Failed to send pong: {e}");
                        }
                    }
                    Ok(tungstenite::Message::Close(_)) => {
                        info!("WebSocket closed by server");
                        let _ = tx.send(WsEvent::Reconnecting);
                        break;
                    }
                    Err(e) => {
                        error!("WebSocket error: {e}");
                        let _ = tx.send(WsEvent::Error(e.to_string()));
                        break;
                    }
                    _ => {} // Binary, Frame — ignore
                }
            }
        });

        Ok(rx)
    }
}

/// Convert a parsed server event into a `WsEvent`, decrypting message
/// ciphertext where applicable.
fn process_server_event(
    event: ServerEvent,
    mls: &std::sync::Arc<crate::mls::MlsManager>,
) -> WsEvent {
    match event {
        ServerEvent::Message {
            group_id,
            message_id,
            sender_did,
            ciphertext,
            epoch,
            seq,
        } => {
            let ct_bytes = match BASE64.decode(&ciphertext) {
                Ok(b) => b,
                Err(e) => {
                    return WsEvent::Error(format!("Invalid base64 ciphertext: {e}"));
                }
            };

            let gid_bytes = match hex::decode(&group_id) {
                Ok(b) => b,
                Err(e) => {
                    return WsEvent::Error(format!("Invalid group ID hex: {e}"));
                }
            };

            match mls.with_context(|ctx| ctx.decrypt_message(gid_bytes, ct_bytes)) {
                Ok(result) => {
                    let unpadded = {
                        let end = result
                            .plaintext
                            .iter()
                            .rposition(|&b| b != 0)
                            .map_or(0, |i| i + 1);
                        &result.plaintext[..end]
                    };
                    let plaintext = String::from_utf8_lossy(unpadded).to_string();
                    let decrypted_sender = if !result.sender_credential.identity.is_empty() {
                        Some(
                            String::from_utf8_lossy(&result.sender_credential.identity).to_string(),
                        )
                    } else {
                        sender_did
                    };

                    WsEvent::Message {
                        convo_id: group_id,
                        plaintext,
                        sender_did: decrypted_sender,
                        message_id,
                        epoch,
                        seq,
                    }
                }
                Err(e) => {
                    warn!("Failed to decrypt WS message {message_id}: {e}");
                    WsEvent::Error(format!("Decrypt failed for {message_id}: {e}"))
                }
            }
        }
        ServerEvent::Typing {
            group_id,
            sender_did,
            is_typing,
        } => WsEvent::Typing {
            convo_id: group_id,
            sender_did,
            is_typing,
        },
        ServerEvent::MemberJoined {
            group_id,
            member_did,
        } => WsEvent::MemberJoined {
            convo_id: group_id,
            member_did,
        },
        ServerEvent::MemberLeft {
            group_id,
            member_did,
        } => WsEvent::MemberLeft {
            convo_id: group_id,
            member_did,
        },
        ServerEvent::EpochAdvanced {
            group_id,
            new_epoch,
        } => WsEvent::EpochAdvanced {
            convo_id: group_id,
            new_epoch,
        },
        ServerEvent::Reaction {
            group_id,
            message_id,
            emoji,
            sender_did,
        } => WsEvent::Reaction {
            convo_id: group_id,
            message_id,
            emoji,
            sender_did,
        },
    }
}
