use catbird_atproto::blue_catbird::mlsChat::subscribe_events::SubscribeEventsMessage;
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

/// Thin owned wrapper for the getSubscriptionTicket response.
/// The generated `GetSubscriptionTicketOutput` uses lifetime parameters and
/// `CowStr<'a>`, so it cannot be used with `DeserializeOwned`-based flows.
/// We keep this minimal owned version matching the generated field names.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionTicketResponse {
    ticket: String,
    endpoint: Option<String>,
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
            .xrpc_procedure("blue.catbird.mlsChat.getSubscriptionTicket", &serde_json::json!({}))
            .await?;
        let ticket = ticket_resp.ticket;

        // 2. Build WebSocket URL from the endpoint returned by the server
        let endpoint = ticket_resp.endpoint.unwrap_or_else(|| {
            let base = self.config.server.mls_url.clone();
            format!("{base}/xrpc/blue.catbird.mlsChat.subscribeEvents?ticket={ticket}")
        });

        // Ensure WSS protocol and ticket is in the URL
        let ws_url = if endpoint.contains("ticket=") {
            endpoint
                .replace("https://", "wss://")
                .replace("http://", "ws://")
        } else {
            let sep = if endpoint.contains('?') { "&" } else { "?" };
            format!("{}{sep}ticket={ticket}", endpoint
                .replace("https://", "wss://")
                .replace("http://", "ws://"))
        };

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
                    Ok(tungstenite::Message::Binary(data)) => {
                        match SubscribeEventsMessage::decode_framed(&data) {
                            Ok(event) => {
                                let ws_event = convert_event(event, &mls);
                                if tx.send(ws_event).is_err() {
                                    debug!("WsEvent receiver dropped, stopping reader");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to decode WebSocket frame: {e}");
                            }
                        }
                    }
                    Ok(tungstenite::Message::Text(text)) => {
                        // JSON text fallback — attempt to decode as a framed
                        // message via serde_json. The generated enum is tagged
                        // on $type which matches the JSON text format.
                        warn!("Received unexpected text frame, ignoring: {text}");
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
                    _ => {} // Frame — ignore
                }
            }
        });

        Ok(rx)
    }
}

/// Convert a decoded `SubscribeEventsMessage` into a `WsEvent`, decrypting
/// message ciphertext where applicable.
fn convert_event(
    event: SubscribeEventsMessage<'_>,
    mls: &std::sync::Arc<crate::mls::MlsManager>,
) -> WsEvent {
    match event {
        SubscribeEventsMessage::MessageEvent(msg_event) => {
            let mv = &msg_event.message;
            let convo_id = mv.convo_id.to_string();
            let message_id = mv.id.to_string();
            let epoch = mv.epoch as u64;
            let seq = mv.seq as u64;

            // ciphertext is already bytes::Bytes — no base64 decode needed
            let ct_bytes = mv.ciphertext.to_vec();

            let gid_bytes = match hex::decode(&convo_id) {
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
                    let sender_did = if !result.sender_credential.identity.is_empty() {
                        Some(
                            String::from_utf8_lossy(&result.sender_credential.identity).to_string(),
                        )
                    } else {
                        None
                    };

                    WsEvent::Message {
                        convo_id,
                        plaintext,
                        sender_did,
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
        SubscribeEventsMessage::TypingEvent(evt) => WsEvent::Typing {
            convo_id: evt.convo_id.to_string(),
            sender_did: evt.did.to_string(),
            is_typing: evt.is_typing,
        },
        SubscribeEventsMessage::MemberJoined(evt) => WsEvent::MemberJoined {
            convo_id: evt.convo_id.to_string(),
            member_did: evt.did.to_string(),
        },
        SubscribeEventsMessage::MemberLeft(evt) => WsEvent::MemberLeft {
            convo_id: evt.convo_id.to_string(),
            member_did: evt.did.to_string(),
        },
        SubscribeEventsMessage::EpochAdvanced(evt) => WsEvent::EpochAdvanced {
            convo_id: evt.convo_id.to_string(),
            new_epoch: evt.epoch as u64,
        },
        SubscribeEventsMessage::ReactionEvent(evt) => WsEvent::Reaction {
            convo_id: evt.convo_id.to_string(),
            message_id: evt.message_id.to_string(),
            emoji: evt.reaction.to_string(),
            sender_did: evt.did.to_string(),
        },
        _ => {
            // ConversationUpdated, NewDeviceEvent, InfoEvent — ignore
            debug!("Ignoring non-essential subscription event");
            WsEvent::Error("ignored event".into())
        }
    }
}
