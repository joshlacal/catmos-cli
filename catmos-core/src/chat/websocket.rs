use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite;
use tracing::{debug, error, info, warn};

// ── DAG-CBOR frame types ──────────────────────────────────────────────

/// Header portion of a DAG-CBOR WebSocket frame from mls-ds.
#[derive(serde::Serialize, Deserialize, Debug)]
struct FrameHeader {
    op: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    t: Option<String>,
}

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
                        // DAG-CBOR frame: header + payload concatenated
                        match parse_dagcbor_frame(&data) {
                            Ok(event) => {
                                let ws_event = process_server_event(event, &mls);
                                if tx.send(ws_event).is_err() {
                                    debug!("WsEvent receiver dropped, stopping reader");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse DAG-CBOR WebSocket frame: {e}");
                            }
                        }
                    }
                    Ok(tungstenite::Message::Text(text)) => {
                        // JSON text fallback (e.g. when server sends format=json)
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
                    _ => {} // Frame — ignore
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

// ── DAG-CBOR payload types ─────────────────────────────────────────────
//
// The mls-ds server sends events as DAG-CBOR binary frames. Each frame is
// two concatenated CBOR objects: a header and a payload. The payload contains
// the event fields with `ciphertext` as CBOR byte strings (not base64).

/// Message view nested inside a `#messageEvent` payload.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CborMessageView {
    id: String,
    convo_id: String,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
    epoch: i64,
    seq: i64,
    #[serde(default)]
    message_type: Option<String>,
}

/// Payload for `#messageEvent`
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct CborMessageEventPayload {
    message: CborMessageView,
    #[serde(default)]
    ephemeral: bool,
    #[serde(default)]
    seq: i64,
}

/// Payload for `#reactionEvent`
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CborReactionEventPayload {
    convo_id: String,
    message_id: String,
    did: String,
    reaction: String,
    #[serde(default)]
    action: Option<String>,
}

/// Payload for `#typingEvent`
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CborTypingEventPayload {
    convo_id: String,
    did: String,
    is_typing: bool,
}

/// Payload for `#membershipChangeEvent`
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CborMembershipChangePayload {
    convo_id: Option<String>,
    group_id: Option<String>,
    did: Option<String>,
    member_did: Option<String>,
    #[serde(default)]
    action: Option<String>,
}

/// Parse a binary DAG-CBOR frame from the mls-ds WebSocket.
///
/// The frame is two concatenated DAG-CBOR objects:
/// 1. Header: `{ op: i32, t: Option<String> }` — op=1 means message, op=-1 means error
/// 2. Payload: the event data with a `seq` field
///
/// We use `ciborium::de::from_reader` with a `Cursor` so it reads exactly one
/// CBOR object and advances the cursor, letting us parse the payload from the
/// remaining bytes. `serde_ipld_dagcbor::from_slice` cannot be used for the
/// header because it expects to consume the entire input and fails with
/// `TrailingData` when the payload follows.
fn parse_dagcbor_frame(data: &[u8]) -> std::result::Result<ServerEvent, String> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(data);

    // Parse header (first CBOR object) — ciborium reads exactly one value.
    let header: FrameHeader = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| format!("Failed to decode CBOR header: {e}"))?;

    if header.op == -1 {
        return Err(format!("Server error frame (type: {:?})", header.t));
    }

    let pos = cursor.position() as usize;
    if pos >= data.len() {
        return Err("CBOR frame too short: no payload after header".into());
    }

    // The payload is the second CBOR object — a single, self-contained value,
    // so `serde_ipld_dagcbor::from_slice` works fine on the remaining bytes.
    let payload_bytes = &data[pos..];

    // Dispatch based on the header's type tag
    match header.t.as_deref() {
        Some("#messageEvent") => {
            let p: CborMessageEventPayload = serde_ipld_dagcbor::from_slice(payload_bytes)
                .map_err(|e| format!("Failed to decode messageEvent payload: {e}"))?;

            if p.ephemeral {
                // Skip ephemeral messages (typing indicators sent as encrypted messages)
                return Err("ephemeral message, skipping".into());
            }

            let ciphertext_b64 = BASE64.encode(&p.message.ciphertext);
            Ok(ServerEvent::Message {
                group_id: p.message.convo_id,
                message_id: p.message.id,
                sender_did: None, // Server doesn't include sender in the outer envelope
                ciphertext: ciphertext_b64,
                epoch: p.message.epoch as u64,
                seq: p.message.seq as u64,
            })
        }
        Some("#reactionEvent") => {
            let p: CborReactionEventPayload = serde_ipld_dagcbor::from_slice(payload_bytes)
                .map_err(|e| format!("Failed to decode reactionEvent payload: {e}"))?;
            Ok(ServerEvent::Reaction {
                group_id: p.convo_id,
                message_id: p.message_id,
                emoji: p.reaction,
                sender_did: p.did,
            })
        }
        Some("#typingEvent") => {
            let p: CborTypingEventPayload = serde_ipld_dagcbor::from_slice(payload_bytes)
                .map_err(|e| format!("Failed to decode typingEvent payload: {e}"))?;
            Ok(ServerEvent::Typing {
                group_id: p.convo_id,
                sender_did: p.did,
                is_typing: p.is_typing,
            })
        }
        Some("#membershipChangeEvent") => {
            let p: CborMembershipChangePayload = serde_ipld_dagcbor::from_slice(payload_bytes)
                .map_err(|e| format!("Failed to decode membershipChangeEvent payload: {e}"))?;
            let convo = p.convo_id.or(p.group_id).unwrap_or_default();
            let member = p.did.or(p.member_did).unwrap_or_default();
            match p.action.as_deref() {
                Some("left") | Some("removed") => Ok(ServerEvent::MemberLeft {
                    group_id: convo,
                    member_did: member,
                }),
                _ => Ok(ServerEvent::MemberJoined {
                    group_id: convo,
                    member_did: member,
                }),
            }
        }
        Some("#infoEvent") | Some("#newDeviceEvent") | Some("#groupInfoRefreshRequestedEvent")
        | Some("#readditionRequestedEvent") => {
            // Non-essential events — log and skip
            Err(format!("Ignoring event type: {:?}", header.t))
        }
        Some(other) => Err(format!("Unknown event type: {other}")),
        None => Err("Missing event type in header".into()),
    }
}
