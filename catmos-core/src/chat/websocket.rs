use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use catbird_atproto::blue_catbird::mlsChat::subscribe_events::SubscribeEventsMessage;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite;
use tracing::{debug, error, info, warn};

/// Raw GroupResetEvent fields for manual DAG-CBOR deserialization.
/// The generated `SubscribeEventsMessage` does not yet include this variant,
/// so we parse it from raw bytes when `decode_framed` returns `UnknownEventType`.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RawGroupResetEvent {
    convo_id: String,
    new_group_id: String,
    reset_generation: u64,
    reset_by: String,
    cipher_suite: String,
    reason: Option<String>,
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
    /// The MLS tree changed for a conversation (server canonical tree updated).
    TreeChanged {
        convo_id: String,
        confirmation_tag: String,
        epoch: u64,
    },
    /// The MLS group was reset by an admin — clients must rejoin with a new group ID.
    GroupReset {
        convo_id: String,
        new_group_id: String,
        reset_generation: u64,
        reset_by: String,
        cipher_suite: String,
        reason: Option<String>,
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
    /// Build a WebSocket URL from a subscription ticket.
    fn build_ws_url(config: &crate::storage::config::Config, ticket: &str, endpoint: Option<&str>) -> String {
        let endpoint = endpoint.map(String::from).unwrap_or_else(|| {
            let base = config.server.mls_url.clone();
            format!("{base}/xrpc/blue.catbird.mlsChat.subscribeEvents?ticket={ticket}")
        });

        if endpoint.contains("ticket=") {
            endpoint
                .replace("https://", "wss://")
                .replace("http://", "ws://")
        } else {
            let sep = if endpoint.contains('?') { "&" } else { "?" };
            format!(
                "{}{sep}ticket={ticket}",
                endpoint
                    .replace("https://", "wss://")
                    .replace("http://", "ws://")
            )
        }
    }

    /// Subscribe to real-time events via WebSocket.
    ///
    /// Returns an unbounded receiver that emits `WsEvent`s. The WebSocket
    /// reader runs in a background task with automatic reconnect and
    /// exponential backoff (max 30s) on disconnect/error.
    pub async fn subscribe(&self) -> Result<mpsc::UnboundedReceiver<WsEvent>> {
        // 1. Get a subscription ticket for the initial connection
        let ticket_resp: SubscriptionTicketResponse = self
            .xrpc_procedure(
                "blue.catbird.mlsChat.getSubscriptionTicket",
                &serde_json::json!({}),
            )
            .await?;

        let ws_url = Self::build_ws_url(
            &self.config,
            &ticket_resp.ticket,
            ticket_resp.endpoint.as_deref(),
        );

        debug!("Connecting WebSocket to {ws_url}");

        // 2. Connect
        let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| CatmosError::WebSocket(format!("Connection failed: {e}")))?;

        info!("WebSocket connected");

        let (tx, rx) = mpsc::unbounded_channel();

        // Clone what the background reconnect task needs
        let mls = self.mls.clone();
        let own_commits = self.own_commits.clone();
        let config = self.config.clone();
        let auth = self.auth.clone();
        let http = self.http.clone();

        // 3. Spawn reader task with reconnect loop
        tokio::spawn(async move {
            let mut attempt: u32 = 0;
            let mut current_stream = Some(ws_stream);

            loop {
                if let Some(stream) = current_stream.take() {
                    // Reset attempt counter on successful connection
                    attempt = 0;

                    let (mut write, mut read) = stream.split();
                    let mut disconnected = false;

                    while let Some(msg_result) = read.next().await {
                        match msg_result {
                            Ok(tungstenite::Message::Binary(data)) => {
                                match SubscribeEventsMessage::decode_framed(&data) {
                                    Ok(event) => {
                                        let ws_event = convert_event(event, &mls, &own_commits).await;
                                        if tx.send(ws_event).is_err() {
                                            debug!("WsEvent receiver dropped, stopping reader");
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        if let Some(ws_event) = try_decode_unknown_event(&data) {
                                            if tx.send(ws_event).is_err() {
                                                debug!("WsEvent receiver dropped, stopping reader");
                                                return;
                                            }
                                        } else {
                                            warn!("Failed to decode WebSocket frame: {e}");
                                        }
                                    }
                                }
                            }
                            Ok(tungstenite::Message::Text(text)) => {
                                warn!("Received unexpected text frame, ignoring: {text}");
                            }
                            Ok(tungstenite::Message::Ping(data)) => {
                                if let Err(e) = write.send(tungstenite::Message::Pong(data)).await {
                                    warn!("Failed to send pong: {e}");
                                }
                            }
                            Ok(tungstenite::Message::Close(_)) => {
                                info!("WebSocket closed by server");
                                disconnected = true;
                                break;
                            }
                            Err(e) => {
                                error!("WebSocket error: {e}");
                                disconnected = true;
                                break;
                            }
                            _ => {}
                        }
                    }

                    if !disconnected {
                        // Stream ended without explicit close/error — still reconnect
                        info!("WebSocket stream ended");
                    }
                }

                // ── Reconnect with exponential backoff ──────────────────
                attempt += 1;
                let backoff_secs = std::cmp::min(2u64.saturating_pow(attempt), 30);
                let _ = tx.send(WsEvent::Reconnecting);
                info!(
                    "WebSocket reconnecting in {backoff_secs}s (attempt {attempt})"
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;

                // Get a fresh subscription ticket using a temporary client
                // (we can't hold &self across the spawn boundary, so we
                //  rebuild the request manually).
                let ticket_result = get_subscription_ticket_standalone(
                    &http, &auth, &config,
                )
                .await;

                match ticket_result {
                    Ok(ticket_resp) => {
                        let ws_url = ChatService::build_ws_url(
                            &config,
                            &ticket_resp.ticket,
                            ticket_resp.endpoint.as_deref(),
                        );
                        debug!("Reconnecting WebSocket to {ws_url}");

                        match tokio_tungstenite::connect_async(&ws_url).await {
                            Ok((stream, _)) => {
                                info!("WebSocket reconnected");
                                current_stream = Some(stream);
                                // Loop continues with the new stream
                            }
                            Err(e) => {
                                error!("WebSocket reconnect failed: {e}");
                                // Loop continues to retry with backoff
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to get subscription ticket for reconnect: {e}");
                        // Loop continues to retry with backoff
                    }
                }
            }
        });

        Ok(rx)
    }
}

/// Standalone subscription ticket fetch for use inside the reconnect task.
/// Avoids needing a `&ChatService` reference across the spawn boundary.
async fn get_subscription_ticket_standalone(
    http: &reqwest::Client,
    auth: &crate::auth::AuthMethod,
    config: &crate::storage::config::Config,
) -> std::result::Result<SubscriptionTicketResponse, String> {
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

    let nsid = "blue.catbird.mlsChat.getSubscriptionTicket";
    let mut headers = HeaderMap::new();

    let url = match auth {
        crate::auth::AuthMethod::OAuth {
            session_cookie,
            nest_url,
            ..
        } => {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {session_cookie}"))
                    .map_err(|e| e.to_string())?,
            );
            format!("{nest_url}/xrpc/{nsid}")
        }
        crate::auth::AuthMethod::AppPassword { access_jwt, .. } => {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {access_jwt}"))
                    .map_err(|e| e.to_string())?,
            );
            format!("{}/xrpc/{nsid}", config.server.mls_url)
        }
    };

    let resp = http
        .post(&url)
        .headers(headers)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| format!("Network error: {e}"))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Ticket request failed: {body}"));
    }

    resp.json::<SubscriptionTicketResponse>()
        .await
        .map_err(|e| format!("Parse error: {e}"))
}

/// Convert a decoded `SubscribeEventsMessage` into a `WsEvent`, decrypting
/// message ciphertext where applicable.
///
/// `own_commits` is checked for commit messages to prevent duplicate processing
/// of our own commits received back via WebSocket (spec section 5.4).
async fn convert_event(
    event: SubscribeEventsMessage<'_>,
    mls: &Arc<crate::mls::MlsManager>,
    own_commits: &Arc<Mutex<HashMap<[u8; 32], Instant>>>,
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
            let msg_type = mv
                .message_type
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or("app");
            info!("WS MessageEvent: id={message_id} convo={convo_id} type={msg_type} epoch={epoch} seq={seq} ct_len={}", ct_bytes.len());

            let gid_bytes = match hex::decode(&convo_id) {
                Ok(b) => b,
                Err(e) => {
                    return WsEvent::Error(format!("Invalid group ID hex: {e}"));
                }
            };

            // Commit messages advance the MLS epoch — process them to update local state
            if msg_type == "commit" {
                // Own-commit dedup (spec section 5.4): check SHA256 of the ciphertext
                // against our own_commits set to avoid duplicate processing.
                let hash: [u8; 32] = Sha256::digest(&ct_bytes).into();
                if own_commits.lock().await.remove(&hash).is_some() {
                    debug!("WS: skipping own commit {message_id} epoch={epoch}");
                    return WsEvent::EpochAdvanced {
                        convo_id,
                        new_epoch: epoch,
                    };
                }

                match mls.with_context(|ctx| ctx.process_message(gid_bytes, ct_bytes)) {
                    Ok(_) => {
                        debug!("Processed commit message {message_id} for {convo_id}");
                    }
                    Err(e) => {
                        debug!("Failed to process commit {message_id}: {e}");
                    }
                }
                // Commits aren't user-visible messages — skip
                return WsEvent::EpochAdvanced {
                    convo_id,
                    new_epoch: epoch,
                };
            }

            // Application messages — decrypt to get plaintext
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
        SubscribeEventsMessage::TreeChanged(evt) => {
            let convo_id = evt.convo_id.to_string();
            let server_tag = String::from_utf8_lossy(&evt.confirmation_tag).to_string();
            let epoch = evt.epoch as u64;

            // Compare server's canonical tag against our local tag
            let gid_bytes = match hex::decode(&convo_id) {
                Ok(b) => b,
                Err(e) => {
                    return WsEvent::Error(format!("Invalid group ID hex in treeChanged: {e}"));
                }
            };

            let local_tag = mls
                .with_context(|ctx| ctx.get_confirmation_tag(gid_bytes))
                .ok()
                .map(|tag| base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &tag,
                ));

            if local_tag.as_deref() == Some(server_tag.as_str()) {
                debug!("treeChanged for {convo_id}: local tag matches canonical, no action needed");
            } else {
                warn!(
                    "treeChanged for {convo_id}: local tag MISMATCH (epoch {epoch}), repair needed"
                );
            }

            WsEvent::TreeChanged {
                convo_id,
                confirmation_tag: server_tag,
                epoch,
            }
        }
        other => {
            info!(
                "Ignoring subscription event: {:?}",
                std::mem::discriminant(&other)
            );
            WsEvent::EpochAdvanced {
                convo_id: String::new(),
                new_epoch: 0,
            }
        }
    }
}

/// Attempt to decode a raw framed binary message for event types not yet in the
/// generated `SubscribeEventsMessage` enum. Returns `Some(WsEvent)` on success.
fn try_decode_unknown_event(data: &[u8]) -> Option<WsEvent> {
    let (header, body) =
        jacquard_common::xrpc::subscription::parse_event_header(data).ok()?;

    match header.t.as_str() {
        "#groupResetEvent" => {
            let raw: RawGroupResetEvent = serde_ipld_dagcbor::from_slice(body).ok()?;
            info!(
                "WS GroupResetEvent: convo={} new_group={} gen={} by={}",
                &raw.convo_id[..12.min(raw.convo_id.len())],
                &raw.new_group_id[..12.min(raw.new_group_id.len())],
                raw.reset_generation,
                &raw.reset_by[..20.min(raw.reset_by.len())]
            );
            Some(WsEvent::GroupReset {
                convo_id: raw.convo_id,
                new_group_id: raw.new_group_id,
                reset_generation: raw.reset_generation,
                reset_by: raw.reset_by,
                cipher_suite: raw.cipher_suite,
                reason: raw.reason,
            })
        }
        _ => None,
    }
}
