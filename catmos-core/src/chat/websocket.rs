use futures_util::{SinkExt, StreamExt};
use petrel_catbird::generated::blue::catbird::chat::defs::{
    ProtocolEventPayload, SubscriptionMessage,
};
use petrel_core::{FromValue, SubscriptionFrame, Value};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite;
use tracing::{error, info, warn};

/// Raw GroupResetEvent fields for manual DAG-CBOR deserialization.
/// The generated `SubscriptionMessage` does not yet include this variant,
/// so we parse it from the decoded payload when its short-name header is present.
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

/// Raw ResetRequestedEvent fields for manual DAG-CBOR deserialization.
///
/// Phase 2.5 indirect-trigger SSE event (`docs/plans/phase-2-5-indirect-funneling.md`
/// §3): an indirect trigger (quorum vote, system sweep, inline 409/404) has
/// requested a crypto session reset. The server has NOT minted a new MLS
/// group id; subscribed clients are invited to elect a first responder.
///
/// The generated `SubscriptionMessage` does not yet include this variant
/// as a top-level message. We decode its legacy short-name form like the
/// `RawGroupResetEvent` pattern above.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RawResetRequestedEvent {
    convo_id: String,
    crypto_session_id: String,
    /// `i64` to match the lexicon `integer` width and the orchestrator-side
    /// `record_reset_requested(reset_generation: i32, ..)` signature in
    /// `catbird-mls/src/orchestrator/recovery.rs:1387` (we narrow at the call
    /// site after a range check).
    generation: i64,
    /// Lexicon `knownValues`: `quorum_vote | system_sweep | inline_commit_409
    /// | inline_groupinfo_404`. Logged for observability (Stage 1
    /// `phase_2_5_path = "request_only"`); not parsed into an enum here per
    /// the orchestrator-side comment at recovery.rs:1373.
    trigger: String,
    /// Server-side opaque id of the `crypto_session_reset_requested`
    /// delivery_event. Deterministic dedup key (plan §3 idempotency scheme).
    request_event_id: String,
    /// Usually `None` for indirect triggers (locked decision §1: server never
    /// mints `mls_group_id` outside the chokepoint). Admin/bootstrap direct
    /// flows may set it.
    expected_new_mls_group_id: Option<String>,
    #[allow(dead_code)]
    reason: Option<String>,
    #[allow(dead_code)]
    requested_at: Option<String>,
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
    /// Phase 2.5 indirect-trigger reset request
    /// (`docs/plans/phase-2-5-indirect-funneling.md` §3, §5 Stage 2).
    ///
    /// The server has not minted a new group id; subscribed clients race to
    /// produce one via `bootstrapResetGroup` / `commitGroupChange`. Our local
    /// handler `ChatService::handle_reset_requested_event` mints a candidate
    /// id and persists `RESET_PENDING`; the existing deferred-recovery loop
    /// drives the first-responder bootstrap.
    ResetRequested {
        convo_id: String,
        crypto_session_id: String,
        generation: i64,
        trigger: String,
        request_event_id: String,
        expected_new_mls_group_id: Option<String>,
    },
    /// An error occurred on the WebSocket.
    Error(String),
    /// The WebSocket is reconnecting.
    Reconnecting,
}

/// Earlier ticket issuers omitted the endpoint and used the configured service URL.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionTicketResponse {
    ticket: String,
    endpoint: Option<String>,
}

impl ChatService {
    /// Build a WebSocket URL from a subscription ticket.
    fn build_ws_url(
        config: &crate::storage::config::Config,
        ticket: &str,
        cursor: &str,
        endpoint: Option<&str>,
    ) -> Result<String> {
        let fallback = format!(
            "{}/xrpc/blue.catbird.chat.subscribeEvents",
            config.server.mls_url.trim_end_matches('/')
        );
        let mut url = url::Url::parse(endpoint.unwrap_or(&fallback))
            .map_err(|_| CatmosError::WebSocket("invalid subscription endpoint".into()))?;
        let ws_scheme = match url.scheme() {
            "ws" | "http" => "ws",
            "wss" | "https" => "wss",
            _ => {
                return Err(CatmosError::WebSocket(
                    "unsupported subscription endpoint scheme".into(),
                ))
            }
        };
        url.set_scheme(ws_scheme)
            .map_err(|_| CatmosError::WebSocket("invalid subscription endpoint scheme".into()))?;
        for (key, value) in [("cursor", cursor), ("ticket", ticket)] {
            if !url.query_pairs().any(|(name, _)| name == key) {
                url.query_pairs_mut().append_pair(key, value);
            }
        }
        Ok(url.into())
    }

    async fn subscription_url(
        &self,
        actor_device_id: &str,
        inventory_session_id: &str,
        event_cursor: &str,
    ) -> Result<String> {
        let ticket_resp: SubscriptionTicketResponse = self
            .xrpc_procedure(
                "blue.catbird.chat.getSubscriptionTicket",
                &serde_json::json!({
                    "actorDeviceId": actor_device_id,
                    "eventCursor": event_cursor,
                    "inventorySessionId": inventory_session_id,
                }),
            )
            .await?;

        Self::build_ws_url(
            &self.config,
            &ticket_resp.ticket,
            event_cursor,
            ticket_resp.endpoint.as_deref(),
        )
    }

    /// Subscribe to real-time events via WebSocket.
    ///
    /// Returns an unbounded receiver that emits `WsEvent`s. The WebSocket
    /// reader runs in a background task with automatic reconnect and
    /// exponential backoff (max 30s) on disconnect/error.
    pub async fn subscribe(&self) -> Result<mpsc::UnboundedReceiver<WsEvent>> {
        let actor_device_id = self.actor_device_id().await?;
        let (inventory_session_id, event_cursor) = {
            let guard = self.inventory_session.read().await;
            guard
                .clone()
                .unwrap_or_else(|| ("catmos-cli-session".to_string(), "0".to_string()))
        };

        let ws_url = self
            .subscription_url(&actor_device_id, &inventory_session_id, &event_cursor)
            .await?;

        // 2. Connect
        let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| CatmosError::WebSocket(format!("Connection failed: {e}")))?;

        info!("WebSocket connected");

        let (tx, rx) = mpsc::unbounded_channel();

        let service = self.clone();

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
                            Ok(tungstenite::Message::Binary(data)) => match decode_event(&data) {
                                Ok(Some(event)) => {
                                    if tx.send(event).is_err() {
                                        return;
                                    }
                                }
                                Ok(None) => {}
                                Err(()) => {
                                    warn!("Subscription error frame; reconnecting");
                                    break;
                                }
                            },
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
                info!("WebSocket reconnecting in {backoff_secs}s (attempt {attempt})");
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;

                if tx.is_closed() {
                    return;
                }
                match service
                    .subscription_url(&actor_device_id, &inventory_session_id, &event_cursor)
                    .await
                {
                    Ok(ws_url) => {
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

/// Convert a decoded `SubscriptionMessage` into a `WsEvent`.
fn convert_event(event: SubscriptionMessage) -> WsEvent {
    match event {
        SubscriptionMessage::EventEnvelope(env) => match env.payload {
            ProtocolEventPayload::MessageAvailableEvent(msg_evt) => {
                let convo_id = msg_evt.conversation_id.to_string();
                let seq = msg_evt.seq as u64;
                WsEvent::EpochAdvanced {
                    convo_id,
                    new_epoch: seq,
                }
            }
            ProtocolEventPayload::ConversationChangedEvent(evt) => {
                let convo_id = evt.conversation_id.to_string();
                WsEvent::EpochAdvanced {
                    convo_id,
                    new_epoch: 0,
                }
            }
            ProtocolEventPayload::ResetRequestedEvent(evt) => WsEvent::ResetRequested {
                convo_id: evt.conversation_id.to_string(),
                crypto_session_id: String::new(),
                generation: 0,
                trigger: "reset_requested".to_string(),
                request_event_id: evt.reset_request_id.to_string(),
                expected_new_mls_group_id: None,
            },
            _ => WsEvent::EpochAdvanced {
                convo_id: String::new(),
                new_epoch: 0,
            },
        },
        SubscriptionMessage::TypingEvent(evt) => WsEvent::Typing {
            convo_id: evt.conversation_id.to_string(),
            sender_did: evt.actor_did.to_string(),
            is_typing: evt.is_typing,
        },
    }
}

/// Attempt to decode a raw framed binary message for event types not yet in the
/// generated `SubscriptionMessage` enum. Returns `Some(WsEvent)` on success.
fn decode_event(data: &[u8]) -> std::result::Result<Option<WsEvent>, ()> {
    let (message_type, payload) = match petrel_core::decode_frame(data) {
        Ok(SubscriptionFrame::Message {
            message_type,
            payload,
            ..
        }) => (message_type, payload),
        Ok(SubscriptionFrame::Error { .. }) => return Err(()),
        Ok(SubscriptionFrame::UnknownOperation { .. }) => return Ok(None),
        Err(_) => {
            // Earlier servers also sent a CBOR header followed by a JSON body.
            // Retain that format without relaxing the operation or frame limit.
            if data.len() > petrel_core::MAXIMUM_FRAME_BYTES {
                return Ok(None);
            }
            let Ok((Value::Object(header), body)) = petrel_core::dagcbor::decode_prefix_with(
                data,
                petrel_core::dagcbor::Limits::STANDARD,
            ) else {
                return Ok(None);
            };
            if header.get("op") != Some(&Value::Integer(1)) {
                return Ok(None);
            }
            let Some(t) = header.get("t").and_then(Value::as_str) else {
                return Ok(None);
            };
            let Ok(Value::Object(mut payload)) = Value::from_json_data_model(body) else {
                return Ok(None);
            };
            payload.insert("$type".into(), Value::String(t.to_owned()));
            (t.to_owned(), Value::Object(payload))
        }
    };
    Ok(match message_type.as_str() {
        "#groupResetEvent" | "#resetRequestedEvent" => decode_legacy_event(&message_type, &payload),
        _ => SubscriptionMessage::from_value(payload)
            .ok()
            .map(convert_event),
    })
}

fn decode_legacy_event(message_type: &str, payload: &Value) -> Option<WsEvent> {
    let body = serde_json::to_value(payload).ok()?;
    match message_type {
        "#groupResetEvent" => {
            let raw: RawGroupResetEvent = serde_json::from_value(body).ok()?;
            info!(
                "WS GroupResetEvent: convo={} new_group={} gen={} by={}",
                raw.convo_id, raw.new_group_id, raw.reset_generation, raw.reset_by
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
        "#resetRequestedEvent" => {
            let raw: RawResetRequestedEvent = serde_json::from_value(body).ok()?;
            info!(
                phase_2_5_path = "request_only",
                "WS ResetRequestedEvent: convo={} crypto_session={} gen={} trigger={} request_event_id={} expected_new_group={}",
                raw.convo_id,
                raw.crypto_session_id,
                raw.generation,
                raw.trigger,
                raw.request_event_id,
                raw.expected_new_mls_group_id
                    .as_deref()
                    .unwrap_or("<none>")
            );
            Some(WsEvent::ResetRequested {
                convo_id: raw.convo_id,
                crypto_session_id: raw.crypto_session_id,
                generation: raw.generation,
                trigger: raw.trigger,
                request_event_id: raw.request_event_id,
                expected_new_mls_group_id: raw.expected_new_mls_group_id,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! Wire fixtures independently encode the header and payload like the server.
    use super::*;
    use serde::Serialize;

    fn try_decode_unknown_event(data: &[u8]) -> Option<WsEvent> {
        decode_event(data).ok().flatten()
    }

    #[derive(Serialize)]
    struct TestEventHeader<'a> {
        op: i64,
        t: &'a str,
    }

    /// Encode a frame with the given header type and body.
    fn frame<B: Serialize>(t: &str, body: &B) -> Vec<u8> {
        let mut buf = Vec::new();
        serde_ipld_dagcbor::ser::to_vec(&TestEventHeader { op: 1, t })
            .unwrap()
            .into_iter()
            .for_each(|b| buf.push(b));
        serde_ipld_dagcbor::ser::to_vec(body)
            .unwrap()
            .into_iter()
            .for_each(|b| buf.push(b));
        buf
    }

    #[test]
    fn canonical_typing_header_supplies_the_body_discriminator() {
        let event = frame(
            "blue.catbird.chat.defs#typingEvent",
            &serde_json::json!({
                "typingId":"typing", "conversationId": "room", "actorDid": "did:plc:z72i7hdynmk6r22z27h6tvur", "actorDeviceId":"device", "isTyping": true, "expiresAt":"2026-11-27T15:00:00Z",
            }),
        );
        assert!(
            matches!(decode_event(&event), Ok(Some(WsEvent::Typing { convo_id, is_typing: true, .. })) if convo_id == "room")
        );
    }

    #[tokio::test]
    async fn reconnect_fetches_another_ticket_and_decodes_the_next_socket() {
        use crate::auth::AuthMethod;
        use crate::storage::{aliases::AliasStore, config::Config, db::Database};
        use axum::{http::HeaderMap, routing::post, Json, Router};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use tokio::net::TcpListener;

        let ds = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ds_url = format!("http://{}", ds.local_addr().unwrap());
        let ws = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", ws.local_addr().unwrap());
        let tickets = Arc::new(AtomicUsize::new(0));
        let issued = tickets.clone();
        let ds_app = Router::new().route(
            "/xrpc/blue.catbird.chat.getSubscriptionTicket",
            post(move |headers: HeaderMap| {
                let n = issued.fetch_add(1, Ordering::SeqCst) + 1;
                let endpoint = endpoint.clone();
                async move {
                    assert_eq!(
                        headers["authorization"].to_str().unwrap(),
                        "Bearer test-only"
                    );
                    Json(serde_json::json!({"ticket":format!("ticket-{n}"), "endpoint":endpoint}))
                }
            }),
        );
        let ds_server = tokio::spawn(async move { axum::serve(ds, ds_app).await.unwrap() });
        let sockets = tokio::spawn(async move {
            for n in 1..=2 {
                let (tcp, _) = ws.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let bytes = frame(
                    "blue.catbird.chat.defs#typingEvent",
                    &serde_json::json!({
                        "typingId": "typing", "conversationId": format!("room-{n}"),
                        "actorDid":"did:plc:z72i7hdynmk6r22z27h6tvur", "actorDeviceId":"device",
                        "isTyping":true, "expiresAt":"2026-11-27T15:00:00Z"
                    }),
                );
                socket
                    .send(tungstenite::Message::Binary(bytes.into()))
                    .await
                    .unwrap();
                socket.close(None).await.unwrap();
            }
        });
        let did = "did:plc:wsreconnecttest";
        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("chat.db"), "local-test-only")
            .await
            .unwrap();
        db.store_session_value("mls_device_id", "device")
            .await
            .unwrap();
        let mut config = Config::default();
        config.server.mls_url = ds_url.clone();
        let service = ChatService::new(
            AuthMethod::OAuth {
                did: did.into(),
                session_cookie: "test-only".into(),
                nest_url: ds_url,
            },
            None,
            Arc::new(crate::mls::MlsManager::new(&dir.path().to_path_buf(), did).unwrap()),
            Arc::new(db),
            config,
            Arc::new(tokio::sync::RwLock::new(AliasStore::default())),
        );
        let mut events = service.subscribe().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(12), async {
            assert!(matches!(events.recv().await, Some(WsEvent::Typing { convo_id, .. }) if convo_id == "room-1"));
            assert!(matches!(events.recv().await, Some(WsEvent::Reconnecting)));
            assert!(matches!(events.recv().await, Some(WsEvent::Typing { convo_id, .. }) if convo_id == "room-2"));
        }).await.unwrap();
        assert_eq!(tickets.load(Ordering::SeqCst), 2);
        drop(events);
        sockets.await.unwrap();
        ds_server.abort();
    }

    /// Lexicon-shaped payload (camelCase keys), matching what the server
    /// emits. We use serde_json::Value at the test boundary to avoid
    /// re-deriving Serialize on the private RawResetRequestedEvent.
    fn reset_requested_body(
        convo_id: &str,
        crypto_session_id: &str,
        generation: i64,
        trigger: &str,
        request_event_id: &str,
        expected_new_mls_group_id: Option<&str>,
        cursor: &str,
    ) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "convoId": convo_id,
            "cryptoSessionId": crypto_session_id,
            "cursor": cursor,
            "generation": generation,
            "trigger": trigger,
            "requestEventId": request_event_id,
        });
        if let Some(g) = expected_new_mls_group_id {
            obj.as_object_mut().unwrap().insert(
                "expectedNewMlsGroupId".into(),
                serde_json::Value::String(g.into()),
            );
        }
        obj
    }

    #[test]
    fn try_decode_unknown_event_returns_none_for_unknown_type() {
        let body = serde_json::json!({"foo": "bar"});
        let bytes = frame("#someUnknownEventType", &body);
        assert!(try_decode_unknown_event(&bytes).is_none());
    }

    /// Validates that an indirect-trigger payload (no `expectedNewMlsGroupId`)
    /// decodes into `WsEvent::ResetRequested` with `expected_new_mls_group_id
    /// = None`. This is the dominant Phase 2.5 case (plan §1 locked decision).
    #[test]
    fn try_decode_reset_requested_indirect_trigger() {
        let body = reset_requested_body(
            "convo-abc",
            "crypto-session-123",
            17,
            "quorum_vote",
            "req-quorum:convo-abc:vote-42",
            None,
            "cursor-99",
        );
        let bytes = frame("#resetRequestedEvent", &body);
        let event = try_decode_unknown_event(&bytes)
            .expect("framed #resetRequestedEvent must decode to Some(WsEvent::ResetRequested)");
        match event {
            WsEvent::ResetRequested {
                convo_id,
                crypto_session_id,
                generation,
                trigger,
                request_event_id,
                expected_new_mls_group_id,
            } => {
                assert_eq!(convo_id, "convo-abc");
                assert_eq!(crypto_session_id, "crypto-session-123");
                assert_eq!(generation, 17);
                assert_eq!(trigger, "quorum_vote");
                assert_eq!(request_event_id, "req-quorum:convo-abc:vote-42");
                assert!(
                    expected_new_mls_group_id.is_none(),
                    "indirect triggers MUST omit expectedNewMlsGroupId (plan §1 locked decision)"
                );
            }
            other => panic!("expected WsEvent::ResetRequested, got {other:?}"),
        }
    }

    /// Validates that a direct-trigger payload (admin path with
    /// `expectedNewMlsGroupId` populated) decodes correctly. Stage 1
    /// dual-emission: the same lexicon variant is used for both indirect
    /// (None) and direct (Some) flows.
    #[test]
    fn try_decode_reset_requested_with_expected_group_id() {
        let body = reset_requested_body(
            "convo-xyz",
            "crypto-session-456",
            42,
            "system_sweep",
            "req-sweep:convo-xyz:tick-789",
            Some("aabbccddeeff00112233445566778899"),
            "cursor-100",
        );
        let bytes = frame("#resetRequestedEvent", &body);
        let event = try_decode_unknown_event(&bytes)
            .expect("framed #resetRequestedEvent must decode to Some(WsEvent::ResetRequested)");
        match event {
            WsEvent::ResetRequested {
                trigger,
                expected_new_mls_group_id,
                ..
            } => {
                assert_eq!(trigger, "system_sweep");
                assert_eq!(
                    expected_new_mls_group_id.as_deref(),
                    Some("aabbccddeeff00112233445566778899")
                );
            }
            other => panic!("expected WsEvent::ResetRequested, got {other:?}"),
        }
    }

    /// All four lexicon `knownValues` for `trigger` must round-trip — the
    /// handler is string-typed by design (orchestrator-side comment at
    /// `catbird-mls/src/orchestrator/recovery.rs:1373`).
    #[test]
    fn try_decode_reset_requested_accepts_all_known_triggers() {
        for trig in [
            "quorum_vote",
            "system_sweep",
            "inline_commit_409",
            "inline_groupinfo_404",
        ] {
            let body = reset_requested_body(
                "convo-1",
                "session-1",
                1,
                trig,
                "req-id-1",
                None,
                "cursor-1",
            );
            let bytes = frame("#resetRequestedEvent", &body);
            let event = try_decode_unknown_event(&bytes)
                .unwrap_or_else(|| panic!("trigger {trig:?} must decode"));
            match event {
                WsEvent::ResetRequested { trigger, .. } => {
                    assert_eq!(trigger, trig);
                }
                other => panic!("expected ResetRequested for {trig:?}, got {other:?}"),
            }
        }
    }

    /// Idempotency at the wire level: replaying the same framed bytes (e.g.
    /// SSE reconnect with cursor replay) decodes to the same payload. The
    /// per-(convo, generation) idempotency check that prevents duplicate
    /// `mark_reset_pending` writes lives in
    /// `ChatService::handle_reset_requested_event` and is exercised by the
    /// DB-layer test.
    #[test]
    fn try_decode_reset_requested_is_pure() {
        let body = reset_requested_body(
            "convo-pure",
            "session-pure",
            7,
            "quorum_vote",
            "req-pure",
            None,
            "cursor-pure",
        );
        let bytes = frame("#resetRequestedEvent", &body);
        let first = try_decode_unknown_event(&bytes).expect("first decode");
        let second = try_decode_unknown_event(&bytes).expect("second decode");
        match (first, second) {
            (
                WsEvent::ResetRequested {
                    convo_id: a,
                    generation: ga,
                    request_event_id: ra,
                    ..
                },
                WsEvent::ResetRequested {
                    convo_id: b,
                    generation: gb,
                    request_event_id: rb,
                    ..
                },
            ) => {
                assert_eq!(a, b);
                assert_eq!(ga, gb);
                assert_eq!(ra, rb);
            }
            other => panic!("decode must be pure, got {other:?}"),
        }
    }
}
