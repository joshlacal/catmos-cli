use catbird_atproto::blue_catbird::chat::subscribe_events::SubscribeEventsMessage;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite;
use tracing::{debug, info};

/// Raw GroupResetEvent fields for manual DAG-CBOR deserialization.
/// The generated `SubscribeEventsMessage` does not yet include this variant,
/// so we parse it from raw bytes when `decode_framed` returns `UnknownEventType`.
#[cfg(test)]
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
/// The generated `SubscribeEventsMessage` does not yet include this variant
/// on `catbird-atproto/main` (the type lives on the
/// `lexicon/reset-requested-event` branch). We parse it from raw bytes when
/// `decode_framed` returns `UnknownEventType`, mirroring the
/// `RawGroupResetEvent` pattern above.
#[cfg(test)]
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
    /// Shared authority has durably refreshed inventory and ordinary entries.
    InventoryRefreshed,
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
    fn build_ws_url(
        config: &crate::storage::config::Config,
        ticket: &str,
        cursor: &str,
        endpoint: Option<&str>,
    ) -> Result<String> {
        let endpoint = endpoint.map(str::to_owned).unwrap_or_else(|| {
            format!(
                "{}/xrpc/blue.catbird.chat.subscribeEvents",
                config.server.mls_url.trim_end_matches('/')
            )
        });
        let mut url = url::Url::parse(&endpoint)
            .map_err(|_| CatmosError::WebSocket("Invalid subscription endpoint".into()))?;
        let scheme = match url.scheme() {
            "https" | "wss" => "wss",
            "http" | "ws" => "ws",
            _ => return Err(CatmosError::WebSocket("Invalid subscription scheme".into())),
        };
        url.set_scheme(scheme)
            .map_err(|_| CatmosError::WebSocket("Invalid subscription scheme".into()))?;
        let retained = url
            .query_pairs()
            .filter(|(key, _)| key != "cursor" && key != "ticket")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>();
        url.set_query(None);
        url.query_pairs_mut()
            .extend_pairs(retained)
            .append_pair("ticket", ticket)
            .append_pair("cursor", cursor);
        Ok(url.into())
    }

    /// Subscribe to real-time events via WebSocket.
    ///
    /// Returns an unbounded receiver that emits `WsEvent`s. The WebSocket
    /// reader runs in a background task with automatic reconnect and
    /// exponential backoff (max 30s) on disconnect/error.
    pub async fn subscribe(&self) -> Result<mpsc::UnboundedReceiver<WsEvent>> {
        let actor_device_id = self.actor_device_id().await?;
        let applied = self.refresh_subscription_state().await?;
        let inventory_session_id = applied.inventory_session_id().to_owned();
        let event_cursor = applied.event_cursor().to_owned();

        // 1. Get a subscription ticket for the initial connection
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

        let ws_url = Self::build_ws_url(
            &self.config,
            &ticket_resp.ticket,
            &event_cursor,
            ticket_resp.endpoint.as_deref(),
        )?;

        debug!("Connecting authenticated WebSocket");

        // 2. Connect
        let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| CatmosError::WebSocket(format!("Connection failed: {e}")))?;

        info!("WebSocket connected");

        let (tx, rx) = mpsc::unbounded_channel();

        let service = self.clone();
        tokio::spawn(async move {
            let mut attempt: u32 = 0;
            let mut current_stream = Some(ws_stream);
            loop {
                if tx.is_closed() {
                    return;
                }
                if let Some(stream) = current_stream.take() {
                    attempt = 0;
                    let (mut write, mut read) = stream.split();
                    while let Some(frame) = read.next().await {
                        let event = match frame {
                            Ok(tungstenite::Message::Text(text)) => {
                                decode_canonical_hint(text.as_bytes())
                            }
                            Ok(tungstenite::Message::Binary(bytes)) => {
                                decode_canonical_hint(&bytes)
                            }
                            Ok(tungstenite::Message::Ping(data)) => {
                                if write.send(tungstenite::Message::Pong(data)).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                            Ok(tungstenite::Message::Pong(_)) => continue,
                            _ => break,
                        };
                        match event {
                            Ok(SubscribeEventsMessage::EventEnvelope(_)) => {
                                // Frames are hints, never custody or policy authority. Do not
                                // persist their cursor, seq-as-epoch, or reset fields. The same
                                // serialized task refetches and applies authenticated authority.
                                if let Err(error) = service.refresh_subscription_state().await {
                                    let _ = tx.send(WsEvent::Error(format!(
                                        "Event reconciliation failed: {error}"
                                    )));
                                    break;
                                }
                                if tx.send(WsEvent::InventoryRefreshed).is_err() {
                                    return;
                                }
                            }
                            Ok(SubscribeEventsMessage::TypingEvent(_)) => {
                                // No typing effect before an independent policy-gated handler.
                            }
                            Err(error) => {
                                let _ = tx.send(WsEvent::Error(error.to_string()));
                                break;
                            }
                        }
                    }
                }
                attempt = attempt.saturating_add(1);
                let _ = tx.send(WsEvent::Reconnecting);
                tokio::select! {
                    _ = tx.closed() => return,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2u64.saturating_pow(attempt).min(30))) => {}
                }
                // A new exact inventory is required on every reconnect, including
                // expired tickets. Its applied fence replaces the original snapshot.
                let result = async {
                    let applied = service.refresh_subscription_state().await?;
                    let actor = service.actor_device_id().await?;
                    let response: SubscriptionTicketResponse = service
                        .xrpc_procedure(
                            "blue.catbird.chat.getSubscriptionTicket",
                            &serde_json::json!({
                                "actorDeviceId": actor,
                                "eventCursor": applied.event_cursor(),
                                "inventorySessionId": applied.inventory_session_id(),
                            }),
                        )
                        .await?;
                    let url = Self::build_ws_url(
                        &service.config,
                        &response.ticket,
                        applied.event_cursor(),
                        response.endpoint.as_deref(),
                    )?;
                    let (stream, _) = tokio_tungstenite::connect_async(url)
                        .await
                        .map_err(|e| CatmosError::WebSocket(e.to_string()))?;
                    Ok::<_, CatmosError>(stream)
                }
                .await;
                match result {
                    Ok(stream) => {
                        current_stream = Some(stream);
                        let _ = tx.send(WsEvent::InventoryRefreshed);
                    }
                    Err(error) => {
                        let _ = tx.send(WsEvent::Error(format!("Reconnect failed: {error}")));
                    }
                }
            }
        });

        Ok(rx)
    }
}

/// Parse the canonical server JSON transport with a bounded frame. Legacy
/// framed-CBOR events are not forwarded into policy-mutating host handlers.
fn decode_canonical_hint(bytes: &[u8]) -> Result<SubscribeEventsMessage> {
    if bytes.len() > 1024 * 1024 {
        return Err(CatmosError::WebSocket("Event frame exceeds bound".into()));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| CatmosError::WebSocket("Invalid canonical event frame".into()))
}

impl ChatService {
    async fn refresh_subscription_state(
        &self,
    ) -> Result<catbird_mls::orchestrator::authenticated_inventory::AppliedInventoryFence> {
        use catbird_mls::orchestrator::MLSStorageBackend;
        let applied = self.refresh_authenticated_inventory().await?;
        let authority = self.request_authority().await?;
        for view in authority
            .storage()
            .list_conversations(self.did())
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))?
        {
            // Pending requests were projected by exact inventory ingestion. Their
            // introduction is not ordinary history and cannot trigger host effects.
            if !authority
                .ensure_conversation_ready(&view.conversation_id)
                .await
                .map_err(|e| CatmosError::Other(e.to_string()))?
                .send_allowed
            {
                continue;
            }
            let mut cursor: Option<String> = None;
            let mut seen = std::collections::HashSet::new();
            for page in 0..100 {
                let (_, next) = authority
                    .fetch_messages(
                        &view.conversation_id,
                        cursor.as_deref(),
                        100,
                        None,
                        None,
                        None,
                    )
                    .await
                    .map_err(|e| CatmosError::Other(e.to_string()))?;
                let Some(next) = next else {
                    break;
                };
                if page == 99 || !seen.insert(next.clone()) {
                    return Err(CatmosError::WebSocket(
                        "Message catch-up exceeds bound".into(),
                    ));
                }
                cursor = Some(next);
            }
        }
        Ok(applied)
    }
}

#[cfg(test)]
/// Attempt to decode a raw framed binary message for event types not yet in the
/// generated `SubscribeEventsMessage` enum. Returns `Some(WsEvent)` on success.
fn try_decode_unknown_event(data: &[u8]) -> Option<WsEvent> {
    let (header, body) = jacquard_common::xrpc::subscription::parse_event_header(data).ok()?;

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
        "#resetRequestedEvent" => {
            let raw: RawResetRequestedEvent = serde_ipld_dagcbor::from_slice(body).ok()?;
            info!(
                phase_2_5_path = "request_only",
                "WS ResetRequestedEvent: convo={} crypto_session={} gen={} trigger={} request_event_id={} expected_new_group={}",
                &raw.convo_id[..12.min(raw.convo_id.len())],
                &raw.crypto_session_id[..12.min(raw.crypto_session_id.len())],
                raw.generation,
                raw.trigger,
                &raw.request_event_id[..16.min(raw.request_event_id.len())],
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
    //! Wire-level decode tests for the manual `try_decode_unknown_event`
    //! parser. The framed format is the AT Protocol subscription frame
    //! `cbor(EventHeader { op, t }) ++ cbor(body)` per
    //! `jacquard_common::xrpc::subscription::parse_event_header`.

    use super::*;
    use serde::Serialize;

    #[test]
    fn subscription_url_uses_exact_applied_fence_and_encodes_opaque_values() {
        let config = crate::storage::config::Config::default();
        let value = ChatService::build_ws_url(
            &config,
            "t+&",
            "c+/=",
            Some("ws://127.0.0.1:1234?cursor=stale&ticket=old"),
        )
        .unwrap();
        let url = url::Url::parse(&value).unwrap();
        assert_eq!(url.path(), "/");
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![
                ("ticket".into(), "t+&".into()),
                ("cursor".into(), "c+/=".into())
            ]
        );
        assert!(ChatService::build_ws_url(&config, "t", "c", Some("file:///tmp/test")).is_err());
    }

    #[test]
    fn canonical_json_hint_is_parsed_without_promoting_event_fields_to_authority() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "$type":"blue.catbird.chat.defs#eventEnvelope", "cursor":"untrusted-next", "previousCursor":"untrusted-prior",
            "createdAt":"2026-09-19T00:00:00.000Z", "payload": {"$type":"blue.catbird.chat.defs#watermarkEvent", "issuedAt":"2026-09-19T00:00:00.000Z"}
        })).unwrap();
        assert!(matches!(
            decode_canonical_hint(&raw).unwrap(),
            SubscribeEventsMessage::EventEnvelope(_)
        ));
        assert!(decode_canonical_hint(b"{invalid").is_err());
        assert!(decode_canonical_hint(&vec![b' '; 1024 * 1024 + 1]).is_err());
        assert!(decode_canonical_hint(br#"{"$type":"unknown"}"#).is_err());
    }

    /// Mirror of `jacquard_common::xrpc::subscription::EventHeader` for
    /// encoding test fixtures. The real type is `Deserialize`-only.
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
