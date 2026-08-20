use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use catbird_atproto::blue_catbird::chat::subscribe_events::SubscribeEventsMessage;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
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
        endpoint: Option<&str>,
    ) -> String {
        let endpoint = endpoint.map(String::from).unwrap_or_else(|| {
            let base = config.server.mls_url.clone();
            format!("{base}/xrpc/blue.catbird.chat.subscribeEvents?ticket={ticket}")
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
                "blue.catbird.chat.getSubscriptionTicket",
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
        let token_session = self.token_session.clone();
        let db = self.db.clone();
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
                                if let Some(ws_event) = try_decode_unknown_event(&data) {
                                    if tx.send(ws_event).is_err() {
                                        debug!("WsEvent receiver dropped, stopping reader");
                                        return;
                                    }
                                } else if let Ok((_header, body)) =
                                    jacquard_common::xrpc::subscription::parse_event_header(&data)
                                {
                                    if let Ok(event) =
                                        serde_ipld_dagcbor::from_slice::<SubscribeEventsMessage>(&body)
                                    {
                                        let ws_event =
                                            convert_event(event, &mls, &own_commits).await;
                                        if tx.send(ws_event).is_err() {
                                            debug!("WsEvent receiver dropped, stopping reader");
                                            return;
                                        }
                                    } else if let Ok(event) =
                                        serde_json::from_slice::<SubscribeEventsMessage>(&body)
                                    {
                                        let ws_event =
                                            convert_event(event, &mls, &own_commits).await;
                                        if tx.send(ws_event).is_err() {
                                            debug!("WsEvent receiver dropped, stopping reader");
                                            return;
                                        }
                                    } else {
                                        warn!("Failed to decode WebSocket event body");
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
                info!("WebSocket reconnecting in {backoff_secs}s (attempt {attempt})");
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;

                // Get a fresh subscription ticket using a temporary client
                // (we can't hold &self across the spawn boundary, so we
                //  rebuild the request manually). Uses the jacquard token
                // session so token refresh happens transparently.
                let ticket_result = get_subscription_ticket_standalone(
                    &http,
                    &auth,
                    token_session.as_ref(),
                    &db,
                    &config,
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
/// On 401/400 with an AppPassword session, refreshes tokens via jacquard
/// and retries once.
async fn get_subscription_ticket_standalone(
    http: &reqwest::Client,
    auth: &crate::auth::AuthMethod,
    token_session: Option<&crate::auth::TokenSession>,
    db: &crate::storage::db::Database,
    config: &crate::storage::config::Config,
) -> std::result::Result<SubscriptionTicketResponse, String> {
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
    use reqwest::StatusCode;

    let nsid = "blue.catbird.chat.getSubscriptionTicket";

    let (base_url, is_proxy) = match auth {
        crate::auth::AuthMethod::OAuth { nest_url, .. } => (format!("{nest_url}/xrpc/{nsid}"), false),
        crate::auth::AuthMethod::AppPassword { pds_url, .. } => {
            (format!("{}/xrpc/{nsid}", pds_url.trim_end_matches('/')), true)
        }
    };

    // Resolve the bearer token for this attempt — OAuth uses the cookie;
    // AppPassword pulls the current access JWT out of the token session.
    let initial_bearer = match (auth, token_session) {
        (crate::auth::AuthMethod::OAuth { session_cookie, .. }, _) => session_cookie.clone(),
        (crate::auth::AuthMethod::AppPassword { .. }, Some(sess)) => sess
            .current_bearer()
            .await
            .map_err(|e| format!("bearer fetch failed: {e}"))?,
        (crate::auth::AuthMethod::AppPassword { .. }, None) => {
            return Err("AppPassword auth without a TokenSession".into());
        }
    };

    let build_headers = |bearer: &str| -> std::result::Result<HeaderMap, String> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|e| e.to_string())?,
        );
        if is_proxy {
            let proxy_val = crate::mls::atproto_proxy_header_value();
            if let Ok(hv) = HeaderValue::from_str(&proxy_val) {
                headers.insert(
                    reqwest::header::HeaderName::from_static("atproto-proxy"),
                    hv,
                );
            }
        }
        Ok(headers)
    };

    let resp = http
        .post(&base_url)
        .headers(build_headers(&initial_bearer)?)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| format!("Network error: {e}"))?;

    let status = resp.status();
    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Network error: {e}"))?;

    // Retry once after token refresh only if AppPassword + ExpiredToken
    let body_bytes = if token_session.is_some() && crate::chat::service::is_expired_token_response(status, &body_bytes) {
        let sess = token_session.expect("checked above");
        let new_bearer = sess
            .refresh(db)
            .await
            .map_err(|e| format!("refresh failed: {e}"))?;
        let retry_resp = http
            .post(&base_url)
            .headers(build_headers(&new_bearer)?)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| format!("Network error (retry): {e}"))?;
        let retry_status = retry_resp.status();
        let retry_bytes = retry_resp
            .bytes()
            .await
            .map_err(|e| format!("Network error (retry): {e}"))?;
        if !retry_status.is_success() {
            let body = String::from_utf8_lossy(&retry_bytes);
            return Err(format!("Ticket request failed: {body}"));
        }
        retry_bytes
    } else {
        if !status.is_success() {
            let body = String::from_utf8_lossy(&body_bytes);
            return Err(format!("Ticket request failed: {body}"));
        }
        body_bytes
    };

    serde_json::from_slice::<SubscriptionTicketResponse>(&body_bytes)
        .map_err(|e| format!("Parse error: {e}"))
}
/// Convert a decoded `SubscribeEventsMessage` into a `WsEvent`, decrypting
/// message ciphertext where applicable.
///
/// `own_commits` is checked for commit messages to prevent duplicate processing
/// of our own commits received back via WebSocket (spec section 5.4).
async fn convert_event(
    event: SubscribeEventsMessage,
    _mls: &Arc<crate::mls::MlsManager>,
    _own_commits: &Arc<Mutex<HashMap<[u8; 32], Instant>>>,
) -> WsEvent {
    match event {
        SubscribeEventsMessage::EventEnvelope(env) => match env.payload {
            catbird_atproto::blue_catbird::chat::ProtocolEventPayload::MessageAvailableEvent(msg_evt) => {
                let convo_id = msg_evt.conversation_id.to_string();
                let seq = msg_evt.seq as u64;
                WsEvent::EpochAdvanced {
                    convo_id,
                    new_epoch: seq,
                }
            }
            catbird_atproto::blue_catbird::chat::ProtocolEventPayload::ConversationChangedEvent(evt) => {
                let convo_id = evt.conversation_id.to_string();
                WsEvent::EpochAdvanced {
                    convo_id,
                    new_epoch: 0,
                }
            }
            catbird_atproto::blue_catbird::chat::ProtocolEventPayload::ResetRequestedEvent(evt) => {
                WsEvent::ResetRequested {
                    convo_id: evt.conversation_id.to_string(),
                    crypto_session_id: String::new(),
                    generation: 0,
                    trigger: "reset_requested".to_string(),
                    request_event_id: evt.reset_request_id.to_string(),
                    expected_new_mls_group_id: None,
                }
            }
            _ => WsEvent::EpochAdvanced {
                convo_id: String::new(),
                new_epoch: 0,
            },
        },
        SubscribeEventsMessage::TypingEvent(evt) => WsEvent::Typing {
            convo_id: evt.conversation_id.to_string(),
            sender_did: evt.actor_did.to_string(),
            is_typing: evt.is_typing,
        },
    }
}

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
