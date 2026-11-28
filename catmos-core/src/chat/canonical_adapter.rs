//! Session-bound adapter for the generated `blue.catbird.chat.*` transport.
//!
//! A previous version of this module accepted `authorization`, DPoP proof/JKT,
//! and signed JSON directly from each caller. That made a caller-supplied tuple
//! look like an authority. The adapter now has one construction path:
//! [`CanonicalSessionAuthority::from_service`]. It rechecks the authenticated
//! session's own clean-chat device record and binds it to the non-exporting MLS
//! signer before any canonical request is prepared.
//!
//! The CLI's existing `ChatService` remains the live legacy path for list/read,
//! send/blob/subscription until the CLI has a Nest-owned DPoP proof provider and
//! generated clean-chat DTO adapters. This module intentionally exposes only
//! canonical read plans and explicit fail-closed errors for mutations/media;
//! it never fabricates a proof, JKT, token, DTO, or private key.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use catbird_mls::orchestrator::CanonicalOperation;
use serde::Deserialize;

use crate::chat::service::ChatService;
use crate::error::{CatmosError, Result};
use crate::mls::MlsManager;

const GET_OWN_DEVICES: &str = "blue.catbird.chat.getOwnDevices";

/// The immutable, server-observed clean-chat device binding used by the CLI.
///
/// This type is deliberately not constructible outside this module. In
/// particular, callers cannot supply a JKT or auth generation alongside a
/// bearer token and turn it into authority. The values are admitted only
/// from the authenticated `getOwnDevices` response and are checked against
/// the restored local signer public key before the signer capability is
/// retained in `MlsManager`.
#[derive(Clone)]
pub struct CanonicalSessionAuthority {
    actor_did: String,
    authorization: String,
    device_id: String,
    #[allow(dead_code)]
    dpop_jkt: String,
    auth_generation: i64,
    key_id: String,
    signer: NonExportingSignerHandle,
}

impl fmt::Debug for CanonicalSessionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalSessionAuthority")
            .field("actor_did", &self.actor_did)
            .field("device_id", &self.device_id)
            .field("auth_generation", &self.auth_generation)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl CanonicalSessionAuthority {
    /// Admit a clean-chat authority from the real CLI session.
    ///
    /// `getOwnDevices` is queried through `ChatService`, which owns the
    /// restored OAuth/AppPassword session and its refresh behavior. Exactly
    /// one active clean-chat record must match the fresh v2 device ID
    /// persisted by clean-chat enrollment, and the public key observed in
    /// that record must be the public half of the signer kept inside
    /// `MLSContext`.
    pub async fn from_service(service: &ChatService) -> Result<Self> {
        match &service.auth {
            crate::auth::AuthMethod::AppPassword { .. } => {
                Err(CatmosError::AuthFailed(
                    "clean-chat session authority unavailable: app-password authority cannot authorize clean chat"
                        .into(),
                ))
            }
            crate::auth::AuthMethod::OAuth { .. } => {
                // ChatService currently owns only OAuth bearer sessions without a verified Nest clean-chat authority producer.
                // Refuse before reading a bearer, calling getOwnDevices, or creating
                // a transport so a generic session can never become clean-chat auth.
                Err(CatmosError::AuthFailed(
                    "clean-chat session authority unavailable: verified Nest clean-chat session producer is not installed"
                        .into(),
                ))
            }
        }
    }

    /// Return the server device ID without exposing any transport secret.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Return the authenticated actor DID.
    pub fn actor_did(&self) -> &str {
        &self.actor_did
    }

    /// Build a non-exporting signer capability for an already-admitted
    /// authority. The capability returns signatures only; private key bytes
    /// remain inside `MLSContext`.
    pub(crate) fn signer(&self) -> &NonExportingSignerHandle {
        &self.signer
    }
}

/// Read every page before selecting a device. Repeated or unchanged cursors
/// fail closed so a malformed snapshot cannot silently authorize a device.
#[allow(dead_code)]
async fn fetch_all_clean_chat_devices(
    service: &ChatService,
    expected_device_id: &str,
) -> Result<Vec<OwnDeviceItem>> {
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();
    let mut all_items = Vec::new();
    loop {
        let mut params = vec![("limit", "100")];
        if let Some(ref value) = cursor {
            params.push(("cursor", value.as_str()));
        }
        let response: OwnDevicesResponse = service
            .xrpc_query(GET_OWN_DEVICES, &params)
            .await
            .map_err(|_| {
                CatmosError::AuthFailed(
                    "clean-chat session authority: getOwnDevices snapshot unavailable".into(),
                )
            })?;
        all_items.extend(response.items);
        let Some(next) = response.cursor.filter(|value| !value.trim().is_empty()) else {
            break;
        };
        if cursor.as_deref() == Some(next.as_str()) || !seen_cursors.insert(next.clone()) {
            return Err(CatmosError::AuthFailed(
                "clean-chat session authority: getOwnDevices cursor stalled".into(),
            ));
        }
        cursor = Some(next);
    }
    if expected_device_id.trim().is_empty() {
        return Err(CatmosError::AuthFailed(
            "clean-chat session authority: missing verified device binding".into(),
        ));
    }
    Ok(all_items)
}

/// A signer handle that can ask MLS to sign without exposing its private key.
#[derive(Clone)]
pub(crate) struct NonExportingSignerHandle {
    mls: Arc<MlsManager>,
    identity: String,
}

impl fmt::Debug for NonExportingSignerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonExportingSignerHandle")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl NonExportingSignerHandle {
    fn new(mls: Arc<MlsManager>, identity: String) -> Self {
        Self { mls, identity }
    }

    /// Sign an already-canonical transcript. This method is crate-private so
    /// transport callers cannot replace the generated DTO/canonicalization
    /// step with an arbitrary signature tuple.
    #[allow(dead_code)]
    pub(crate) fn sign_transcript(&self, transcript: &[u8]) -> Result<Vec<u8>> {
        self.mls.sign_non_exporting(&self.identity, transcript)
    }
}

/// Request plan used by the CLI's Nest session transport.
///
/// The authorization is retained only for the HTTP executor and is omitted
/// from `Debug`; no proof/JKT field exists here because Nest owns DPoP proof
/// issuance. The `body` is present only for generated requests once a typed
/// adapter is available; arbitrary caller-supplied signed JSON is not accepted.
#[derive(Clone, PartialEq, Eq)]
pub struct CliPreparedRequest {
    pub operation: CanonicalOperation,
    pub method: String,
    pub path: String,
    pub device_id: String,
    authorization: String,
    pub body: Option<Vec<u8>>,
}

impl fmt::Debug for CliPreparedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliPreparedRequest")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("device_id", &self.device_id)
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

impl CliPreparedRequest {
    /// Access the session credential only inside the crate's HTTP executor.
    #[allow(dead_code)]
    pub(crate) fn authorization(&self) -> &str {
        &self.authorization
    }
}

/// Native adapter that prepares generated clean-chat read routes from a real
/// session authority. It does not accept caller-supplied proof/JKT/signature
/// tuples and does not export signing keys.
#[derive(Clone)]
pub struct CanonicalTransportAdapter {
    authority: CanonicalSessionAuthority,
}

impl fmt::Debug for CanonicalTransportAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalTransportAdapter")
            .field("authority", &self.authority)
            .finish()
    }
}

impl CanonicalTransportAdapter {
    pub fn from_session_authority(authority: CanonicalSessionAuthority) -> Self {
        Self { authority }
    }

    /// Prepare the canonical conversation inventory query.
    pub fn get_conversations(
        &self,
        limit: i64,
        page_cursor: Option<&str>,
    ) -> Result<CliPreparedRequest> {
        if !(1..=100).contains(&limit) {
            return Err(CatmosError::Other(
                "canonical transport: limit must be between 1 and 100".into(),
            ));
        }
        let mut path = format!(
            "/xrpc/{}?limit={limit}",
            crate::chat::canonical::GET_CONVERSATIONS
        );
        if let Some(cursor) = page_cursor {
            if cursor.trim().is_empty() {
                return Err(CatmosError::Other(
                    "canonical transport: empty page cursor".into(),
                ));
            }
            path.push_str("&pageCursor=");
            path.push_str(&encode_query_component(cursor));
        }
        Ok(self.read_request(CanonicalOperation::GetConversations, path))
    }

    /// Prepare the canonical conversation-entry query.
    pub fn get_entries(
        &self,
        conversation_id: &str,
        after_seq: i64,
        limit: i64,
    ) -> Result<CliPreparedRequest> {
        if conversation_id.trim().is_empty() {
            return Err(CatmosError::Other(
                "canonical transport: missing conversation id".into(),
            ));
        }
        if after_seq < 0 || !(1..=100).contains(&limit) {
            return Err(CatmosError::Other(
                "canonical transport: invalid entry cursor or limit".into(),
            ));
        }
        let path = format!(
            "/xrpc/{}?conversationId={}&afterSeq={after_seq}&limit={limit}",
            crate::chat::canonical::GET_ENTRIES,
            encode_query_component(conversation_id),
        );
        Ok(self.read_request(CanonicalOperation::GetEntries, path))
    }

    /// Explicitly reject operations that do not have a generated CLI adapter.
    ///
    /// This is intentionally not a replacement for the old
    /// `prepare_signed_json(operation, request_json)` API. A caller may not
    /// provide a body plus fabricated proof/JKT/signature fields. Once the
    /// CLI receives a reviewed generated DTO adapter, it should call the
    /// non-exporting signer handle from that typed path.
    pub fn unsupported_operation(
        &self,
        operation: CanonicalOperation,
    ) -> Result<CliPreparedRequest> {
        reject_operation(operation)
    }

    fn read_request(&self, operation: CanonicalOperation, path: String) -> CliPreparedRequest {
        CliPreparedRequest {
            operation,
            method: "GET".into(),
            path,
            device_id: self.authority.device_id.clone(),
            authorization: self.authority.authorization.clone(),
            body: None,
        }
    }
}

fn reject_operation(operation: CanonicalOperation) -> Result<CliPreparedRequest> {
    Err(CatmosError::Other(format!(
        "canonical transport: unsupported CLI operation {operation:?}; no caller-supplied signing tuple is accepted"
    )))
}

#[cfg(test)]
fn read_request_for_test(operation: CanonicalOperation, path: &str) -> CliPreparedRequest {
    CliPreparedRequest {
        operation,
        method: "GET".into(),
        path: path.into(),
        device_id: "fixture-device".into(),
        authorization: "fixture-session-credential".into(),
        body: None,
    }
}

fn encode_query_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[derive(Deserialize)]
struct OwnDevicesResponse {
    #[serde(default)]
    items: Vec<OwnDeviceItem>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct OwnDeviceItem {
    device: OwnDeviceRecord,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnDeviceRecord {
    device_id: String,
    dpop_jkt: String,
    auth_generation: i64,
    key_id: String,
    status: String,
    #[serde(default)]
    signature_public_key: Option<ByteEnvelope>,
}

#[derive(Deserialize)]
struct ByteEnvelope {
    #[serde(rename = "$bytes")]
    bytes: String,
}

fn select_clean_chat_device(
    items: &[OwnDeviceItem],
    expected_device_id: &str,
) -> Result<AdmittedDevice> {
    let matches: Vec<&OwnDeviceRecord> = items
        .iter()
        .map(|item| &item.device)
        .filter(|device| device.device_id == expected_device_id)
        .collect();
    let [record] = matches.as_slice() else {
        return Err(CatmosError::AuthFailed(
            "clean-chat session authority: expected exactly one matching device".into(),
        ));
    };
    if record.status != "active" {
        return Err(CatmosError::AuthFailed(
            "clean-chat session authority: matching device is not active".into(),
        ));
    }
    if record.dpop_jkt.trim().is_empty() || record.auth_generation <= 0 {
        return Err(CatmosError::AuthFailed(
            "clean-chat session authority: device binding is incomplete".into(),
        ));
    }
    if record.key_id.trim().is_empty() {
        return Err(CatmosError::AuthFailed(
            "clean-chat session authority: device key id is missing".into(),
        ));
    }
    let envelope = record.signature_public_key.as_ref().ok_or_else(|| {
        CatmosError::AuthFailed(
            "clean-chat session authority: device signing public key is missing".into(),
        )
    })?;
    let signature_public_key = BASE64.decode(&envelope.bytes).map_err(|_| {
        CatmosError::AuthFailed(
            "clean-chat session authority: invalid device signing public key".into(),
        )
    })?;
    if signature_public_key.is_empty() {
        return Err(CatmosError::AuthFailed(
            "clean-chat session authority: empty device signing public key".into(),
        ));
    }
    Ok(AdmittedDevice {
        device_id: record.device_id.clone(),
        dpop_jkt: record.dpop_jkt.clone(),
        auth_generation: record.auth_generation,
        key_id: record.key_id.clone(),
        signature_public_key,
    })
}

#[allow(dead_code)]
fn admit_device(mls: &Arc<MlsManager>, identity: &str, record: &AdmittedDevice) -> Result<()> {
    let retained = mls.signer_public_key(identity).ok_or_else(|| {
        CatmosError::AuthFailed("clean-chat session authority: no retained local signer".into())
    })?;
    if retained != record.signature_public_key {
        return Err(CatmosError::AuthFailed(
            "clean-chat session authority: server device signing key does not match the retained local signer".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct AdmittedDevice {
    device_id: String,
    #[allow(dead_code)]
    dpop_jkt: String,
    #[allow(dead_code)]
    auth_generation: i64,
    key_id: String,
    signature_public_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMethod;
    use crate::chat::service::ChatService;
    use crate::mls::DeviceInfo;
    use crate::storage::aliases::AliasStore;
    use crate::storage::config::Config;
    use crate::storage::db::Database;

    async fn generic_service(auth: AuthMethod) -> ChatService {
        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let path = std::env::temp_dir().join(format!(
            "catmos-canonical-service-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let db = Arc::new(Database::open_unencrypted(&path).await.expect("database"));
        let did = "did:plc:test";
        let data_dir = std::env::temp_dir().join(format!(
            "catmos-canonical-service-mls-{}",
            uuid::Uuid::new_v4()
        ));
        let mls = Arc::new(MlsManager::new(&data_dir, did).expect("MLS context"));
        ChatService::new(
            auth,
            None,
            mls,
            db,
            Config::default(),
            Arc::new(tokio::sync::RwLock::new(AliasStore::default())),
        )
    }

    #[tokio::test]
    async fn from_service_refuses_generic_session_authority_before_transport() {
        let oauth = generic_service(AuthMethod::OAuth {
            session_cookie: "fixture-cookie".into(),
            did: "did:plc:test".into(),
            nest_url: "https://nest.invalid".into(),
        })
        .await;
        let error = CanonicalSessionAuthority::from_service(&oauth)
            .await
            .expect_err("generic OAuth must never become clean-chat authority");
        assert!(error
            .to_string()
            .contains("verified Nest clean-chat session producer is not installed"));
    }

    #[test]
    fn canonical_reads_bind_real_device_and_do_not_expose_dpop_proof() {
        let request = read_request_for_test(
            CanonicalOperation::GetConversations,
            "/xrpc/blue.catbird.chat.getConversations?limit=20&pageCursor=cursor%2F1",
        );
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/xrpc/blue.catbird.chat.getConversations?limit=20&pageCursor=cursor%2F1"
        );
        assert!(request.body.is_none());
        assert_eq!(request.authorization(), "fixture-session-credential");
        let debug = format!("{request:?}");
        assert!(!debug.contains("fixture-session-credential"));
        assert!(!debug.contains("fixture-jkt"));
    }

    #[test]
    fn caller_supplied_proof_jkt_and_signature_tuple_has_no_adapter_path() {
        for operation in [
            CanonicalOperation::SendMessage,
            CanonicalOperation::SubmitTransition,
            CanonicalOperation::SubscribeEvents,
        ] {
            let error =
                reject_operation(operation).expect_err("unsupported operation must fail closed");
            assert!(error.to_string().contains("unsupported CLI operation"));
            assert!(error.to_string().contains("caller-supplied signing tuple"));
        }
    }

    #[test]
    fn entry_reads_preserve_cursor_and_reject_invalid_values() {
        let request = read_request_for_test(
            CanonicalOperation::GetEntries,
            "/xrpc/blue.catbird.chat.getEntries?conversationId=conversation%2F1&afterSeq=12&limit=50",
        );
        assert_eq!(
            request.path,
            "/xrpc/blue.catbird.chat.getEntries?conversationId=conversation%2F1&afterSeq=12&limit=50"
        );
    }

    #[test]
    fn clean_device_selection_requires_one_active_complete_binding() {
        let record = |device_id: &str| OwnDeviceItem {
            device: OwnDeviceRecord {
                device_id: device_id.into(),
                dpop_jkt: "jkt".into(),
                auth_generation: 1,
                key_id: "key".into(),
                status: "active".into(),
                signature_public_key: Some(ByteEnvelope {
                    bytes: BASE64.encode([1u8, 2, 3]),
                }),
            },
        };
        assert!(select_clean_chat_device(&[], "device").is_err());
        assert!(select_clean_chat_device(&[record("device"), record("device")], "device").is_err());
        assert!(select_clean_chat_device(&[record("other")], "device").is_err());
        assert!(select_clean_chat_device(&[record("device")], "device").is_ok());
    }

    // ── Finding 2: categorical bearer rejection ────────────────────────────

    #[tokio::test]
    async fn from_service_refuses_app_password_authority_before_transport() {
        let service = generic_service(AuthMethod::AppPassword {
            handle: "alice.test".into(),
            did: "did:plc:test".into(),
            pds_url: "https://pds.invalid".into(),
        })
        .await;
        let error = CanonicalSessionAuthority::from_service(&service)
            .await
            .expect_err("app-password/PDS authority must never become clean-chat authority");
        let rendered = error.to_string();
        assert!(
            rendered.contains("app-password"),
            "expected typed app-password rejection, got: {rendered}"
        );
        assert!(
            rendered.contains("cannot authorize clean chat"),
            "expected categorical rejection, got: {rendered}"
        );
    }

    // ── Finding 1: actual-signer binding ───────────────────────────────────

    fn test_mls() -> Arc<MlsManager> {
        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let data_dir =
            std::env::temp_dir().join(format!("catmos-canonical-mls-{}", uuid::Uuid::new_v4()));
        Arc::new(MlsManager::new(&data_dir, "did:plc:test").expect("MLS context"))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admission_rejects_server_key_that_does_not_match_retained_signer() {
        let mls = test_mls();
        let identity = "did:plc:test";
        mls.with_context(|ctx| ctx.create_key_package(identity.as_bytes().to_vec()))
            .expect("register retained signer");
        let retained = mls
            .signer_public_key(identity)
            .expect("retained signer key");
        assert_eq!(retained.len(), 32, "Ed25519 public key must be 32 bytes");

        // Fabricate a server record whose key matches caller-supplied legacy
        // device state but NOT the retained signer.
        let fabricated_key = vec![0xAB; 32];
        let record = AdmittedDevice {
            device_id: "device-1".into(),
            dpop_jkt: "jkt".into(),
            auth_generation: 1,
            key_id: "key-1".into(),
            signature_public_key: fabricated_key.clone(),
        };
        // Caller-constructible legacy device state matching the server record
        // must never satisfy admission on its own.
        let _fabricated_device = DeviceInfo {
            device_id: "device-1".into(),
            mls_did: identity.into(),
            device_uuid: "uuid-1".into(),
            signature_public_key: fabricated_key,
        };
        let error = admit_device(&mls, identity, &record)
            .expect_err("server key differing from the retained signer must fail admission");
        assert!(
            error
                .to_string()
                .contains("does not match the retained local signer"),
            "unexpected error: {error}"
        );
        assert_ne!(retained, record.signature_public_key);
    }

    // ── Finding 3: complete device pagination ──────────────────────────────

    fn device_json(device_id: &str, jkt: &str, key_b64: &str) -> serde_json::Value {
        serde_json::json!({
            "device": {
                "deviceId": device_id,
                "dpopJkt": jkt,
                "authGeneration": 1,
                "keyId": "key-1",
                "status": "active",
                "signaturePublicKey": { "$bytes": key_b64 }
            }
        })
    }

    async fn spawn_get_own_devices_server() -> (String, tokio::task::JoinHandle<()>) {
        use axum::extract::Query;
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::{Json, Router};
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        async fn handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
            let key_b64 = BASE64.encode([0x42u8; 32]);
            match params.get("cursor").map(String::as_str) {
                None => Json(serde_json::json!({
                    "items": [device_json("device-1", "REDACT-ME-JKT", &key_b64)],
                    "cursor": "page-2"
                })),
                Some("page-2") => Json(serde_json::json!({
                    "items": [device_json("device-1", "REDACT-ME-JKT", &key_b64)],
                    "cursor": null
                })),
                _ => Json(serde_json::json!({ "items": [], "cursor": null })),
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let app = Router::new().route("/xrpc/blue.catbird.chat.getOwnDevices", get(handler));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn admission_exhausts_pages_and_fails_on_page_two_duplicate() {
        let (nest_url, _server) = spawn_get_own_devices_server().await;
        let service = generic_service(AuthMethod::OAuth {
            session_cookie: "fixture-cookie".into(),
            did: "did:plc:test".into(),
            nest_url,
        })
        .await;
        let items = fetch_all_clean_chat_devices(&service, "device-1")
            .await
            .expect("both pages must be fetched");
        assert_eq!(items.len(), 2, "duplicate on page 2 must be collected");
        let error = select_clean_chat_device(&items, "device-1")
            .expect_err("duplicate across pages must fail exactly-one-match");
        assert!(
            error.to_string().contains("exactly one matching device"),
            "unexpected error: {error}"
        );
    }

    // ── Finding 4: redaction of JKT and key material ───────────────────────

    #[tokio::test]
    async fn admission_errors_and_logs_redact_jkt_and_key_material() {
        use tracing::field::Visit;
        use tracing::span::{Attributes, Id, Record};
        use tracing::{Event, Metadata, Subscriber};

        #[derive(Clone, Default)]
        struct CapturingSubscriber {
            events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        }

        impl Subscriber for CapturingSubscriber {
            fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }
            fn record(&self, _span: &Id, _values: &Record<'_>) {}
            fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
            fn event(&self, event: &Event<'_>) {
                struct Visitor(String);
                impl Visit for Visitor {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        self.0.push_str(&format!("{}={:?} ", field.name(), value));
                    }
                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        self.0.push_str(&format!("{}={} ", field.name(), value));
                    }
                }
                let mut visitor = Visitor(String::new());
                event.record(&mut visitor);
                self.events.lock().unwrap().push(visitor.0);
            }
            fn enter(&self, _span: &Id) {}
            fn exit(&self, _span: &Id) {}
        }

        let subscriber = CapturingSubscriber::default();
        let _guard = tracing::subscriber::set_default(subscriber.clone());
        let key_b64 = BASE64.encode([0x42u8; 32]);

        let (nest_url, _server) = spawn_get_own_devices_server().await;
        let service = generic_service(AuthMethod::OAuth {
            session_cookie: "fixture-cookie".into(),
            did: "did:plc:test".into(),
            nest_url,
        })
        .await;
        let items = fetch_all_clean_chat_devices(&service, "device-1")
            .await
            .expect("pages fetched");
        let error = select_clean_chat_device(&items, "device-1")
            .expect_err("duplicate must fail admission");
        let rendered = error.to_string();
        assert!(
            !rendered.contains("REDACT-ME-JKT"),
            "error leaked JKT: {rendered}"
        );
        assert!(
            !rendered.contains(&key_b64),
            "error leaked signing key: {rendered}"
        );
        drop(_guard);
        let logs = subscriber.events.lock().unwrap().join("\n");
        assert!(!logs.contains("REDACT-ME-JKT"), "log leaked JKT: {logs}");
        assert!(!logs.contains(&key_b64), "log leaked signing key: {logs}");
    }
}
