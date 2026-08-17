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

use std::fmt;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use catbird_mls::orchestrator::CanonicalOperation;
use serde::Deserialize;

use crate::chat::service::ChatService;
use crate::error::{CatmosError, Result};
use crate::mls::{DeviceInfo, MlsManager};

const GET_OWN_DEVICES: &str = "blue.catbird.chat.getOwnDevices";
const KEY_CLEAN_CHAT_DEVICE_ID: &str = "clean_chat_device_id";

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
    signer: Option<NonExportingSignerHandle>,
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
    pub async fn from_service(service: &ChatService, device: &DeviceInfo) -> Result<Self> {
        if device.device_id.trim().is_empty() {
            return Err(CatmosError::AuthFailed(
                "clean-chat session authority: missing server device id".into(),
            ));
        }

        // `DeviceInfo` is populated by the legacy mlsChat registration flow.
        // It is never an acceptable clean-chat authority. A future enrollment
        // flow must persist a distinct v2 device ID before this adapter can
        // query `getOwnDevices`; refusing the missing key here prevents an
        // accidental legacy-ID mapping during restart.
        let clean_device_id = service
            .db
            .get_session_value(KEY_CLEAN_CHAT_DEVICE_ID)
            .await?
            .ok_or_else(|| {
                CatmosError::AuthFailed(
                    "clean-chat session authority unavailable: fresh v2 device enrollment is required"
                        .into(),
                )
            })?;
        if clean_device_id == device.device_id {
            return Err(CatmosError::AuthFailed(
                "clean-chat session authority: legacy mlsChat device ID cannot authorize clean chat"
                    .into(),
            ));
        }

        let response: OwnDevicesResponse = service
            .xrpc_query(GET_OWN_DEVICES, &[("limit", "100")])
            .await?;
        let record = select_clean_chat_device(&response.items, &clean_device_id)?;

        if device.signature_public_key.is_empty() {
            return Err(CatmosError::AuthFailed(
                "clean-chat session authority: local signer public key is unavailable after restore"
                    .into(),
            ));
        }
        if device.signature_public_key != record.signature_public_key {
            return Err(CatmosError::AuthFailed(
                "clean-chat session authority: server device key does not match the local signer"
                    .into(),
            ));
        }

        let actor_did = service.did().to_string();
        let signer = NonExportingSignerHandle::new(service.mls.clone(), actor_did.clone());

        let authorization = service.current_bearer().await?;
        if authorization.trim().is_empty() {
            return Err(CatmosError::AuthFailed(
                "clean-chat session authority: empty session credential".into(),
            ));
        }

        Ok(Self {
            actor_did,
            authorization,
            device_id: record.device_id,
            dpop_jkt: record.dpop_jkt,
            auth_generation: record.auth_generation,
            key_id: record.key_id,
            signer: Some(signer),
        })
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
    pub(crate) fn signer(&self) -> Result<&NonExportingSignerHandle> {
        self.signer.as_ref().ok_or_else(|| {
            CatmosError::Other("clean-chat session authority: signer unavailable".into())
        })
    }
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
        let _ = self.authority.signer();
        Err(CatmosError::Other(format!(
            "canonical transport: unsupported CLI operation {operation:?}; no caller-supplied signing tuple is accepted"
        )))
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

fn encode_query_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[derive(Debug, Deserialize)]
struct OwnDevicesResponse {
    #[serde(default)]
    items: Vec<OwnDeviceItem>,
}

#[derive(Debug, Deserialize)]
struct OwnDeviceItem {
    device: OwnDeviceRecord,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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

struct AdmittedDevice {
    device_id: String,
    dpop_jkt: String,
    auth_generation: i64,
    key_id: String,
    signature_public_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> CanonicalSessionAuthority {
        CanonicalSessionAuthority {
            actor_did: "did:plc:test".into(),
            authorization: "Bearer test-token".into(),
            device_id: "00000000-0000-4000-8000-000000000001".into(),
            dpop_jkt: "server-observed-jkt".into(),
            auth_generation: 7,
            key_id: "key-1".into(),
            signer: None,
        }
    }

    #[test]
    fn session_authority_debug_redacts_transport_material() {
        let debug = format!("{:?}", authority());
        assert!(debug.contains("did:plc:test"));
        assert!(debug.contains("device_id"));
        assert!(!debug.contains("test-token"));
        assert!(!debug.contains("server-observed-jkt"));
    }

    #[test]
    fn canonical_reads_bind_real_device_and_do_not_expose_dpop_proof() {
        let adapter = CanonicalTransportAdapter::from_session_authority(authority());
        let request = adapter
            .get_conversations(20, Some("cursor/1"))
            .expect("valid read request");
        assert_eq!(request.method, "GET");
        assert_eq!(request.device_id, "00000000-0000-4000-8000-000000000001");
        assert_eq!(
            request.path,
            "/xrpc/blue.catbird.chat.getConversations?limit=20&pageCursor=cursor%2F1"
        );
        assert!(request.body.is_none());
        assert_eq!(request.authorization(), "Bearer test-token");
        let debug = format!("{request:?}");
        assert!(!debug.contains("test-token"));
        assert!(!debug.contains("server-observed-jkt"));
    }

    #[test]
    fn caller_supplied_proof_jkt_and_signature_tuple_has_no_adapter_path() {
        let adapter = CanonicalTransportAdapter::from_session_authority(authority());
        for operation in [
            CanonicalOperation::SendMessage,
            CanonicalOperation::UploadBlob,
            CanonicalOperation::SubscribeEvents,
        ] {
            let error = adapter
                .unsupported_operation(operation)
                .expect_err("unsupported operation must fail closed");
            assert!(error.to_string().contains("unsupported CLI operation"));
            assert!(error.to_string().contains("caller-supplied signing tuple"));
        }
    }

    #[test]
    fn entry_reads_preserve_cursor_and_reject_invalid_values() {
        let adapter = CanonicalTransportAdapter::from_session_authority(authority());
        let request = adapter
            .get_entries("conversation/1", 12, 50)
            .expect("valid entry request");
        assert_eq!(
            request.path,
            "/xrpc/blue.catbird.chat.getEntries?conversationId=conversation%2F1&afterSeq=12&limit=50"
        );
        assert!(adapter.get_entries("", 0, 50).is_err());
        assert!(adapter.get_entries("conversation", -1, 50).is_err());
        assert!(adapter.get_entries("conversation", 0, 101).is_err());
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
}
