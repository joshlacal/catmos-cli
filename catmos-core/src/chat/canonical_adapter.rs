//! Native adapter for the generated `blue.catbird.chat.*` transport.
//!
//! This layer deliberately accepts the authenticated DPoP material and, for
//! signed mutations, the already-signed generated DTO from the caller. The
//! CLI does not own a DPoP key or an application Ed25519 signer, so it must
//! never manufacture either value from an ATProto bearer token or an MLS
//! public key. Until the auth/device integration supplies those exact values,
//! the existing legacy calls remain the only live path.

use catbird_mls::orchestrator::{
    prepare_clean_chat_request, prepare_get_conversations, prepare_get_entries, CanonicalOperation,
    CleanChatAuthContext, CleanChatAuthContextFfi, CleanChatOperationFfi, PreparedRequest,
    TransportError,
};

use crate::error::{CatmosError, Result};

/// Explicit caller-owned canonical transport context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalAuth {
    pub authorization: String,
    pub dpop_proof: String,
    pub dpop_jkt: String,
    pub device_id: String,
    pub auth_generation: Option<i64>,
}

impl CanonicalAuth {
    pub fn new(
        authorization: String,
        dpop_proof: String,
        dpop_jkt: String,
        device_id: String,
    ) -> Self {
        Self {
            authorization,
            dpop_proof,
            dpop_jkt,
            device_id,
            auth_generation: None,
        }
    }

    pub fn with_auth_generation(mut self, generation: i64) -> Self {
        self.auth_generation = Some(generation);
        self
    }

    fn into_mls(self) -> CleanChatAuthContext {
        let context = CleanChatAuthContext::new(
            self.authorization,
            self.dpop_proof,
            self.dpop_jkt,
            self.device_id,
        );
        match self.auth_generation {
            Some(generation) => context.with_auth_generation(generation),
            None => context,
        }
    }
}

/// Small native adapter that prepares canonical requests for the existing
/// HTTP client. It does not send requests and does not access private keys.
#[derive(Clone, Debug)]
pub struct CanonicalTransportAdapter {
    auth: CanonicalAuth,
}

impl CanonicalTransportAdapter {
    pub fn new(auth: CanonicalAuth) -> Self {
        Self { auth }
    }

    /// Prepare the safest unsigned canonical read route.
    pub fn get_conversations(
        &self,
        limit: i64,
        page_cursor: Option<&str>,
    ) -> Result<PreparedRequest> {
        prepare_get_conversations(&self.auth.clone().into_mls(), limit, page_cursor)
            .map_err(map_transport_error)
    }

    /// Prepare the safest unsigned canonical entry read route.
    pub fn get_entries(
        &self,
        conversation_id: &str,
        after_seq: i64,
        limit: i64,
    ) -> Result<PreparedRequest> {
        prepare_get_entries(
            &self.auth.clone().into_mls(),
            conversation_id,
            after_seq,
            limit,
        )
        .map_err(map_transport_error)
    }

    /// Prepare a request whose generated DTO has already been signed by the
    /// platform/device adapter. This is intentionally not a signer: unsigned
    /// or incorrectly bound JSON is rejected by the canonical transport.
    /// Task 9 live-command wiring remains blocked until a trusted device-bound
    /// DPoP and application-signer provider supplies those caller-owned values.
    pub fn prepare_signed_json(
        &self,
        operation: CanonicalOperation,
        request_json: Vec<u8>,
    ) -> Result<PreparedRequest> {
        let operation = match operation {
            CanonicalOperation::UploadBlob | CanonicalOperation::SubscribeEvents => {
                return Err(CatmosError::Other(
                    "canonical blob upload and event subscription require dedicated media adapters"
                        .into(),
                ));
            }
            other => other,
        };

        // The native public API is exposed through the UniFFI-compatible
        // operation enum. This conversion keeps the mapping explicit and
        // prevents accidentally routing unsupported media operations.
        let ffi_operation = operation_to_ffi(operation);
        let prepared = prepare_clean_chat_request(
            CleanChatAuthContextFfi {
                authorization: self.auth.authorization.clone(),
                dpop_proof: self.auth.dpop_proof.clone(),
                dpop_jkt: self.auth.dpop_jkt.clone(),
                device_id: self.auth.device_id.clone(),
                auth_generation: self.auth.auth_generation,
            },
            ffi_operation,
            request_json,
        )
        .map_err(|error| CatmosError::Other(format!("canonical transport: {error}")))?;

        // Task 1's FFI intentionally makes transport credentials optional so
        // Nest-proxy adapters can attach them outside the signer. Keep this
        // native consumer fail-closed. The release provenance guard rejects
        // older sibling checkouts instead of masking an API mismatch here.
        Ok(PreparedRequest {
            operation,
            method: prepared.method,
            path: prepared.path,
            authorization: require_transport_credential(prepared.authorization, "authorization")?,
            dpop: require_transport_credential(prepared.dpop, "dpop")?,
            body: prepared.body,
        })
    }
}

fn require_transport_credential(value: Option<String>, field: &str) -> Result<String> {
    value.ok_or_else(|| CatmosError::Other(format!("canonical transport: missing {field}")))
}

fn map_transport_error(error: TransportError) -> CatmosError {
    CatmosError::Other(format!("canonical transport: {error}"))
}

fn operation_to_ffi(operation: CanonicalOperation) -> CleanChatOperationFfi {
    match operation {
        CanonicalOperation::AcceptConversation => CleanChatOperationFfi::AcceptConversation,
        CanonicalOperation::AcknowledgeWelcome => CleanChatOperationFfi::AcknowledgeWelcome,
        CanonicalOperation::ActivateReset => CleanChatOperationFfi::ActivateReset,
        CanonicalOperation::CancelLeafRecovery => CleanChatOperationFfi::CancelLeafRecovery,
        CanonicalOperation::CancelLeave => CleanChatOperationFfi::CancelLeave,
        CanonicalOperation::CloseConversation => CleanChatOperationFfi::CloseConversation,
        CanonicalOperation::GetConversations => CleanChatOperationFfi::GetConversations,
        CanonicalOperation::CreateConversation => CleanChatOperationFfi::CreateConversation,
        CanonicalOperation::DeleteBlob => CleanChatOperationFfi::DeleteBlob,
        CanonicalOperation::SendMessage => CleanChatOperationFfi::SendMessage,
        CanonicalOperation::GetBlob => CleanChatOperationFfi::GetBlob,
        CanonicalOperation::GetBlobUsage => CleanChatOperationFfi::GetBlobUsage,
        CanonicalOperation::GetConversationState => CleanChatOperationFfi::GetConversationState,
        CanonicalOperation::GetDevices => CleanChatOperationFfi::GetDevices,
        CanonicalOperation::GetEntries => CleanChatOperationFfi::GetEntries,
        CanonicalOperation::GetLeafRecoveryInbox => CleanChatOperationFfi::GetLeafRecoveryInbox,
        CanonicalOperation::GetOwnDevices => CleanChatOperationFfi::GetOwnDevices,
        CanonicalOperation::GetPendingWelcomes => CleanChatOperationFfi::GetPendingWelcomes,
        CanonicalOperation::GetSubscriptionTicket => CleanChatOperationFfi::GetSubscriptionTicket,
        CanonicalOperation::PrepareBlobUpload => CleanChatOperationFfi::PrepareBlobUpload,
        CanonicalOperation::PublishTyping => CleanChatOperationFfi::PublishTyping,
        CanonicalOperation::RebindDeviceAuthentication => {
            CleanChatOperationFfi::RebindDeviceAuthentication
        }
        CanonicalOperation::RejectWelcome => CleanChatOperationFfi::RejectWelcome,
        CanonicalOperation::ReplenishKeyPackages => CleanChatOperationFfi::ReplenishKeyPackages,
        CanonicalOperation::RequestLeafRecovery => CleanChatOperationFfi::RequestLeafRecovery,
        CanonicalOperation::EnrollDevice => CleanChatOperationFfi::EnrollDevice,
        CanonicalOperation::RequestLeave => CleanChatOperationFfi::RequestLeave,
        CanonicalOperation::RequestReset => CleanChatOperationFfi::RequestReset,
        CanonicalOperation::RevokeDevice => CleanChatOperationFfi::RevokeDevice,
        CanonicalOperation::SubmitTransition => CleanChatOperationFfi::SubmitTransition,
        CanonicalOperation::SubscribeEvents | CanonicalOperation::UploadBlob => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(jkt: &str) -> CanonicalAuth {
        CanonicalAuth::new(
            "Bearer test-token".into(),
            "dpop-proof".into(),
            jkt.into(),
            "00000000-0000-4000-8000-000000000001".into(),
        )
    }

    #[test]
    fn reads_reject_invalid_dpop_context_before_http() {
        let err = CanonicalTransportAdapter::new(auth("not-a-jkt"))
            .get_conversations(20, None)
            .expect_err("invalid JKT must fail closed");
        assert!(err.to_string().contains("canonical transport"));
    }

    #[test]
    fn media_operations_are_typed_fail_closed() {
        let adapter = CanonicalTransportAdapter::new(auth("not-a-jkt"));
        for operation in [
            CanonicalOperation::UploadBlob,
            CanonicalOperation::SubscribeEvents,
        ] {
            let err = adapter
                .prepare_signed_json(operation, b"{}".to_vec())
                .expect_err("media operations have no JSON-only adapter");
            assert!(err.to_string().contains("dedicated media adapters"));
        }
    }

    #[test]
    fn valid_read_prepares_generated_canonical_route_and_auth() {
        let adapter =
            CanonicalTransportAdapter::new(auth("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        let request = adapter
            .get_conversations(20, Some("cursor-1"))
            .expect("valid transport context");
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/xrpc/blue.catbird.chat.getConversations?limit=20&pageCursor=cursor-1"
        );
        assert_eq!(request.authorization, "Bearer test-token");
        assert_eq!(request.dpop, "dpop-proof");
        assert!(request.body.is_none());
    }

    #[test]
    fn missing_optional_transport_credential_fails_closed() {
        let error = require_transport_credential(None, "dpop")
            .expect_err("missing optional FFI credential must fail closed");
        assert!(error.to_string().contains("missing dpop"));
    }
}
