//! A sanitized observer around Jacquard's existing transport. Credential
//! selection, refresh parsing, token rotation and storage remain in the SDK.
//! The pinned SDK's bodyless-refresh encoding is normalized at this boundary.
use std::sync::{Arc, Mutex};

use axum::http::{Method, Request, Response};
use jacquard_common::{
    error::{ClientError, ClientErrorKind},
    http_client::HttpClient,
    types::string::{Did, Handle},
    BosStr,
};
use jacquard_identity::{
    resolver::{DidDocResponse, IdentityError, IdentityResolver, ResolverOptions},
    PublicResolver,
};

use crate::error::{AuthRenewalFailure, RenewalRejection};

#[derive(Clone, Copy)]
struct Observation {
    status: u16,
    rejection: RenewalRejection,
}

#[derive(Clone, Default)]
pub(super) struct RefreshDiagnostics(Arc<Mutex<Option<Observation>>>);

impl RefreshDiagnostics {
    pub(super) fn reset(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub(super) fn classify(&self, error: &ClientError) -> AuthRenewalFailure {
        let observed = *self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(observed) = observed {
            if !(200..300).contains(&observed.status) {
                return AuthRenewalFailure::Rejected {
                    status: observed.status,
                    code: observed.rejection,
                };
            }
            // The SDK has received a successful HTTP response but could not
            // parse it. It otherwise flattens this into AuthError::RefreshFailed.
            return match error.kind() {
                ClientErrorKind::Storage => AuthRenewalFailure::MemoryState,
                _ => AuthRenewalFailure::Decode,
            };
        }
        match error.kind() {
            ClientErrorKind::Transport => AuthRenewalFailure::Transport,
            ClientErrorKind::Decode(_) => AuthRenewalFailure::Decode,
            ClientErrorKind::Http { status } => AuthRenewalFailure::Rejected {
                status: status.as_u16(),
                code: RenewalRejection::UnknownError,
            },
            ClientErrorKind::Storage => AuthRenewalFailure::MemoryState,
            _ => AuthRenewalFailure::InvalidSnapshot,
        }
    }
}

pub(super) struct ObservedResolver {
    inner: PublicResolver,
    diagnostics: RefreshDiagnostics,
}

impl ObservedResolver {
    pub(super) fn new(diagnostics: RefreshDiagnostics) -> Self {
        Self {
            inner: PublicResolver::default(),
            diagnostics,
        }
    }
}

impl HttpClient for ObservedResolver {
    type Error = IdentityError;

    async fn send_http(
        &self,
        mut request: Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, Self::Error> {
        let is_refresh = is_refresh_request(&request);
        normalize_bodyless_refresh(&mut request);
        let response = self.inner.send_http(request).await?;
        if is_refresh {
            // Never retain request headers, the body, arbitrary server text or
            // JWT claims. Only these closed enum values can reach errors/logs.
            let rejection = if response.status().is_success() || response.body().len() > 16 * 1024 {
                RenewalRejection::UnknownError
            } else {
                let value: Option<serde_json::Value> = serde_json::from_slice(response.body()).ok();
                RenewalRejection::from_code(
                    value
                        .as_ref()
                        .and_then(|v| v.get("error"))
                        .and_then(|v| v.as_str()),
                )
            };
            *self.diagnostics.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(Observation {
                status: response.status().as_u16(),
                rejection,
            });
        }
        Ok(response)
    }
}

impl IdentityResolver for ObservedResolver {
    fn options(&self) -> &ResolverOptions {
        self.inner.options()
    }
    async fn resolve_handle<S: BosStr + Sync>(
        &self,
        handle: &Handle<S>,
    ) -> Result<Did, IdentityError> {
        self.inner.resolve_handle(handle).await
    }
    async fn resolve_did_doc<S: BosStr + Sync>(
        &self,
        did: &Did<S>,
    ) -> Result<DidDocResponse, IdentityError> {
        self.inner.resolve_did_doc(did).await
    }
}

fn is_refresh_request(request: &Request<Vec<u8>>) -> bool {
    request.method() == Method::POST
        && request
            .uri()
            .path()
            .ends_with("/xrpc/com.atproto.server.refreshSession")
}

fn normalize_bodyless_refresh(request: &mut Request<Vec<u8>>) {
    use axum::http::{header, HeaderValue};
    // Jacquard 3287244's hand-written common::xrpc::atproto::RefreshSession
    // inherits serde's unit encoding (JSON null). The refresh lexicon has no
    // input, so PDS input verification rejects that four-byte body. Keep the
    // SDK's credential/rotation flow and repair only this exact encoding.
    // A future SDK that already emits an empty body passes through unchanged.
    if !is_refresh_request(request)
        || request.body().as_slice() != b"null"
        || !request
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v == "application/json")
    {
        return;
    }
    request.body_mut().clear();
    request.headers_mut().remove(header::TRANSFER_ENCODING);
    request
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use axum::http::{header, HeaderValue};

    #[test]
    fn sdk_null_refresh_becomes_bodyless_without_changing_authority() {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("https://pds.example.test/base/xrpc/com.atproto.server.refreshSession")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, "4")
            .header(header::TRANSFER_ENCODING, "chunked")
            .header(header::AUTHORIZATION, "Bearer fixture-refresh")
            .header("x-fixture", "unchanged")
            .body(b"null".to_vec())
            .unwrap();
        let uri = request.uri().clone();
        let authority = request.headers()[header::AUTHORIZATION].clone();
        normalize_bodyless_refresh(&mut request);
        assert!(request.body().is_empty());
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri(), &uri);
        assert!(request.headers()[header::AUTHORIZATION] == authority);
        assert_eq!(request.headers()["x-fixture"], "unchanged");
        assert_eq!(request.headers()[header::CONTENT_LENGTH], "0");
        assert!(!request.headers().contains_key(header::TRANSFER_ENCODING));
    }

    #[test]
    fn correct_empty_and_other_requests_are_unchanged() {
        for (method, path, content_type, body) in [
            (
                Method::POST,
                "/xrpc/com.atproto.server.refreshSession",
                "application/json",
                b"".as_slice(),
            ),
            (
                Method::GET,
                "/xrpc/com.atproto.server.refreshSession",
                "application/json",
                b"null".as_slice(),
            ),
            (
                Method::POST,
                "/xrpc/com.atproto.server.createSession",
                "application/json",
                b"null".as_slice(),
            ),
            (
                Method::POST,
                "/xrpc/com.atproto.server.refreshSession",
                "application/json",
                b"{}".as_slice(),
            ),
            (
                Method::POST,
                "/xrpc/com.atproto.server.refreshSession",
                "application/octet-stream",
                b"null".as_slice(),
            ),
        ] {
            let mut request = Request::builder()
                .method(method)
                .uri(format!("https://pds.example.test{path}"))
                .header(header::CONTENT_TYPE, content_type)
                .header(
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&body.len().to_string()).unwrap(),
                )
                .body(body.to_vec())
                .unwrap();
            let headers = request.headers().clone();
            let uri = request.uri().clone();
            let method = request.method().clone();
            normalize_bodyless_refresh(&mut request);
            assert_eq!(request.body().as_slice(), body);
            assert_eq!(request.headers(), &headers);
            assert_eq!(request.uri(), &uri);
            assert_eq!(request.method(), method);
        }
    }
}
