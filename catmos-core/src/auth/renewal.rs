//! Bodyless AT Protocol session renewal through Petrel's bounded native transport.
//! Keep status and known rejection codes available to the service-auth retry policy.
use crate::error::{AuthRenewalFailure, RenewalRejection};
use axum::http::{header, Request};
use bytes::Bytes;
use petrel::net::{SendOptions, SharedTransport};
use petrel_api::generated::com::atproto::server::refresh_session;

pub(super) async fn refresh(
    transport: &SharedTransport,
    pds_url: &str,
    refresh_jwt: &str,
) -> Result<refresh_session::Output, AuthRenewalFailure> {
    let endpoint = format!(
        "{}/xrpc/{}",
        pds_url.trim_end_matches('/'),
        refresh_session::NSID
    );
    let request = Request::post(endpoint)
        .header(header::ACCEPT, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {refresh_jwt}"))
        .body(Bytes::new())
        .map_err(|_| AuthRenewalFailure::InvalidSnapshot)?;
    let mut options = SendOptions::new();
    options.allow_loopback = cfg!(test);
    options.max_response_bytes = Some(512 * 1024);
    let response = transport
        .send_dyn(request, &options)
        .await
        .map_err(|_| AuthRenewalFailure::Transport)?;
    if !response.status().is_success() {
        let details: Option<serde_json::Value> = (response.body().len() <= 16 * 1024)
            .then(|| serde_json::from_slice(response.body()).ok())
            .flatten();
        let code = RenewalRejection::from_code(
            details
                .as_ref()
                .and_then(|v| v.get("error"))
                .and_then(|v| v.as_str()),
        );
        return Err(AuthRenewalFailure::Rejected {
            status: response.status().as_u16(),
            code,
        });
    }
    let output: refresh_session::Output =
        petrel_core::from_json(response.body()).map_err(|_| AuthRenewalFailure::Decode)?;
    if output.access_jwt.is_empty() || output.refresh_jwt.is_empty() {
        return Err(AuthRenewalFailure::Decode);
    }
    Ok(output)
}
