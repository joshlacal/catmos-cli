//! Obtain method-scoped delivery-service tokens without sending PDS session
//! credentials to the delivery service when token exchange fails.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use catbird_mls::chat_v2::ids::BareDid;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use url::Url;

use crate::device_records::{response_json, xrpc_url};
use crate::error::{CatmosError, RenewalRejection, Result};

pub(crate) fn audience(proxy: &str) -> Result<&str> {
    let did = match proxy.split_once('#') {
        Some((did, service))
            if !service.is_empty()
                && service
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte)) =>
        {
            did
        }
        Some(_) => {
            return Err(CatmosError::Config(
                "Chat service authentication audience has an invalid service reference".into(),
            ))
        }
        None => proxy,
    };
    BareDid::parse(did).map_err(|_| {
        CatmosError::Config(
            "Chat service authentication audience must be a DID or DID service reference".into(),
        )
    })?;
    Ok(proxy)
}

fn failure(message: &str) -> CatmosError {
    CatmosError::AuthFailed(format!("Could not obtain chat service authorization: {message}. Please retry or log in again; device keys were preserved"))
}

fn error_code(value: &Value) -> RenewalRejection {
    RenewalRejection::from_code(value.get("error").and_then(Value::as_str))
}

fn validate_token(token: &str, did: &str, aud: &str, nsid: &str) -> Result<()> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 || segments.iter().any(|part| part.is_empty()) {
        return Err(failure("PDS returned an invalid service token"));
    }
    let claims: Value = URL_SAFE_NO_PAD
        .decode(segments[1])
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| failure("PDS returned invalid service token claims"))?;
    if claims.get("iss").and_then(Value::as_str) != Some(did)
        || claims.get("aud").and_then(Value::as_str) != Some(aud)
        || claims.get("lxm").and_then(Value::as_str) != Some(nsid)
        || !claims
            .get("exp")
            .and_then(Value::as_i64)
            .is_some_and(|exp| exp > chrono::Utc::now().timestamp())
    {
        return Err(failure(
            "PDS returned a token without the required issuer, audience, method, or validity",
        ));
    }
    Ok(())
}

pub(crate) async fn acquire<F, Fut>(
    client: &Client,
    pds: &Url,
    did: &str,
    aud: &str,
    nsid: &str,
    initial_bearer: String,
    refresh: F,
) -> Result<String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    let mut url = xrpc_url(pds, "com.atproto.server.getServiceAuth");
    url.query_pairs_mut()
        .append_pair("aud", aud)
        .append_pair("lxm", nsid);
    let send = |bearer: String| {
        let url = url.clone();
        async move {
            let response = client
                .get(url)
                .bearer_auth(bearer)
                .send()
                .await
                .map_err(|_| failure("PDS token request failed"))?;
            let status = response.status();
            let body = response_json(response).await.map_err(|_| {
                failure(&format!(
                    "PDS returned HTTP {} with an invalid authorization response",
                    status.as_u16()
                ))
            })?;
            Ok::<_, CatmosError>((status, body))
        }
    };
    let (mut status, mut body) = send(initial_bearer).await?;
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST)
        && error_code(&body) == RenewalRejection::ExpiredToken
    {
        let refreshed = match refresh().await {
            Ok(bearer) => bearer,
            Err(error @ (CatmosError::AuthSessionChanged | CatmosError::AuthRenewal(_))) => {
                return Err(error)
            }
            Err(_) => return Err(failure("PDS session renewal and persistence failed")),
        };
        (status, body) = send(refreshed).await?;
    }
    if !status.is_success() {
        return Err(failure(&format!(
            "PDS returned HTTP {} ({}) for {nsid}",
            status.as_u16(),
            error_code(&body)
        )));
    }
    let token = body
        .get("token")
        .and_then(Value::as_str)
        .filter(|token| token.len() <= 16 * 1024)
        .ok_or_else(|| failure("PDS omitted its service token"))?;
    validate_token(token, did, aud, nsid)?;
    Ok(token.to_string())
}

#[cfg(test)]
mod tests;
