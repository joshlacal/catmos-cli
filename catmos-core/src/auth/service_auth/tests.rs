use super::*;
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const AUD: &str = "did:web:chat.catbird.blue";
const NSID: &str = "blue.catbird.chat.getOwnDevices";

#[test]
fn service_audience_preserves_configured_did_or_service_reference() {
    assert_eq!(audience(AUD).unwrap(), AUD);
    let full = "did:web:chat.catbird.blue#atproto_mls";
    assert_eq!(audience(full).unwrap(), full);
    assert!(audience("did:web:chat.catbird.blue#").is_err());
}

fn token(claims: Value) -> String {
    format!(
        "e30.{}.c2ln",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    )
}
fn scoped_token() -> String {
    token(json!({"iss": DID, "aud": AUD, "lxm": NSID, "exp": chrono::Utc::now().timestamp()+120}))
}

#[derive(Default)]
struct Fixture {
    responses: VecDeque<(StatusCode, Value)>,
    pds_bearers: Vec<String>,
    ds_bearers: Vec<String>,
}
async fn server(
    responses: Vec<(StatusCode, Value)>,
) -> (Url, Arc<Mutex<Fixture>>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Mutex::new(Fixture {
        responses: responses.into(),
        ..Default::default()
    }));
    let app = Router::new()
        .route(
            "/xrpc/com.atproto.server.getServiceAuth",
            get(
                |State(state): State<Arc<Mutex<Fixture>>>,
                 Query(params): Query<HashMap<String, String>>,
                 headers: HeaderMap| async move {
                    assert_eq!(params["aud"], AUD);
                    assert_eq!(params["lxm"], NSID);
                    let mut state = state.lock().unwrap();
                    state
                        .pds_bearers
                        .push(headers["authorization"].to_str().unwrap().to_string());
                    let (status, body) =
                        state.responses.pop_front().expect("unexpected auth retry");
                    (status, Json(body))
                },
            ),
        )
        .route(
            "/xrpc/blue.catbird.chat.getOwnDevices",
            get(
                |State(state): State<Arc<Mutex<Fixture>>>, headers: HeaderMap| async move {
                    state
                        .lock()
                        .unwrap()
                        .ds_bearers
                        .push(headers["authorization"].to_str().unwrap().to_string());
                    Json(json!({"items": []}))
                },
            ),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, state, handle)
}

#[tokio::test]
async fn expired_session_refreshes_once_and_only_scoped_token_reaches_ds() {
    let fresh_token = scoped_token();
    let (pds, state, handle) = server(vec![
        (StatusCode::BAD_REQUEST, json!({"error": "ExpiredToken"})),
        (StatusCode::OK, json!({"token": fresh_token})),
    ])
    .await;
    let refreshes = AtomicUsize::new(0);
    let client = crate::device_records::public_client().unwrap();
    let bearer = acquire(
        &client,
        &pds,
        DID,
        AUD,
        NSID,
        "old-session-secret".into(),
        || async {
            refreshes.fetch_add(1, Ordering::Relaxed);
            Ok("refreshed-session-secret".into())
        },
    )
    .await
    .unwrap();
    client
        .get(xrpc_url(&pds, NSID))
        .bearer_auth(&bearer)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(refreshes.load(Ordering::Relaxed), 1);
    let state = state.lock().unwrap();
    assert_eq!(
        state.pds_bearers,
        [
            "Bearer old-session-secret",
            "Bearer refreshed-session-secret"
        ]
    );
    assert_eq!(state.ds_bearers, [format!("Bearer {fresh_token}")]);
    handle.abort();
}

#[tokio::test]
async fn failed_exchange_never_falls_back_to_session_or_exposes_response_secrets() {
    for response in [
        (
            StatusCode::BAD_REQUEST,
            json!({"error": "DO_NOT_EXPOSE_SESSION"}),
        ),
        (
            StatusCode::BAD_REQUEST,
            json!({"error": "InvalidRequest", "message": "DO_NOT_EXPOSE_SESSION", "token": "DO_NOT_EXPOSE_SESSION"}),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "DO_NOT_EXPOSE_SESSION/token"}),
        ),
        (
            StatusCode::OK,
            json!({"token": token(json!({"sub": DID, "aud": "did:web:pds.catbird.blue", "exp": chrono::Utc::now().timestamp()+120}))}),
        ),
        (StatusCode::OK, json!({"token": "DO_NOT_EXPOSE_SESSION"})),
    ] {
        let (pds, state, handle) = server(vec![response]).await;
        let client = crate::device_records::public_client().unwrap();
        let result: Result<()> = async {
            let bearer = acquire(
                &client,
                &pds,
                DID,
                AUD,
                NSID,
                "DO_NOT_EXPOSE_SESSION".into(),
                || async {
                    panic!("non-expiry error refreshed the session");
                },
            )
            .await?;
            client
                .get(xrpc_url(&pds, NSID))
                .bearer_auth(bearer)
                .send()
                .await
                .unwrap();
            Ok(())
        }
        .await;
        let error = result.unwrap_err().to_string();
        assert!(!error.contains("DO_NOT_EXPOSE_SESSION"));
        assert!(error.contains("device keys were preserved"));
        assert!(state.lock().unwrap().ds_bearers.is_empty());
        assert_eq!(state.lock().unwrap().pds_bearers.len(), 1);
        handle.abort();
    }
}

#[tokio::test]
async fn persistent_expiry_has_one_refresh_and_no_unbounded_retry() {
    let (pds, state, handle) = server(vec![
        (StatusCode::UNAUTHORIZED, json!({"error":"ExpiredToken"})),
        (StatusCode::UNAUTHORIZED, json!({"error":"ExpiredToken"})),
    ])
    .await;
    let refreshes = AtomicUsize::new(0);
    let result = acquire(
        &crate::device_records::public_client().unwrap(),
        &pds,
        DID,
        AUD,
        NSID,
        "old".into(),
        || async {
            refreshes.fetch_add(1, Ordering::Relaxed);
            Ok("new".into())
        },
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("ExpiredToken"));
    assert_eq!(refreshes.load(Ordering::Relaxed), 1);
    assert_eq!(state.lock().unwrap().pds_bearers.len(), 2);
    handle.abort();
}

#[test]
fn returned_service_token_requires_exact_did_audience_method_and_live_expiry() {
    assert!(validate_token(&scoped_token(), DID, AUD, NSID).is_ok());
    for (key, value) in [
        ("iss", json!("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")),
        ("aud", json!("did:web:other.catbird.blue")),
        ("lxm", json!("blue.catbird.chat.sendMessage")),
        ("exp", json!(chrono::Utc::now().timestamp() - 1)),
    ] {
        let mut claims =
            json!({"iss":DID,"aud":AUD,"lxm":NSID,"exp":chrono::Utc::now().timestamp()+120});
        claims[key] = value;
        assert!(validate_token(&token(claims), DID, AUD, NSID).is_err());
    }
}

#[tokio::test]
async fn concurrent_session_change_remains_a_typed_retry_without_second_mint() {
    let (pds, state, handle) = server(vec![(
        StatusCode::UNAUTHORIZED,
        json!({"error": "ExpiredToken"}),
    )])
    .await;
    let error = acquire(
        &crate::device_records::public_client().unwrap(),
        &pds,
        DID,
        AUD,
        NSID,
        "old-session".into(),
        || async { Err(CatmosError::AuthSessionChanged) },
    )
    .await
    .unwrap_err();
    assert!(matches!(error, CatmosError::AuthSessionChanged));
    assert_eq!(state.lock().unwrap().pds_bearers.len(), 1);
    assert!(state.lock().unwrap().ds_bearers.is_empty());
    handle.abort();
}

#[tokio::test]
async fn non_json_pds_error_preserves_http_status_without_response_body() {
    let app = Router::new().route(
        "/xrpc/com.atproto.server.getServiceAuth",
        get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "DO_NOT_EXPOSE_SESSION") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pds = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let error = acquire(
        &crate::device_records::public_client().unwrap(),
        &pds,
        DID,
        AUD,
        NSID,
        "session".into(),
        || async { panic!("invalid response must not refresh session") },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("HTTP 503"));
    assert!(!error.contains("DO_NOT_EXPOSE_SESSION"));
    handle.abort();
}
