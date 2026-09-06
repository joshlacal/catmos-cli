use super::*;
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const HANDLE: &str = "actor.catbird.blue";
const SECRET: &str = "DO_NOT_EXPOSE_REFRESH_SECRET";

async fn fixture(pds: String) -> (tempfile::TempDir, Database, TokenSession) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("auth.db"), "test-only-sqlcipher-key")
        .await
        .unwrap();
    let session =
        TokenSession::restore(HANDLE.into(), DID.into(), SECRET.into(), SECRET.into(), pds)
            .await
            .unwrap();
    session.persist(&db).await.unwrap();
    db.store_session_value("device_uuid", "preserved-device")
        .await
        .unwrap();
    (dir, db, session)
}

#[tokio::test]
async fn renewal_response_classification_survives_sdk_and_service_exchange_without_secrets() {
    for (status, body, expected) in [
        (
            StatusCode::BAD_REQUEST,
            json!({"error":"InvalidToken","message":SECRET}).to_string(),
            "HTTP 400 (InvalidToken)",
        ),
        (
            StatusCode::UNAUTHORIZED,
            json!({"error":"ExpiredToken","message":SECRET}).to_string(),
            "HTTP 401 (ExpiredToken)",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":SECRET,"message":SECRET}).to_string(),
            "HTTP 503 (UnknownError)",
        ),
        (
            StatusCode::OK,
            SECRET.to_string(),
            "invalid refresh response",
        ),
    ] {
        let app = Router::new()
            .route(
                "/xrpc/com.atproto.server.getServiceAuth",
                get(|| async {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error":"ExpiredToken"})),
                    )
                }),
            )
            .route(
                "/xrpc/com.atproto.server.refreshSession",
                post(move |headers: axum::http::HeaderMap| {
                    let body = body.clone();
                    async move {
                        assert!(
                            headers["authorization"].as_bytes()
                                == format!("Bearer {SECRET}").as_bytes()
                        );
                        (
                            status,
                            [(axum::http::header::WWW_AUTHENTICATE, SECRET)],
                            body,
                        )
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pds = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (_dir, db, session) = fixture(pds.clone()).await;
        let error = crate::auth::service_auth::acquire(
            &reqwest::Client::new(),
            &url::Url::parse(&pds).unwrap(),
            DID,
            "did:web:chat.catbird.blue",
            "blue.catbird.chat.getOwnDevices",
            SECRET.into(),
            || session.refresh(&db),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CatmosError::AuthRenewal(_)));
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET) && !debug.contains(SECRET));
        assert!(
            display.contains(expected),
            "missing safe category: {display}"
        );
        assert!(db.get_session_value("access_jwt").await.unwrap().as_deref() == Some(SECRET));
        assert!(
            db.get_session_value("refresh_jwt")
                .await
                .unwrap()
                .as_deref()
                == Some(SECRET)
        );
        assert_eq!(
            db.get_session_value("device_uuid")
                .await
                .unwrap()
                .as_deref(),
            Some("preserved-device")
        );
        db.pool_for_test().close().await;
        server.abort();
    }
}

#[tokio::test]
async fn renewal_transport_and_snapshot_read_are_distinct_and_redacted() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let pds = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let (_dir, db, session) = fixture(pds).await;
    let error = session.refresh(&db).await.unwrap_err();
    assert!(matches!(
        error,
        CatmosError::AuthRenewal(AuthRenewalFailure::Transport)
    ));
    let text = error.to_string();
    assert!(!text.contains(SECRET));
    assert!(
        text.contains("network transport"),
        "missing safe category: {text}"
    );
    db.pool_for_test().close().await;
    let error = session.refresh(&db).await.unwrap_err();
    assert!(matches!(
        error,
        CatmosError::AuthRenewal(AuthRenewalFailure::ReadSnapshot)
    ));
    assert!(error.to_string().contains("read saved session"));
}

#[tokio::test]
async fn renewal_write_failure_is_redacted_and_keeps_durable_pair() {
    let app=Router::new().route("/xrpc/com.atproto.server.refreshSession",post(||async {
        Json(json!({"did":DID,"handle":HANDLE,"accessJwt":"next-access","refreshJwt":"next-refresh"}))
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pds = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (_dir, db, session) = fixture(pds).await;
    sqlx::query("CREATE TRIGGER fail_refresh BEFORE INSERT ON session WHEN NEW.key='refresh_jwt' BEGIN SELECT RAISE(ABORT, 'DO_NOT_EXPOSE_REFRESH_SECRET'); END").execute(db.pool_for_test()).await.unwrap();
    let error = session.refresh(&db).await.unwrap_err();
    assert!(matches!(
        error,
        CatmosError::AuthRenewal(AuthRenewalFailure::PersistSnapshot)
    ));
    let text = error.to_string();
    let debug = format!("{error:?}");
    assert!(
        !text.contains(SECRET) && !debug.contains(SECRET),
        "storage details escaped"
    );
    assert!(text.contains("save renewed session"));
    assert!(session.current_bearer().await.unwrap() == SECRET);
    assert!(db.get_session_value("access_jwt").await.unwrap().as_deref() == Some(SECRET));
    assert!(
        db.get_session_value("refresh_jwt")
            .await
            .unwrap()
            .as_deref()
            == Some(SECRET)
    );
    db.pool_for_test().close().await;
    server.abort();
}

#[tokio::test]
async fn renewal_has_no_input_body_as_required_by_the_pds_verifier() {
    let app=Router::new().route("/xrpc/com.atproto.server.refreshSession",post(|headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
        // Reference PDS getBodyPresence: Transfer-Encoding means present;
        // Content-Length 0 means empty; any other Content-Length means present.
        // The private wire proof also runs the actual upstream JS verifier.
        let present=headers.contains_key(axum::http::header::TRANSFER_ENCODING)
            || headers.get(axum::http::header::CONTENT_LENGTH).is_some_and(|v|v!="0");
        if present {
            return (StatusCode::BAD_REQUEST,Json(json!({"error":"InvalidRequest","message":"A request body was provided when none was expected"})));
        }
        assert!(body.is_empty());
        assert!(headers["authorization"].as_bytes()==format!("Bearer {SECRET}").as_bytes());
        (StatusCode::OK,Json(json!({"did":DID,"handle":HANDLE,"accessJwt":"renewed-access","refreshJwt":"renewed-refresh"})))
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pds = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (_dir, db, session) = fixture(pds).await;
    assert!(
        session.refresh(&db).await.is_ok(),
        "SDK sent input to the bodyless refresh procedure"
    );
    assert_eq!(
        db.get_session_value("access_jwt").await.unwrap().as_deref(),
        Some("renewed-access")
    );
    assert_eq!(
        db.get_session_value("refresh_jwt")
            .await
            .unwrap()
            .as_deref(),
        Some("renewed-refresh")
    );
    assert_eq!(
        db.get_session_value("device_uuid")
            .await
            .unwrap()
            .as_deref(),
        Some("preserved-device")
    );
    db.pool_for_test().close().await;
    server.abort();
}
