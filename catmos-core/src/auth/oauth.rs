use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use rand::TryRng;
use tokio::sync::oneshot;
use url::Url;

use crate::error::{CatmosError, Result};
use crate::storage::db::Database;

/// Authentication via OAuth loopback flow through the nest BFF.
pub struct OAuthAuth {
    pub session_cookie: String,
    pub did: String,
    pub handle: String,
    pub nest_url: String,
}

/// The callback carries only a short-lived, single-use exchange code.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CallbackParams {
    code: Option<String>,
}

#[derive(serde::Serialize)]
struct ExchangeRequest<'a> {
    code: &'a str,
    browser_nonce: &'a str,
}

#[derive(serde::Deserialize)]
struct ExchangeResponse {
    session_id: String,
}

/// Response from `GET {nest_url}/auth/session` with the session cookie.
#[derive(Debug, serde::Deserialize)]
struct SessionResponse {
    did: String,
    handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthSessionInfo {
    pub did: String,
    pub handle: String,
}

struct CallbackState {
    pending: std::sync::Mutex<Option<PendingCallback>>,
}

struct PendingCallback {
    tx: oneshot::Sender<PendingExchange>,
    browser_nonce: String,
}

struct PendingExchange {
    code: String,
    browser_nonce: String,
}

impl CallbackState {
    fn new(tx: oneshot::Sender<PendingExchange>, browser_nonce: String) -> Self {
        Self {
            pending: std::sync::Mutex::new(Some(PendingCallback { tx, browser_nonce })),
        }
    }

    fn deliver(&self, code: String) -> bool {
        if code.len() != 43
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return false;
        }
        let Some(pending) = self.pending.lock().unwrap().take() else {
            return false;
        };
        pending
            .tx
            .send(PendingExchange {
                code,
                browser_nonce: pending.browser_nonce,
            })
            .is_ok()
    }
}

const MAX_OAUTH_RESPONSE_BYTES: usize = 16 * 1024;

fn generate_browser_nonce() -> Result<String> {
    let mut bytes = [0_u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| CatmosError::AuthFailed(format!("OS randomness unavailable: {e}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn build_login_url(
    nest_url: &str,
    handle: &str,
    redirect_to: &str,
    browser_nonce: &str,
) -> Result<Url> {
    let mut url = Url::parse(&format!("{}/auth/login", nest_url.trim_end_matches('/')))
        .map_err(|e| CatmosError::Network(format!("invalid Nest URL: {e}")))?;
    url.query_pairs_mut()
        .append_pair("identifier", handle)
        .append_pair("client", "catmos")
        .append_pair("redirect_to", redirect_to)
        .append_pair("browser_nonce", browser_nonce);
    Ok(url)
}

fn build_oauth_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(tokio::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CatmosError::Network(format!("failed to build HTTP client: {e}")))
}

async fn read_bounded_response(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_OAUTH_RESPONSE_BYTES as u64)
    {
        return Err(CatmosError::AuthFailed(
            "OAuth response exceeded size limit".into(),
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| CatmosError::Network(format!("failed to read OAuth exchange response: {e}")))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_OAUTH_RESPONSE_BYTES {
            return Err(CatmosError::AuthFailed(
                "OAuth response exceeded size limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn fetch_session_info(
    http: &reqwest::Client,
    nest_url: &str,
    session_id: &str,
) -> Result<SessionResponse> {
    let response = http
        .get(format!("{}/auth/session", nest_url.trim_end_matches('/')))
        .header("Cookie", format!("catbird_session={session_id}"))
        .send()
        .await
        .map_err(|e| CatmosError::Network(format!("failed to validate OAuth session: {e}")))?;
    let status = response.status();
    let body = read_bounded_response(response).await;

    if !status.is_success() {
        // Drain through the bounded reader, but never surface an upstream body
        // (which may contain credentials or attacker-controlled diagnostics).
        let _ = body;
        return Err(CatmosError::AuthFailed(
            "OAuth session validation failed".into(),
        ));
    }

    let body = body?;
    serde_json::from_slice(&body)
        .map_err(|_| CatmosError::AuthFailed("OAuth session validation failed".into()))
}

async fn redeem_exchange(
    http: &reqwest::Client,
    nest_url: &str,
    origin: &str,
    code: &str,
    browser_nonce: &str,
) -> Result<String> {
    let response = http
        .post(format!("{}/auth/exchange", nest_url.trim_end_matches('/')))
        .header(reqwest::header::ORIGIN, origin)
        .json(&ExchangeRequest {
            code,
            browser_nonce,
        })
        .send()
        .await
        .map_err(|e| CatmosError::Network(format!("OAuth exchange failed: {e}")))?;

    if !response.status().is_success() {
        return Err(CatmosError::AuthFailed("OAuth exchange failed".into()));
    }
    let body = read_bounded_response(response).await?;
    let exchange: ExchangeResponse = serde_json::from_slice(&body)
        .map_err(|_| CatmosError::AuthFailed("OAuth exchange failed".into()))?;
    if exchange.session_id.is_empty() {
        return Err(CatmosError::AuthFailed("OAuth exchange failed".into()));
    }
    Ok(exchange.session_id)
}

impl OAuthAuth {
    /// Start an OAuth loopback login flow.
    ///
    /// 1. Bind a local TCP listener on a random port
    /// 2. Open the browser to the nest auth URL with a redirect back to localhost
    /// 3. Wait up to 2 minutes for the callback with an opaque exchange code
    /// 4. Redeem the code and locally retained nonce, then fetch session identity
    pub async fn login(handle: &str, nest_url: &str) -> Result<Self> {
        let nest_url = nest_url.trim_end_matches('/');
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| CatmosError::Network(format!("failed to bind loopback listener: {e}")))?;

        let port = listener
            .local_addr()
            .map_err(|e| CatmosError::Network(e.to_string()))?
            .port();

        let redirect_to = format!("http://127.0.0.1:{port}/callback");
        let redirect_url = Url::parse(&redirect_to)
            .map_err(|e| CatmosError::Network(format!("invalid loopback redirect: {e}")))?;
        let redirect_origin = redirect_url.origin().ascii_serialization();
        let browser_nonce = generate_browser_nonce()?;
        let auth_url = build_login_url(nest_url, handle, &redirect_to, &browser_nonce)?;

        let (tx, rx) = oneshot::channel::<PendingExchange>();
        let state = Arc::new(CallbackState::new(tx, browser_nonce));

        let app = Router::new()
            .route("/callback", get(handle_callback))
            .with_state(state);

        // Open the browser
        tracing::info!("Opening browser for authentication...");
        if let Err(e) = open::that(auth_url.as_str()) {
            tracing::warn!("Failed to open browser: {e}");
            eprintln!("Open this URL in your browser to log in:\n  {auth_url}");
        }

        // Serve the callback endpoint
        let server = axum::serve(listener, app);
        let timeout = tokio::time::Duration::from_secs(120);

        // Race the server against a 2-minute timeout
        let pending = tokio::select! {
            result = rx => {
                result.map_err(|_| CatmosError::AuthFailed("callback channel closed".into()))
            }
            _ = async {
                // Run server until the callback fires or timeout
                let _ = server.await;
            } => {
                Err(CatmosError::AuthFailed("server exited unexpectedly".into()))
            }
            _ = tokio::time::sleep(timeout) => {
                Err(CatmosError::AuthFailed("login timed out after 2 minutes".into()))
            }
        }?;

        let http = build_oauth_http_client()?;
        let session_id = redeem_exchange(
            &http,
            nest_url,
            &redirect_origin,
            &pending.code,
            &pending.browser_nonce,
        )
        .await?;

        // Fetch DID + handle with the newly issued credential.
        let session_info = fetch_session_info(&http, nest_url, &session_id).await?;

        Ok(Self {
            session_cookie: session_id,
            did: session_info.did,
            handle: session_info.handle,
            nest_url: nest_url.to_string(),
        })
    }

    /// Persist OAuth session to the session store.
    pub async fn save(&self, db: &Database) -> Result<()> {
        db.store_session_value("auth_method", "oauth").await?;
        db.store_session_value("session_cookie", &self.session_cookie)
            .await?;
        db.store_session_value("did", &self.did).await?;
        db.store_session_value("handle", &self.handle).await?;
        db.store_session_value("nest_url", &self.nest_url).await?;
        Ok(())
    }

    /// Load previously-saved OAuth auth from the session store.
    pub async fn load(db: &Database) -> Result<Option<Self>> {
        let method = db.get_session_value("auth_method").await?;
        if method.as_deref() != Some("oauth") {
            return Ok(None);
        }

        let session_cookie = db.get_session_value("session_cookie").await?;
        let did = db.get_session_value("did").await?;
        let handle = db.get_session_value("handle").await?;
        let nest_url = db.get_session_value("nest_url").await?;

        match (session_cookie, did, nest_url) {
            (Some(session_cookie), Some(did), Some(nest_url)) => Ok(Some(Self {
                session_cookie,
                did,
                handle: handle.unwrap_or_default(),
                nest_url,
            })),
            _ => Ok(None),
        }
    }

    /// Validate a restored Nest session before the caller starts MLS side
    /// effects. OAuth sessions are server-side cookies, not refreshable ATProto
    /// JWTs, so a stale cookie must fail fast instead of letting the first MLS
    /// maintenance request surface a noisy 401.
    pub async fn validate_for_did(&self, expected_did: &str) -> Result<OAuthSessionInfo> {
        let http = build_oauth_http_client()?;
        let nest_url = self.nest_url.trim_end_matches('/');
        let session_info = fetch_session_info(&http, nest_url, &self.session_cookie).await?;

        if session_info.did != expected_did || self.did != expected_did {
            return Err(CatmosError::AuthFailed(format!(
                "restored OAuth session DID mismatch: expected {expected_did}, stored {}, server returned {}. Run `catmos login` again.",
                self.did, session_info.did
            )));
        }

        Ok(OAuthSessionInfo {
            did: session_info.did,
            handle: session_info.handle,
        })
    }
}

async fn handle_callback(
    State(state): State<Arc<CallbackState>>,
    Query(params): Query<CallbackParams>,
) -> Html<String> {
    let code = match params.code {
        Some(s) => s,
        None => {
            return Html(
                "<html><body><h1>Login failed</h1><p>Missing exchange code.</p></body></html>"
                    .to_string(),
            );
        }
    };

    if !state.deliver(code) {
        return Html(
            "<html><body><h1>Login failed</h1><p>This callback was already used.</p></body></html>"
                .to_string(),
        );
    }

    Html(
        "<html><body><h1>Login successful!</h1><p>You can close this tab and return to the terminal.</p></body></html>"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::json;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    #[test]
    fn callback_accepts_only_an_opaque_exchange_code() {
        let params: CallbackParams =
            serde_json::from_value(json!({ "code": "opaque-exchange-code" })).unwrap();
        assert_eq!(params.code.as_deref(), Some("opaque-exchange-code"));

        assert!(serde_json::from_value::<CallbackParams>(
            json!({ "session_id": "live-session-credential" })
        )
        .is_err());
    }

    #[tokio::test]
    async fn callback_atomically_consumes_the_locally_retained_nonce() {
        let (tx, rx) = oneshot::channel();
        let state = CallbackState::new(tx, "local-browser-nonce".to_string());

        let code = "A".repeat(43);
        assert!(state.deliver(code.clone()));
        assert!(!state.deliver("B".repeat(43)));

        let pending = rx.await.unwrap();
        assert_eq!(pending.code, code);
        assert_eq!(pending.browser_nonce, "local-browser-nonce");
    }

    #[tokio::test]
    async fn callback_rejects_malformed_code_without_consuming_nonce() {
        let (tx, rx) = oneshot::channel();
        let state = CallbackState::new(tx, "local-browser-nonce".to_string());

        assert!(!state.deliver("not-an-exchange-code".to_string()));
        assert!(state.deliver("A".repeat(43)));
        assert_eq!(rx.await.unwrap().code, "A".repeat(43));
    }

    #[test]
    fn login_url_binds_nonce_and_exact_loopback_redirect() {
        let url = build_login_url(
            "https://api.catbird.blue",
            "alice.test",
            "http://127.0.0.1:49152/callback",
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(query.get("identifier").unwrap(), "alice.test");
        assert_eq!(query.get("client").unwrap(), "catmos");
        assert_eq!(
            query.get("redirect_to").unwrap(),
            "http://127.0.0.1:49152/callback"
        );
        assert_eq!(
            query.get("browser_nonce").unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    async fn session_handler(headers: HeaderMap) -> impl IntoResponse {
        let cookie = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if cookie != "catbird_session=valid-session" {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "InvalidToken" })),
            )
                .into_response();
        }

        Json(json!({
            "did": "did:plc:actual",
            "handle": "actual.test"
        }))
        .into_response()
    }

    async fn spawn_session_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let app = Router::new().route("/auth/session", get(session_handler));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn exchange_handler(
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> impl IntoResponse {
        assert_eq!(
            headers.get("origin").and_then(|value| value.to_str().ok()),
            Some("http://127.0.0.1:49152")
        );
        assert_eq!(body["code"], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(body["browser_nonce"], "0123456789abcdef0123456789abcdef");
        Json(json!({ "session_id": "new-session-credential" }))
    }

    async fn oversized_exchange_handler() -> impl IntoResponse {
        "x".repeat(MAX_OAUTH_RESPONSE_BYTES + 1)
    }

    fn chunked_oversized_response(status: StatusCode) -> Response {
        let chunks = futures_util::stream::iter([
            Ok::<_, std::convert::Infallible>(bytes::Bytes::from(vec![
                b'x';
                MAX_OAUTH_RESPONSE_BYTES
            ])),
            Ok(bytes::Bytes::from_static(b"x")),
        ]);
        Response::builder()
            .status(status)
            .body(Body::from_stream(chunks))
            .unwrap()
    }

    async fn chunked_oversized_exchange_handler() -> Response {
        chunked_oversized_response(StatusCode::OK)
    }

    async fn spawn_exchange_server(oversized: bool) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let app = if oversized {
            Router::new().route("/auth/exchange", post(oversized_exchange_handler))
        } else {
            Router::new().route("/auth/exchange", post(exchange_handler))
        };
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn exchange_posts_code_nonce_and_exact_origin() {
        let nest_url = spawn_exchange_server(false).await;
        let session = redeem_exchange(
            &reqwest::Client::new(),
            &nest_url,
            "http://127.0.0.1:49152",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "0123456789abcdef0123456789abcdef",
        )
        .await
        .unwrap();

        assert_eq!(session, "new-session-credential");
    }

    #[tokio::test]
    async fn exchange_rejects_oversized_response() {
        let nest_url = spawn_exchange_server(true).await;
        let error = redeem_exchange(
            &reqwest::Client::new(),
            &nest_url,
            "http://127.0.0.1:49152",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "0123456789abcdef0123456789abcdef",
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("exceeded size limit"));
    }

    #[tokio::test]
    async fn exchange_rejects_chunked_oversized_response_without_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let app = Router::new().route("/auth/exchange", post(chunked_oversized_exchange_handler));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let error = redeem_exchange(
            &reqwest::Client::new(),
            &format!("http://{addr}"),
            "http://127.0.0.1:49152",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "0123456789abcdef0123456789abcdef",
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("exceeded size limit"));
    }

    #[tokio::test]
    async fn identity_hydration_rejects_oversized_success_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/auth/session",
            get(|| async { "x".repeat(MAX_OAUTH_RESPONSE_BYTES + 1) }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let error = fetch_session_info(&reqwest::Client::new(), &format!("http://{addr}"), "token")
            .await
            .unwrap_err();

        assert!(error.to_string().contains("exceeded size limit"));
    }

    #[tokio::test]
    async fn identity_hydration_rejects_chunked_oversized_success_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/auth/session",
            get(|| async { chunked_oversized_response(StatusCode::OK) }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let error = fetch_session_info(&reqwest::Client::new(), &format!("http://{addr}"), "token")
            .await
            .unwrap_err();

        assert!(error.to_string().contains("exceeded size limit"));
    }

    #[tokio::test]
    async fn identity_hydration_sanitizes_error_body_after_bounded_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/auth/session",
            get(|| async { (StatusCode::UNAUTHORIZED, "sensitive-upstream-detail") }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let error = fetch_session_info(&reqwest::Client::new(), &format!("http://{addr}"), "token")
            .await
            .unwrap_err();
        let message = error.to_string();

        assert_eq!(
            message,
            "Authentication failed: OAuth session validation failed"
        );
        assert!(!message.contains("sensitive-upstream-detail"));
    }

    #[tokio::test]
    async fn identity_hydration_sanitizes_chunked_oversized_error_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/auth/session",
            get(|| async { chunked_oversized_response(StatusCode::UNAUTHORIZED) }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let error = fetch_session_info(&reqwest::Client::new(), &format!("http://{addr}"), "token")
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Authentication failed: OAuth session validation failed"
        );
    }

    #[tokio::test]
    async fn exchange_never_follows_redirects_with_credentials() {
        let followed = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let counter = followed.clone();
        let app = Router::new()
            .route(
                "/auth/exchange",
                post(|| async { (StatusCode::FOUND, [("location", "/credential-sink")]) }),
            )
            .route(
                "/credential-sink",
                get(move || {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(json!({ "session_id": "stolen" }))
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let error = redeem_exchange(
            &build_oauth_http_client().unwrap(),
            &format!("http://{addr}"),
            "http://127.0.0.1:49152",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "0123456789abcdef0123456789abcdef",
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("OAuth exchange failed"));
        assert_eq!(followed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn validate_for_did_accepts_matching_nest_session() {
        let nest_url = spawn_session_server().await;
        let auth = OAuthAuth {
            session_cookie: "valid-session".to_string(),
            did: "did:plc:actual".to_string(),
            handle: "cached.test".to_string(),
            nest_url,
        };

        let validated = auth.validate_for_did("did:plc:actual").await.unwrap();

        assert_eq!(validated.did, "did:plc:actual");
        assert_eq!(validated.handle, "actual.test");
    }

    #[tokio::test]
    async fn validate_for_did_rejects_did_mismatch_before_startup() {
        let nest_url = spawn_session_server().await;
        let auth = OAuthAuth {
            session_cookie: "valid-session".to_string(),
            did: "did:plc:cached".to_string(),
            handle: "cached.test".to_string(),
            nest_url,
        };

        let err = auth.validate_for_did("did:plc:cached").await.unwrap_err();

        assert!(
            err.to_string()
                .contains("restored OAuth session DID mismatch"),
            "unexpected error: {err}"
        );
    }
}
