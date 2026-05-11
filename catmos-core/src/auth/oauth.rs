use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use tokio::sync::oneshot;

use crate::error::{CatmosError, Result};
use crate::storage::db::Database;

/// Authentication via OAuth loopback flow through the nest BFF.
pub struct OAuthAuth {
    pub session_cookie: String,
    pub did: String,
    pub handle: String,
    pub nest_url: String,
}

/// The callback from nest redirects to `http://127.0.0.1:{port}/callback?session_id={UUID}`.
#[derive(serde::Deserialize)]
struct CallbackParams {
    session_id: Option<String>,
}

/// Response from `GET {nest_url}/auth/session` with the session cookie.
#[derive(serde::Deserialize)]
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
    tx: std::sync::Mutex<Option<oneshot::Sender<String>>>,
}

impl OAuthAuth {
    /// Start an OAuth loopback login flow.
    ///
    /// 1. Bind a local TCP listener on a random port
    /// 2. Open the browser to the nest auth URL with a redirect back to localhost
    /// 3. Wait up to 2 minutes for the callback with session_id
    /// 4. Exchange session_id for DID and handle via `GET /auth/session`
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
        let auth_url = format!(
            "{nest_url}/auth/login?identifier={handle}&client=catmos-web&redirect_to={redirect_to}"
        );

        // Channel for the callback result (just the session_id)
        let (tx, rx) = oneshot::channel::<String>();
        let state = Arc::new(CallbackState {
            tx: std::sync::Mutex::new(Some(tx)),
        });

        let app = Router::new()
            .route("/callback", get(handle_callback))
            .with_state(state);

        // Open the browser
        tracing::info!("Opening browser for authentication...");
        if let Err(e) = open::that(&auth_url) {
            tracing::warn!("Failed to open browser: {e}");
            eprintln!("Open this URL in your browser to log in:\n  {auth_url}");
        }

        // Serve the callback endpoint
        let server = axum::serve(listener, app);
        let timeout = tokio::time::Duration::from_secs(120);

        // Race the server against a 2-minute timeout
        let session_id = tokio::select! {
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

        // Exchange session_id for DID + handle via GET /auth/session
        let http = reqwest::Client::new();
        let session_resp = http
            .get(format!("{nest_url}/auth/session"))
            .header("Cookie", format!("catbird_session={session_id}"))
            .send()
            .await
            .map_err(|e| CatmosError::Network(format!("failed to fetch session: {e}")))?;

        if !session_resp.status().is_success() {
            let body = session_resp.text().await.unwrap_or_default();
            return Err(CatmosError::AuthFailed(format!(
                "session endpoint returned error: {body}"
            )));
        }

        let session_info: SessionResponse = session_resp.json().await.map_err(|e| {
            CatmosError::AuthFailed(format!("failed to parse session response: {e}"))
        })?;

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
        let http = reqwest::Client::new();
        let nest_url = self.nest_url.trim_end_matches('/');
        let session_resp = http
            .get(format!("{nest_url}/auth/session"))
            .header("Cookie", format!("catbird_session={}", self.session_cookie))
            .send()
            .await
            .map_err(|e| CatmosError::Network(format!("failed to validate OAuth session: {e}")))?;

        if !session_resp.status().is_success() {
            let status = session_resp.status();
            let body = session_resp.text().await.unwrap_or_default();
            return Err(CatmosError::AuthFailed(format!(
                "restored OAuth session is invalid ({status}): {body}. Run `catmos login` again."
            )));
        }

        let session_info: SessionResponse = session_resp.json().await.map_err(|e| {
            CatmosError::AuthFailed(format!("failed to parse restored OAuth session: {e}"))
        })?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

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

async fn handle_callback(
    State(state): State<Arc<CallbackState>>,
    Query(params): Query<CallbackParams>,
) -> Html<String> {
    let session_id = match params.session_id {
        Some(s) => s,
        None => {
            return Html(
                "<html><body><h1>Login failed</h1><p>Missing session_id parameter.</p></body></html>"
                    .to_string(),
            );
        }
    };

    // Send session_id through the channel
    if let Some(tx) = state.tx.lock().unwrap().take() {
        let _ = tx.send(session_id);
    }

    Html(
        "<html><body><h1>Login successful!</h1><p>You can close this tab and return to the terminal.</p></body></html>"
            .to_string(),
    )
}
