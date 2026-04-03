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

        let session_info: SessionResponse = session_resp
            .json()
            .await
            .map_err(|e| CatmosError::AuthFailed(format!("failed to parse session response: {e}")))?;

        Ok(Self {
            session_cookie: session_id,
            did: session_info.did,
            handle: session_info.handle,
            nest_url: nest_url.to_string(),
        })
    }

    /// Persist OAuth session to the session store.
    pub fn save(&self, db: &Database) -> Result<()> {
        db.store_session_value("auth_method", "oauth")?;
        db.store_session_value("session_cookie", &self.session_cookie)?;
        db.store_session_value("did", &self.did)?;
        db.store_session_value("handle", &self.handle)?;
        db.store_session_value("nest_url", &self.nest_url)?;
        Ok(())
    }

    /// Load previously-saved OAuth auth from the session store.
    pub fn load(db: &Database) -> Result<Option<Self>> {
        let method = db.get_session_value("auth_method")?;
        if method.as_deref() != Some("oauth") {
            return Ok(None);
        }

        let session_cookie = db.get_session_value("session_cookie")?;
        let did = db.get_session_value("did")?;
        let handle = db.get_session_value("handle")?;
        let nest_url = db.get_session_value("nest_url")?;

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
