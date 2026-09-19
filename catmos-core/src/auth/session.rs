//! Jacquard-backed credential session for app-password auth.
//!
//! Wraps `MemoryCredentialSession` so that we own the in-memory session store
//! and can read refreshed tokens back out to persist them in the local DB.
//! All catmos-cli code goes through this for app-password bearer tokens.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::renewal::{ObservedResolver, RefreshDiagnostics};
use jacquard::client::credential_session::{CredentialSession, SessionKey};
use jacquard::client::AtpSession;
use jacquard_common::deps::fluent_uri::Uri;
use jacquard_common::session::{MemorySessionStore, SessionStore};
use jacquard_common::types::string::{Did, Handle};
use jacquard_common::{AuthorizationToken, SmolStr};

use crate::error::{AuthRenewalFailure, CatmosError, Result};
use crate::storage::db::Database;

/// Session label inside the jacquard store. A single session per catmos account.
const SESSION_ID: &str = "catmos";
type ObservedCredentialSession =
    CredentialSession<MemorySessionStore<SessionKey, AtpSession>, ObservedResolver>;
pub(crate) const APP_PASSWORD_SESSION_KEYS: &[&str] = &[
    "auth_method",
    "handle",
    "did",
    "access_jwt",
    "refresh_jwt",
    "pds_url",
];

/// A live app-password session that handles token refresh automatically.
///
/// Cheap to clone (internal `Arc`s). Shared across the ChatService and any
/// background tasks that make XRPC calls.
#[derive(Clone)]
pub struct TokenSession {
    session: Arc<ObservedCredentialSession>,
    refresh_diagnostics: RefreshDiagnostics,
    store: Arc<MemorySessionStore<SessionKey, AtpSession>>,
    did: Did,
    handle: String,
    pds_url: String,
    refresh_persist_lock: Arc<tokio::sync::Mutex<()>>,
    invalidated: Arc<AtomicBool>,
}

/// Cancellation drops futures without visiting their error branches. Once a
/// refresh can mutate SDK memory, keep every clone unusable unless this call
/// observes durable commit or restores a validated durable snapshot.
struct RefreshCancellationGuard {
    invalidated: Arc<AtomicBool>,
    armed: bool,
}

impl RefreshCancellationGuard {
    fn new(invalidated: Arc<AtomicBool>) -> Self {
        Self {
            invalidated,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RefreshCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.invalidated.store(true, Ordering::Release);
        }
    }
}

impl TokenSession {
    pub fn did(&self) -> &str {
        self.did.as_str()
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn pds_url(&self) -> &str {
        &self.pds_url
    }

    /// Start a fresh session via `com.atproto.server.createSession`.
    pub async fn login(handle: &str, app_password: &str) -> Result<Self> {
        let store: Arc<MemorySessionStore<SessionKey, AtpSession>> =
            Arc::new(MemorySessionStore::default());
        let refresh_diagnostics = RefreshDiagnostics::default();
        let resolver = Arc::new(ObservedResolver::new(refresh_diagnostics.clone()));
        let session: ObservedCredentialSession = CredentialSession::new(store.clone(), resolver);

        let atp = session
            .login(handle, app_password, Some(SESSION_ID), None, None, None)
            .await
            .map_err(|e| CatmosError::AuthFailed(format!("login failed: {e}")))?;

        let key = session
            .session_info()
            .await
            .ok_or_else(|| CatmosError::AuthFailed("no session after login".into()))?;
        let did = key.did.clone();
        let pds_url = session
            .endpoint()
            .await
            .as_str()
            .trim_end_matches('/')
            .to_string();

        Ok(Self {
            session: Arc::new(session),
            refresh_diagnostics,
            store,
            did,
            handle: atp.handle.to_string(),
            pds_url,
            refresh_persist_lock: Arc::new(tokio::sync::Mutex::new(())),
            invalidated: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Rebuild a session from tokens that were previously persisted.
    ///
    /// No network calls — seeds the in-memory store with the stored
    /// `AtpSession` and activates it. The next XRPC call will use the stored
    /// access token; if it has expired, `refresh` will swap it for a new one.
    pub async fn restore(
        handle: String,
        did_str: String,
        access_jwt: String,
        refresh_jwt: String,
        pds_url: String,
    ) -> Result<Self> {
        let did = Did::new_owned(&did_str).map_err(|e| {
            CatmosError::AuthFailed(format!("invalid did in stored session: {e:?}"))
        })?;
        let handle_parsed = Handle::new_owned(&handle).map_err(|e| {
            CatmosError::AuthFailed(format!("invalid handle in stored session: {e:?}"))
        })?;

        let pds_uri = Uri::parse(pds_url.clone()).ok();
        let atp = AtpSession {
            access_jwt: SmolStr::from(access_jwt),
            refresh_jwt: SmolStr::from(refresh_jwt),
            did: did.clone(),
            handle: handle_parsed,
            pds: pds_uri,
        };

        let store: Arc<MemorySessionStore<SessionKey, AtpSession>> =
            Arc::new(MemorySessionStore::default());
        let key = SessionKey::new(did.clone(), SESSION_ID);
        store
            .set(key.clone(), atp)
            .await
            .map_err(|e| CatmosError::AuthFailed(format!("store set failed: {e}")))?;

        let refresh_diagnostics = RefreshDiagnostics::default();
        let resolver = Arc::new(ObservedResolver::new(refresh_diagnostics.clone()));
        let session: ObservedCredentialSession = CredentialSession::new(store.clone(), resolver);

        session
            .restore(did.clone(), SESSION_ID)
            .await
            .map_err(|e| CatmosError::AuthFailed(format!("restore failed: {e}")))?;

        // `restore` may resolve the PDS via DID doc; override with the cached
        // value to save a round-trip when we already know it.
        if let Ok(uri) = Uri::parse(pds_url.clone()) {
            session.set_endpoint(uri).await;
        }

        Ok(Self {
            session: Arc::new(session),
            refresh_diagnostics,
            store,
            did,
            handle,
            pds_url,
            refresh_persist_lock: Arc::new(tokio::sync::Mutex::new(())),
            invalidated: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Return the current access token as a raw bearer string.
    pub async fn current_bearer(&self) -> Result<String> {
        let _guard = self.refresh_persist_lock.lock().await;
        self.require_valid_session()?;
        let token = self
            .session
            .access_token()
            .await
            .ok_or_else(|| CatmosError::AuthFailed("no access token in session".into()))?;
        Ok(bearer_string(token))
    }

    /// Force a `com.atproto.server.refreshSession` call and return the new bearer.
    /// Persists the refreshed tokens to `db`.
    pub async fn refresh(&self, db: &Database) -> Result<String> {
        let _guard = self.refresh_persist_lock.lock().await;
        self.require_valid_session()?;
        let expected = db
            .get_session_values(APP_PASSWORD_SESSION_KEYS)
            .await
            .map_err(|_| AuthRenewalFailure::ReadSnapshot)?;
        if let Err(error) = self.adopt_durable_snapshot(&expected).await {
            self.invalidated.store(true, Ordering::Release);
            return Err(error);
        }
        // Declared after the serialization guard so Drop invalidates memory
        // before another clone can acquire the session lock on cancellation.
        let mut cancellation = RefreshCancellationGuard::new(self.invalidated.clone());
        self.refresh_diagnostics.reset();
        let token = match self.session.refresh().await {
            Ok(token) => token,
            Err(error) => {
                if self.restore_current_or_invalidate(db).await.is_ok() {
                    cancellation.disarm();
                }
                return Err(self.refresh_diagnostics.classify(&error).into());
            }
        };
        let bearer = bearer_string(token);
        let key = SessionKey::new(self.did.clone(), SESSION_ID);
        let atp = match self.store.get(&key).await {
            Some(atp) => atp,
            None => {
                self.invalidated.store(true, Ordering::Release);
                return Err(AuthRenewalFailure::MemoryState.into());
            }
        };
        if atp.did != self.did {
            self.invalidated.store(true, Ordering::Release);
            return Err(AuthRenewalFailure::IdentityMismatch.into());
        }
        let saved = db
            .compare_and_store_session_values(
                &expected,
                &[
                    ("auth_method", "app_password"),
                    ("handle", atp.handle.as_str()),
                    ("did", self.did.as_str()),
                    ("access_jwt", atp.access_jwt.as_str()),
                    ("refresh_jwt", atp.refresh_jwt.as_str()),
                    ("pds_url", &self.pds_url),
                ],
            )
            .await;
        match saved {
            Ok(true) => cancellation.disarm(),
            Ok(false) => {
                self.restore_current_or_invalidate(db).await?;
                cancellation.disarm();
                return Err(CatmosError::AuthSessionChanged);
            }
            Err(_) => {
                // Do not expose an unpersisted token to other clones after a
                // storage failure. A later retry may require normal login.
                if self.restore_current_or_invalidate(db).await.is_ok() {
                    cancellation.disarm();
                }
                return Err(AuthRenewalFailure::PersistSnapshot.into());
            }
        }
        Ok(bearer)
    }

    fn require_valid_session(&self) -> Result<()> {
        if self.invalidated.load(Ordering::Acquire) {
            return Err(AuthRenewalFailure::Invalidated.into());
        }
        Ok(())
    }

    async fn restore_current_or_invalidate(&self, db: &Database) -> Result<()> {
        let result = match db.get_session_values(APP_PASSWORD_SESSION_KEYS).await {
            Ok(current) => self.adopt_durable_snapshot(&current).await,
            Err(_) => Err(AuthRenewalFailure::ReadSnapshot.into()),
        };
        if result.is_err() {
            self.invalidated.store(true, Ordering::Release);
        }
        result
    }

    async fn adopt_durable_snapshot(
        &self,
        snapshot: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let value = |key: &str| {
            snapshot
                .get(key)
                .filter(|value| !value.is_empty())
                .map(String::as_str)
        };
        if value("auth_method") != Some("app_password")
            || value("did") != Some(self.did.as_str())
            || value("pds_url") != Some(self.pds_url.as_str())
        {
            return Err(CatmosError::AuthSessionChanged);
        }
        let access = value("access_jwt")
            .ok_or_else(|| CatmosError::AuthRenewal(AuthRenewalFailure::InvalidSnapshot))?;
        let refresh = value("refresh_jwt")
            .ok_or_else(|| CatmosError::AuthRenewal(AuthRenewalFailure::InvalidSnapshot))?;
        let handle = value("handle")
            .ok_or_else(|| CatmosError::AuthRenewal(AuthRenewalFailure::InvalidSnapshot))?;
        let handle = Handle::new_owned(handle)
            .map_err(|_| CatmosError::AuthRenewal(AuthRenewalFailure::InvalidSnapshot))?;
        let pds = Uri::parse(self.pds_url.clone())
            .map_err(|_| CatmosError::AuthRenewal(AuthRenewalFailure::InvalidSnapshot))?;
        self.store
            .set(
                SessionKey::new(self.did.clone(), SESSION_ID),
                AtpSession {
                    access_jwt: SmolStr::from(access),
                    refresh_jwt: SmolStr::from(refresh),
                    did: self.did.clone(),
                    handle,
                    pds: Some(pds),
                },
            )
            .await
            .map_err(|_| CatmosError::AuthRenewal(AuthRenewalFailure::InvalidSnapshot))?;
        Ok(())
    }

    /// Write the session's current access/refresh JWTs into the DB session table.
    pub async fn persist(&self, db: &Database) -> Result<()> {
        let _guard = self.refresh_persist_lock.lock().await;
        self.require_valid_session()?;
        self.persist_unlocked(db).await
    }

    async fn persist_unlocked(&self, db: &Database) -> Result<()> {
        let key = SessionKey::new(self.did.clone(), SESSION_ID);
        let atp = self
            .store
            .get(&key)
            .await
            .ok_or_else(|| CatmosError::AuthFailed("session missing from store".into()))?;

        db.store_session_values(&[
            ("auth_method", "app_password"),
            ("handle", atp.handle.as_str()),
            ("did", self.did.as_str()),
            ("access_jwt", atp.access_jwt.as_str()),
            ("refresh_jwt", atp.refresh_jwt.as_str()),
            ("pds_url", &self.pds_url),
        ])
        .await?;
        Ok(())
    }
}

fn bearer_string(token: AuthorizationToken) -> String {
    match token {
        AuthorizationToken::Bearer(s) => s.to_string(),
        AuthorizationToken::Dpop(s) => s.to_string(),
        AuthorizationToken::Delegation(s) => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    const HANDLE: &str = "actor.catbird.blue";

    #[tokio::test]
    async fn cancelled_refresh_after_mint_invalidates_clones_and_preserves_durable_pair() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let handler_entered = entered.clone();
        let handler_release = release.clone();
        let app = Router::new().route(
            "/xrpc/com.atproto.server.refreshSession",
            post(move || {
                let entered = handler_entered.clone();
                let release = handler_release.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    Json(json!({"did": DID, "handle": HANDLE,
                    "accessJwt": "unpersisted-access", "refreshJwt": "unpersisted-refresh"}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pds = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            Database::open(&dir.path().join("session.db"), "test-only-sqlcipher-key")
                .await
                .unwrap(),
        );
        let old = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-old".into(),
            "refresh-old".into(),
            pds,
        )
        .await
        .unwrap();
        old.persist(&db).await.unwrap();
        let sibling = old.clone();
        let pending_db = db.clone();
        let pending = tokio::spawn(async move { old.refresh(&pending_db).await });
        entered.notified().await;
        // The authorized baseline read and HTTP request have completed. Hold a
        // separate writer so the refreshed response cannot pass its CAS barrier.
        let writer = db
            .pool_for_test()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .unwrap();
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let atp = sibling
                    .store
                    .get(&SessionKey::new(sibling.did.clone(), SESSION_ID))
                    .await
                    .unwrap();
                if atp.access_jwt.as_str() == "unpersisted-access" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("SDK never installed the refreshed in-memory token");
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        writer.rollback().await.unwrap();
        assert!(
            sibling.current_bearer().await.is_err(),
            "cancelled refresh exposed an unpersisted token"
        );
        assert!(sibling.persist(&db).await.is_err());
        assert_eq!(
            db.get_session_value("access_jwt").await.unwrap().as_deref(),
            Some("access-old")
        );
        assert_eq!(
            db.get_session_value("refresh_jwt")
                .await
                .unwrap()
                .as_deref(),
            Some("refresh-old")
        );
        db.pool_for_test().close().await;
        server.abort();
    }

    #[tokio::test]
    async fn wrong_refresh_identity_invalidates_all_clones_without_publishing_tokens() {
        let app = Router::new().route(
            "/xrpc/com.atproto.server.refreshSession",
            post(|| async {
                Json(
                    json!({"did": "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", "handle": HANDLE,
                "accessJwt": "unpersisted-access", "refreshJwt": "unpersisted-refresh"}),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pds = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("session.db"), "test-only-sqlcipher-key")
            .await
            .unwrap();
        let old = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-old".into(),
            "refresh-old".into(),
            pds,
        )
        .await
        .unwrap();
        old.persist(&db).await.unwrap();
        let sibling = old.clone();
        assert!(old.refresh(&db).await.is_err());
        assert!(old.current_bearer().await.is_err());
        assert!(sibling.current_bearer().await.is_err());
        assert!(sibling.persist(&db).await.is_err());
        assert_eq!(
            db.get_session_value("access_jwt").await.unwrap().as_deref(),
            Some("access-old")
        );
        assert_eq!(
            db.get_session_value("refresh_jwt")
                .await
                .unwrap()
                .as_deref(),
            Some("refresh-old")
        );
        db.pool_for_test().close().await;
        server.abort();
    }

    #[tokio::test]
    async fn changed_authority_during_refresh_invalidates_clones_without_overwrite() {
        for change_did in [true, false] {
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let handler_entered = entered.clone();
            let handler_release = release.clone();
            let app = Router::new().route("/xrpc/com.atproto.server.refreshSession", post(move || {
                let entered = handler_entered.clone(); let release = handler_release.clone();
                async move {
                    entered.notify_one(); release.notified().await;
                    Json(json!({"did": DID, "handle": HANDLE, "accessJwt": "unpersisted-access", "refreshJwt": "unpersisted-refresh"}))
                }
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let pds = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let dir = tempfile::tempdir().unwrap();
            let db = Arc::new(
                Database::open(&dir.path().join("session.db"), "test-only-sqlcipher-key")
                    .await
                    .unwrap(),
            );
            let old = TokenSession::restore(
                HANDLE.into(),
                DID.into(),
                "access-old".into(),
                "refresh-old".into(),
                pds.clone(),
            )
            .await
            .unwrap();
            old.persist(&db).await.unwrap();
            let sibling = old.clone();
            let pending_db = db.clone();
            let pending = tokio::spawn(async move { old.refresh(&pending_db).await });
            entered.notified().await;
            let new_did = if change_did {
                "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
            } else {
                DID
            };
            let new_pds = if change_did {
                pds.as_str()
            } else {
                "https://other-pds.catbird.blue"
            };
            let login = TokenSession::restore(
                HANDLE.into(),
                new_did.into(),
                "access-login".into(),
                "refresh-login".into(),
                new_pds.into(),
            )
            .await
            .unwrap();
            login.persist(&db).await.unwrap();
            release.notify_one();
            assert!(pending.await.unwrap().is_err());
            assert!(sibling.current_bearer().await.is_err());
            assert!(sibling.persist(&db).await.is_err());
            assert_eq!(
                db.get_session_value("access_jwt").await.unwrap().as_deref(),
                Some("access-login")
            );
            assert_eq!(
                db.get_session_value("did").await.unwrap().as_deref(),
                Some(new_did)
            );
            assert_eq!(
                db.get_session_value("pds_url").await.unwrap().as_deref(),
                Some(new_pds)
            );
            db.pool_for_test().close().await;
            server.abort();
        }
    }

    #[tokio::test]
    async fn in_flight_refresh_cannot_overwrite_a_newer_durable_login() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let handler_entered = entered.clone();
        let handler_release = release.clone();
        let app = Router::new().route("/xrpc/com.atproto.server.refreshSession", post(move |headers: HeaderMap| {
            let entered = handler_entered.clone(); let release = handler_release.clone();
            async move {
                assert_eq!(headers["authorization"], "Bearer refresh-old");
                entered.notify_one(); release.notified().await;
                Json(json!({"did": DID, "handle": HANDLE, "accessJwt": "access-stale", "refreshJwt": "refresh-stale"}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pds = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            Database::open(&dir.path().join("session.db"), "test-only-sqlcipher-key")
                .await
                .unwrap(),
        );
        let old = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-old".into(),
            "refresh-old".into(),
            pds.clone(),
        )
        .await
        .unwrap();
        old.persist(&db).await.unwrap();
        let pending_db = db.clone();
        let pending = tokio::spawn(async move {
            let result = old.refresh(&pending_db).await;
            (result, old.current_bearer().await)
        });
        entered.notified().await;
        let login = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-login".into(),
            "refresh-login".into(),
            pds,
        )
        .await
        .unwrap();
        login.persist(&db).await.unwrap();
        release.notify_one();
        let (result, memory_bearer) = pending.await.unwrap();
        assert!(
            matches!(result, Err(CatmosError::AuthSessionChanged)),
            "stale in-flight refresh overwrote newer login"
        );
        assert_eq!(memory_bearer.unwrap(), "access-login");
        assert_eq!(
            db.get_session_value("access_jwt").await.unwrap().as_deref(),
            Some("access-login")
        );
        assert_eq!(
            db.get_session_value("refresh_jwt")
                .await
                .unwrap()
                .as_deref(),
            Some("refresh-login")
        );
        db.pool_for_test().close().await;
        server.abort();
    }

    #[tokio::test]
    async fn stale_instance_reloads_current_same_account_session_before_refresh() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = calls.clone();
        let app = Router::new().route("/xrpc/com.atproto.server.refreshSession", post(move |headers: HeaderMap| {
            let calls = handler_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(headers["authorization"], "Bearer refresh-login");
                Json(json!({"did": DID, "handle": HANDLE, "accessJwt": "access-rotated", "refreshJwt": "refresh-rotated"}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pds = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("session.db"), "test-only-sqlcipher-key")
            .await
            .unwrap();
        let old = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-old".into(),
            "refresh-old".into(),
            pds.clone(),
        )
        .await
        .unwrap();
        old.persist(&db).await.unwrap();
        let login = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-login".into(),
            "refresh-login".into(),
            pds.clone(),
        )
        .await
        .unwrap();
        login.persist(&db).await.unwrap();
        assert_eq!(old.refresh(&db).await.unwrap(), "access-rotated");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for (field, invalid_value, original_value) in [
            ("did", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", DID),
            ("pds_url", "https://unverified.catbird.blue", pds.as_str()),
            ("auth_method", "oauth", "app_password"),
        ] {
            db.store_session_value(field, invalid_value).await.unwrap();
            assert!(old.refresh(&db).await.is_err());
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "changed authority received a credential"
            );
            db.store_session_value(field, original_value).await.unwrap();
        }
        db.pool_for_test().close().await;
        server.abort();
    }

    #[tokio::test]
    async fn session_restore_reads_one_complete_auth_snapshot_during_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            Database::open(&dir.path().join("session.db"), "test-only-sqlcipher-key")
                .await
                .unwrap(),
        );
        let first = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-0".into(),
            "refresh-0".into(),
            "https://pds.catbird.blue".into(),
        )
        .await
        .unwrap();
        first.persist(&db).await.unwrap();
        let writer_db = db.clone();
        let writer = tokio::spawn(async move {
            for index in 1..60 {
                let login = TokenSession::restore(
                    HANDLE.into(),
                    DID.into(),
                    format!("access-{index}"),
                    format!("refresh-{index}"),
                    "https://pds.catbird.blue".into(),
                )
                .await
                .unwrap();
                login.persist(&writer_db).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        for _ in 0..60 {
            let restored = crate::auth::app_password::AppPasswordAuth::load(&db)
                .await
                .unwrap()
                .unwrap();
            let atp = restored
                .session
                .store
                .get(&SessionKey::new(restored.session.did.clone(), SESSION_ID))
                .await
                .unwrap();
            assert_eq!(
                atp.access_jwt.strip_prefix("access-"),
                atp.refresh_jwt.strip_prefix("refresh-")
            );
        }
        writer.await.unwrap();
        db.pool_for_test().close().await;
    }

    #[tokio::test]
    async fn auth_persistence_interruption_cannot_split_access_and_refresh_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("session.db"), "test-only-sqlcipher-key")
            .await
            .unwrap();
        let old = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-old".into(),
            "refresh-old".into(),
            "https://pds.catbird.blue".into(),
        )
        .await
        .unwrap();
        old.persist(&db).await.unwrap();
        sqlx::query("CREATE TRIGGER reject_refresh_write BEFORE INSERT ON session WHEN NEW.key = 'refresh_jwt' AND NEW.value = 'refresh-new' BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END")
            .execute(db.pool_for_test()).await.unwrap();
        let new = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-new".into(),
            "refresh-new".into(),
            "https://pds.catbird.blue".into(),
        )
        .await
        .unwrap();
        assert!(new.persist(&db).await.is_err());
        assert_eq!(
            db.get_session_value("access_jwt").await.unwrap().as_deref(),
            Some("access-old")
        );
        assert_eq!(
            db.get_session_value("refresh_jwt")
                .await
                .unwrap()
                .as_deref(),
            Some("refresh-old")
        );
        db.pool_for_test().close().await;
    }

    #[tokio::test]
    async fn concurrent_clones_refresh_serially_and_persist_matching_pair() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen_calls = calls.clone();
        let app = Router::new().route("/xrpc/com.atproto.server.refreshSession", post(move |headers: HeaderMap| {
            let calls = seen_calls.clone();
            async move {
                let index = calls.fetch_add(1, Ordering::SeqCst);
                if headers["authorization"] != format!("Bearer refresh-{index}") {
                    return (StatusCode::UNAUTHORIZED, Json(json!({"error": "ExpiredToken"})));
                }
                if index == 0 { tokio::time::sleep(std::time::Duration::from_millis(50)).await; }
                (StatusCode::OK, Json(json!({"did": DID, "handle": HANDLE,
                    "accessJwt": format!("access-{}", index+1), "refreshJwt": format!("refresh-{}", index+1)})))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pds = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("session.db"), "test-only-sqlcipher-key")
            .await
            .unwrap();
        let session = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-0".into(),
            "refresh-0".into(),
            pds,
        )
        .await
        .unwrap();
        session.persist(&db).await.unwrap();
        let sibling = session.clone();
        let (first, second) = tokio::join!(session.refresh(&db), sibling.refresh(&db));
        assert!(
            first.is_ok() && second.is_ok(),
            "concurrent refresh reused a superseded refresh credential"
        );
        assert_eq!(
            db.get_session_value("access_jwt").await.unwrap().as_deref(),
            Some("access-2")
        );
        assert_eq!(
            db.get_session_value("refresh_jwt")
                .await
                .unwrap()
                .as_deref(),
            Some("refresh-2")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        db.pool_for_test().close().await;
        server.abort();
    }

    #[tokio::test]
    async fn refreshed_tokens_survive_encrypted_database_restart_and_rotate_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen_calls = calls.clone();
        let app = Router::new().route(
            "/xrpc/com.atproto.server.refreshSession",
            post(move |headers: HeaderMap| {
                let calls = seen_calls.clone();
                async move {
                    let index = calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(headers["authorization"], format!("Bearer refresh-{index}"));
                    Json(json!({
                        "did": DID, "handle": HANDLE,
                        "accessJwt": format!("access-{}", index+1),
                        "refreshJwt": format!("refresh-{}", index+1), "active": true,
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pds = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.db");
        let db = Database::open(&path, "test-only-sqlcipher-key")
            .await
            .unwrap();
        db.store_session_value("device_uuid", "existing-device-marker")
            .await
            .unwrap();
        let session = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "access-0".into(),
            "refresh-0".into(),
            pds.clone(),
        )
        .await
        .unwrap();
        session.persist(&db).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "restore must not silently rotate credentials"
        );
        assert_eq!(session.refresh(&db).await.unwrap(), "access-1");
        assert_eq!(
            db.get_session_value("refresh_jwt")
                .await
                .unwrap()
                .as_deref(),
            Some("refresh-1")
        );
        db.pool_for_test().close().await;
        drop(db);
        drop(session);
        let db = Database::open(&path, "test-only-sqlcipher-key")
            .await
            .unwrap();
        let restored = crate::auth::app_password::AppPasswordAuth::load(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.session.current_bearer().await.unwrap(), "access-1");
        assert_eq!(restored.pds_url, pds);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "restart restore must not rotate credentials"
        );
        assert_eq!(restored.session.refresh(&db).await.unwrap(), "access-2");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            db.get_session_value("refresh_jwt")
                .await
                .unwrap()
                .as_deref(),
            Some("refresh-2")
        );
        assert_eq!(
            db.get_session_value("device_uuid")
                .await
                .unwrap()
                .as_deref(),
            Some("existing-device-marker")
        );
        db.pool_for_test().close().await;
        server.abort();
    }

    #[tokio::test]
    async fn rejected_refresh_preserves_stored_session_and_device_identity() {
        let app = Router::new().route(
            "/xrpc/com.atproto.server.refreshSession",
            post(|headers: HeaderMap| async move {
                assert_eq!(headers["authorization"], "Bearer expired-refresh");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "ExpiredToken", "message": "expired"})),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pds = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("session.db"), "test-only-sqlcipher-key")
            .await
            .unwrap();
        let session = TokenSession::restore(
            HANDLE.into(),
            DID.into(),
            "old-access".into(),
            "expired-refresh".into(),
            pds,
        )
        .await
        .unwrap();
        session.persist(&db).await.unwrap();
        db.store_session_value("device_uuid", "existing-device-marker")
            .await
            .unwrap();
        assert!(session.refresh(&db).await.is_err());
        assert_eq!(session.current_bearer().await.unwrap(), "old-access");
        assert_eq!(
            db.get_session_value("access_jwt").await.unwrap().as_deref(),
            Some("old-access")
        );
        assert_eq!(
            db.get_session_value("refresh_jwt")
                .await
                .unwrap()
                .as_deref(),
            Some("expired-refresh")
        );
        assert_eq!(
            db.get_session_value("device_uuid")
                .await
                .unwrap()
                .as_deref(),
            Some("existing-device-marker")
        );
        db.pool_for_test().close().await;
        server.abort();
    }
}

#[cfg(test)]
#[path = "session/renewal_tests.rs"]
mod renewal_tests;
