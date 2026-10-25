//! Jacquard-backed credential session for app-password auth.
//!
//! Wraps `MemoryCredentialSession` so that we own the in-memory session store
//! and can read refreshed tokens back out to persist them in the local DB.
//! All catmos-cli code goes through this for app-password bearer tokens.

use std::sync::Arc;

use jacquard::client::credential_session::{CredentialSession, SessionKey};
use jacquard::client::{AtpSession, MemoryCredentialSession};
use jacquard_common::session::{MemorySessionStore, SessionStore};
use jacquard_common::types::string::{Did, Handle};
use jacquard_common::AuthorizationToken;
use jacquard_identity::PublicResolver;

use crate::error::{CatmosError, Result};
use crate::storage::db::Database;

/// Session label inside the jacquard store. A single session per catmos account.
const SESSION_ID: &str = "catmos";

/// A live app-password session that handles token refresh automatically.
///
/// Cheap to clone (internal `Arc`s). Shared across the ChatService and any
/// background tasks that make XRPC calls.
#[derive(Clone)]
pub struct TokenSession {
    session: Arc<MemoryCredentialSession>,
    store: Arc<MemorySessionStore<SessionKey, AtpSession>>,
    did: Did,
    handle: String,
    pds_url: String,
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
        let resolver = Arc::new(PublicResolver::default());
        let session: MemoryCredentialSession = CredentialSession::new(store.clone(), resolver);

        session
            .login(handle, app_password, Some(SESSION_ID), None, None, None)
            .await
            .map_err(|e| CatmosError::AuthFailed(format!("login failed: {e}")))?;

        let key = session
            .session_info()
            .await
            .ok_or_else(|| CatmosError::AuthFailed("no session after login".into()))?;
        let did = key.did.clone();
        let atp = store.get(&key).await.ok_or_else(|| {
            CatmosError::AuthFailed("session missing from store after login".into())
        })?;
        let pds_url = session
            .endpoint()
            .await
            .as_str()
            .trim_end_matches('/')
            .to_string();

        Ok(Self {
            session: Arc::new(session),
            store,
            did,
            handle: atp.handle.to_string(),
            pds_url,
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

        let atp = AtpSession {
            access_jwt: access_jwt.into(),
            refresh_jwt: refresh_jwt.into(),
            did: did.clone(),
            handle: handle_parsed,
            pds: Some(
                jacquard::deps::fluent_uri::Uri::parse(pds_url.clone()).map_err(|(e, _)| {
                    CatmosError::AuthFailed(format!("invalid PDS URL in stored session: {e}"))
                })?,
            ),
        };

        let store: Arc<MemorySessionStore<SessionKey, AtpSession>> =
            Arc::new(MemorySessionStore::default());
        let key = SessionKey::new(did.clone(), SESSION_ID);
        store
            .set(key.clone(), atp)
            .await
            .map_err(|e| CatmosError::AuthFailed(format!("store set failed: {e}")))?;

        let resolver = Arc::new(PublicResolver::default());
        let session: MemoryCredentialSession = CredentialSession::new(store.clone(), resolver);

        session
            .restore(did.clone(), SESSION_ID)
            .await
            .map_err(|e| CatmosError::AuthFailed(format!("restore failed: {e}")))?;

        // The cached PDS is part of AtpSession, so activation needs no DID
        // resolution and preserves the previously persisted endpoint.

        Ok(Self {
            session: Arc::new(session),
            store,
            did,
            handle,
            pds_url,
        })
    }

    /// Return the current access token as a raw bearer string.
    pub async fn current_bearer(&self) -> Result<String> {
        let token = self
            .session
            .access_token()
            .await
            .ok_or_else(|| CatmosError::AuthFailed("no access token in session".into()))?;
        bearer_string(token)
    }

    /// Force a `com.atproto.server.refreshSession` call and return the new bearer.
    /// Persists the refreshed tokens to `db`.
    pub async fn refresh(&self, db: &Database) -> Result<String> {
        let token = self
            .session
            .refresh()
            .await
            .map_err(|e| CatmosError::AuthFailed(format!("refresh failed: {e}")))?;
        let bearer = bearer_string(token)?;
        self.persist(db).await?;
        Ok(bearer)
    }

    /// Write the session's current access/refresh JWTs into the DB session table.
    pub async fn persist(&self, db: &Database) -> Result<()> {
        let key = SessionKey::new(self.did.clone(), SESSION_ID);
        let atp = self
            .store
            .get(&key)
            .await
            .ok_or_else(|| CatmosError::AuthFailed("session missing from store".into()))?;

        db.store_session_value("auth_method", "app_password")
            .await?;
        db.store_session_value("handle", &self.handle).await?;
        db.store_session_value("did", self.did.as_str()).await?;
        db.store_session_value("access_jwt", atp.access_jwt.as_ref())
            .await?;
        db.store_session_value("refresh_jwt", atp.refresh_jwt.as_ref())
            .await?;
        db.store_session_value("pds_url", &self.pds_url).await?;
        Ok(())
    }
}

fn bearer_string(token: AuthorizationToken) -> Result<String> {
    match token {
        AuthorizationToken::Bearer(s) => Ok(s.to_string()),
        // This adapter is exclusively an app-password credential session.
        // Proof-bound OAuth/delegation tokens require their own request signer.
        AuthorizationToken::Dpop(_) | AuthorizationToken::Delegation(_) => {
            Err(CatmosError::AuthFailed(
                "credential session returned a token requiring a proof signer".into(),
            ))
        }
    }
}

#[cfg(test)]
mod token_tests {
    use super::*;

    #[test]
    fn credential_adapter_never_downgrades_proof_bound_tokens() {
        assert_eq!(
            bearer_string(AuthorizationToken::Bearer("fixture".into())).unwrap(),
            "fixture"
        );
        assert!(bearer_string(AuthorizationToken::Dpop("fixture".into())).is_err());
        assert!(bearer_string(AuthorizationToken::Delegation("fixture".into())).is_err());
    }
}
