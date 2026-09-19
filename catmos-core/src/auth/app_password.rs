//! App-password auth: thin DTO + DB persistence over the jacquard-backed
//! `TokenSession`. Callers use `login` / `load` to obtain a `TokenSession`
//! plus the metadata needed to build an `AuthMethod`.

use crate::auth::session::TokenSession;
use crate::error::Result;
use crate::storage::db::Database;

/// Result of a login or restore: a live token session + the metadata needed
/// to build an `AuthMethod::AppPassword` variant.
pub struct AppPasswordAuth {
    pub handle: String,
    pub did: String,
    pub pds_url: String,
    pub session: TokenSession,
}

impl AppPasswordAuth {
    /// Log in using an AT Protocol handle and app password.
    ///
    /// Delegates to `TokenSession::login`, which uses jacquard's built-in
    /// PublicResolver to locate the user's PDS and create a session there.
    pub async fn login(handle: &str, app_password: &str) -> Result<Self> {
        let session = TokenSession::login(handle, app_password).await?;
        Ok(Self {
            handle: session.handle().to_string(),
            did: session.did().to_string(),
            pds_url: session.pds_url().to_string(),
            session,
        })
    }

    /// Persist auth credentials (including the current access/refresh JWTs)
    /// to the session store.
    pub async fn save(&self, db: &Database) -> Result<()> {
        self.session.persist(db).await
    }

    /// Load previously-saved app password auth from the session store and
    /// rebuild a live `TokenSession` from the stored tokens.
    pub async fn load(db: &Database) -> Result<Option<Self>> {
        let mut snapshot = db
            .get_session_values(super::session::APP_PASSWORD_SESSION_KEYS)
            .await?;
        let method = snapshot.remove("auth_method");
        if method.as_deref() != Some("app_password") {
            return Ok(None);
        }

        let handle = snapshot.remove("handle");
        let did = snapshot.remove("did");
        let access_jwt = snapshot.remove("access_jwt");
        let refresh_jwt = snapshot.remove("refresh_jwt");
        let pds_url = snapshot.remove("pds_url");

        match (handle, did, access_jwt, refresh_jwt, pds_url) {
            (Some(handle), Some(did), Some(access_jwt), Some(refresh_jwt), Some(pds_url)) => {
                let session = TokenSession::restore(
                    handle.clone(),
                    did.clone(),
                    access_jwt,
                    refresh_jwt,
                    pds_url.clone(),
                )
                .await?;
                Ok(Some(Self {
                    handle,
                    did,
                    pds_url,
                    session,
                }))
            }
            _ => Ok(None),
        }
    }
}
