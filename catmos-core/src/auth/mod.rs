pub mod app_password;
pub mod oauth;
mod renewal;
pub(crate) mod service_auth;
pub mod session;

use crate::auth::app_password::AppPasswordAuth;
use crate::auth::oauth::OAuthAuth;
use crate::error::{CatmosError, Result};
use crate::storage::db::Database;

pub use session::TokenSession;

/// Represents the active authentication method for a session.
///
/// For AppPassword auth, live tokens are owned by `TokenSession` on ChatService;
/// this enum only carries metadata needed for routing / display.
#[derive(Clone)]
pub enum AuthMethod {
    OAuth {
        session_cookie: String,
        did: String,
        nest_url: String,
    },
    AppPassword {
        handle: String,
        did: String,
        pds_url: String,
    },
}

pub struct RestoredAuth {
    pub auth: AuthMethod,
    pub token_session: Option<TokenSession>,
}

pub async fn restore_saved_auth(db: &Database, expected_did: &str) -> Result<Option<RestoredAuth>> {
    if let Some(oauth) = OAuthAuth::load(db).await? {
        let validated = match oauth.validate_for_did(expected_did).await {
            Ok(validated) => validated,
            Err(err) => {
                db.clear_auth_session().await?;
                return Err(err);
            }
        };

        return Ok(Some(RestoredAuth {
            auth: AuthMethod::OAuth {
                session_cookie: oauth.session_cookie,
                did: validated.did,
                nest_url: oauth.nest_url,
            },
            token_session: None,
        }));
    }

    if let Some(ap) = AppPasswordAuth::load(db).await? {
        if ap.did != expected_did {
            db.clear_auth_session().await?;
            return Err(CatmosError::AuthFailed(format!(
                "restored app-password session DID mismatch: expected {expected_did}, stored {}. Run `catmos login` again.",
                ap.did
            )));
        }

        return Ok(Some(RestoredAuth {
            auth: AuthMethod::AppPassword {
                handle: ap.handle,
                did: ap.did,
                pds_url: ap.pds_url,
            },
            token_session: Some(ap.session),
        }));
    }

    Ok(None)
}
