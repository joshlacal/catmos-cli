pub mod app_password;
pub mod oauth;
pub mod session;

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
