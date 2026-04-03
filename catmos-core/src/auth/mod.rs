pub mod app_password;
pub mod oauth;

/// Represents the active authentication method for a session.
pub enum AuthMethod {
    OAuth {
        session_cookie: String,
        did: String,
        nest_url: String,
    },
    AppPassword {
        handle: String,
        did: String,
        access_jwt: String,
        refresh_jwt: String,
        pds_url: String,
    },
}
