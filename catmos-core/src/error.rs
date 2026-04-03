use thiserror::Error;

#[derive(Error, Debug)]
pub enum CatmosError {
    #[error("Authentication required. Run `catmos login` first.")]
    NotAuthenticated,
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Conversation not found: {0}")]
    ConvoNotFound(String),
    #[error("Not a member of conversation: {0}")]
    NotMember(String),
    #[error("MLS error: {0}")]
    Mls(#[from] catbird_mls::MLSError),
    #[error("XRPC error: {0}")]
    Xrpc(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CatmosError>;

impl From<rusqlite::Error> for CatmosError {
    fn from(e: rusqlite::Error) -> Self {
        CatmosError::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for CatmosError {
    fn from(e: serde_json::Error) -> Self {
        CatmosError::Other(format!("JSON error: {e}"))
    }
}

impl From<std::io::Error> for CatmosError {
    fn from(e: std::io::Error) -> Self {
        CatmosError::Other(format!("IO error: {e}"))
    }
}
