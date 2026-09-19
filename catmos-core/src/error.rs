use thiserror::Error;

#[derive(Error, Debug)]
pub enum CatmosError {
    #[error("Unsupported canonical operation: {operation}")]
    UnsupportedOperation { operation: &'static str },
    #[error("Operation requires verified account consent and device readiness")]
    RequestEffectsNotAuthorized,
    #[error("Authentication required. Run `catmos login` first.")]
    NotAuthenticated,
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Authentication changed in another process. Retry this command; the newer session and device keys were preserved.")]
    AuthSessionChanged,
    #[error("PDS session renewal failed: {0}. Device keys were preserved.")]
    AuthRenewal(#[from] AuthRenewalFailure),
    #[error("Conversation not found: {0}")]
    ConvoNotFound(String),
    #[error("Not a member of conversation: {0}")]
    NotMember(String),
    #[error("MLS error: {0}")]
    Mls(#[from] catbird_mls::MLSError),
    /// Three-phase-commit failures from `MLSContext::{stage,confirm,discard}_commit`
    /// (task #62). Carries the structured `EpochMismatch { local, remote }`
    /// variant so callers can pattern-match instead of string-sniffing
    /// (task #63 — pending a `MLSError::EpochMismatch` unflatten).
    #[error("MLS commit error: {0}")]
    MlsCommit(#[from] catbird_mls::MLSCommitError),
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

impl From<sqlx::Error> for CatmosError {
    fn from(e: sqlx::Error) -> Self {
        CatmosError::Storage(format!("{e:#}"))
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

/// Closed classifications only: these errors cannot contain a response body,
/// bearer, URL, database error text or arbitrary server-provided string.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRenewalFailure {
    #[error("network transport failed while renewing the PDS session")]
    Transport,
    #[error("PDS rejected session renewal: HTTP {status} ({code})")]
    Rejected { status: u16, code: RenewalRejection },
    #[error("PDS returned an invalid refresh response")]
    Decode,
    #[error("could not read saved session")]
    ReadSnapshot,
    #[error("could not save renewed session")]
    PersistSnapshot,
    #[error("saved session is incomplete or invalid")]
    InvalidSnapshot,
    #[error("session was invalidated; restart the command or log in again")]
    Invalidated,
    #[error("PDS refresh returned a different account identity")]
    IdentityMismatch,
    #[error("could not retain renewed session in memory")]
    MemoryState,
}

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalRejection {
    #[error("InvalidToken")]
    InvalidToken,
    #[error("ExpiredToken")]
    ExpiredToken,
    #[error("AuthenticationRequired")]
    AuthenticationRequired,
    #[error("AccountTakedown")]
    AccountTakedown,
    #[error("AccountDeactivated")]
    AccountDeactivated,
    #[error("InvalidRequest")]
    InvalidRequest,
    #[error("RateLimitExceeded")]
    RateLimitExceeded,
    #[error("UnknownError")]
    UnknownError,
}

impl RenewalRejection {
    pub(crate) fn from_code(code: Option<&str>) -> Self {
        match code {
            Some("InvalidToken") => Self::InvalidToken,
            Some("ExpiredToken") => Self::ExpiredToken,
            Some("AuthenticationRequired") => Self::AuthenticationRequired,
            Some("AccountTakedown") => Self::AccountTakedown,
            Some("AccountDeactivated") => Self::AccountDeactivated,
            Some("InvalidRequest") => Self::InvalidRequest,
            Some("RateLimitExceeded") => Self::RateLimitExceeded,
            _ => Self::UnknownError,
        }
    }
}
