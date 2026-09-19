pub mod auth;
pub mod chat;
pub(crate) mod device_records;
pub mod error;
mod http_client;
pub mod mls;
pub mod orchestrator_api;
pub mod orchestrator_credentials;
pub mod orchestrator_storage;
pub mod recovery;
pub mod runtime;
pub mod storage;
pub mod types;
pub type CliOrchestrator = catbird_mls::orchestrator::MLSOrchestrator<
    orchestrator_storage::SqliteStorage,
    orchestrator_api::CliApiClient,
    orchestrator_credentials::KeyringCredentialStore,
    catbird_mls::MLSContext,
>;
