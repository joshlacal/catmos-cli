//! Shared native runtime bootstrap for the command-line and terminal clients.
//!
//! The runtime owns the per-account presentation database, MLS context,
//! orchestrator authority, and protected orchestrator journal. Entry points
//! select only their startup policy; they do not assemble parallel MLS stacks.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::auth::{restore_saved_auth, RestoredAuth};
use crate::chat::ChatService;
use crate::mls::MlsManager;
use crate::orchestrator_api::CliApiClient;
use crate::orchestrator_credentials::KeyringCredentialStore;
use crate::orchestrator_storage::SqliteStorage;
use crate::storage::aliases::AliasStore;
use crate::storage::config::Config;
use crate::storage::db::Database;
use crate::CliOrchestrator;

/// Startup behavior retained by the two native entry points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStartup {
    /// CLI commands require network registration to succeed. Canonical sync
    /// remains best-effort, matching the historical command bootstrap.
    Command { run_startup_sync: bool },
    /// The interactive TUI bounds network startup and remains usable with its
    /// locally initialized authority when the server is temporarily offline.
    Interactive,
}

impl RuntimeStartup {
    pub const fn command(run_startup_sync: bool) -> Self {
        Self::Command { run_startup_sync }
    }

    pub const fn interactive() -> Self {
        Self::Interactive
    }

    pub const fn run_startup_sync(self) -> bool {
        match self {
            Self::Command { run_startup_sync } => run_startup_sync,
            Self::Interactive => true,
        }
    }

    pub const fn network_failures_are_fatal(self) -> bool {
        matches!(self, Self::Command { .. })
    }
}

/// Non-sensitive startup effects that an entry point may present to a user.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeStartupReport {
    pub reconciled_blocked_groups: usize,
}

/// Fully initialized per-account MLS runtime shared by CLI and TUI callers.
///
/// T06 request commands can use [`Self::orchestrator`] for the canonical
/// request lifecycle while existing presentation paths continue to use
/// [`Self::service`]. Both handles refer to the same authority and storage.
pub struct Runtime {
    did: String,
    config: Config,
    service: Arc<ChatService>,
    orchestrator: Arc<CliOrchestrator>,
    startup_report: RuntimeStartupReport,
}

impl Runtime {
    /// Restore the selected account and initialize its local authority before
    /// applying the entry point's network startup policy.
    pub async fn initialize(startup: RuntimeStartup) -> anyhow::Result<Self> {
        let mut runtime = load_local_runtime().await?;

        if startup.network_failures_are_fatal() {
            runtime.start_network(startup.run_startup_sync()).await?;
        } else {
            match tokio::time::timeout(
                Duration::from_secs(15),
                runtime.start_network(startup.run_startup_sync()),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::error!("MLS setup failed: {error}"),
                Err(_) => tracing::info!(
                    "MLS setup timed out — continuing with initialized local authority"
                ),
            }
        }

        Ok(runtime)
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn service(&self) -> &Arc<ChatService> {
        &self.service
    }

    pub fn orchestrator(&self) -> &Arc<CliOrchestrator> {
        &self.orchestrator
    }

    pub const fn startup_report(&self) -> RuntimeStartupReport {
        self.startup_report
    }

    async fn start_network(&mut self, run_startup_sync: bool) -> anyhow::Result<()> {
        self.orchestrator
            .ensure_device_registered()
            .await
            .map_err(|error| anyhow::anyhow!("Device registration failed: {error}"))?;
        self.service
            .ensure_device_record_published()
            .await
            .map_err(|error| anyhow::anyhow!("Device identity publication failed: {error}"))?;

        if run_startup_sync {
            if let Err(error) = self.orchestrator.sync_with_server(false).await {
                tracing::warn!("Conversation synchronization incomplete: {error}");
            }
        }

        match self.service.fetch_conversations().await {
            Ok(_) if run_startup_sync => {
                self.startup_report.reconciled_blocked_groups =
                    reconcile_blocked_groups(&self.service).await;
            }
            Ok(_) => {}
            Err(error) => tracing::warn!("Failed to fetch conversations: {error}"),
        }

        Ok(())
    }
}

async fn load_local_runtime() -> anyhow::Result<Runtime> {
    let config = Config::load()?;
    let did = config
        .default_account
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No account configured. Run `catmos login` first."))?
        .to_string();
    let account_dir = Config::account_data_dir(&did)?;
    let database_key = crate::mls::context::get_or_create_db_key(&did)?;
    let database = Arc::new(Database::open(&account_dir.join("catmos.db"), &database_key).await?);
    let restored_auth = restore_saved_auth(&database, &did)
        .await?
        .ok_or_else(|| anyhow::anyhow!("No saved session found. Run `catmos login` first."))?;
    tracing::info!("Restored saved session for {did}");

    assemble_local_runtime(LocalRuntimeInput {
        did,
        config,
        restored_auth,
        database,
        database_key,
        account_dir,
        mls_dir: Config::data_dir()?.join("mls"),
        config_dir: Config::config_dir()?,
        aliases: AliasStore::load()?,
    })
    .await
}

struct LocalRuntimeInput {
    did: String,
    config: Config,
    restored_auth: RestoredAuth,
    database: Arc<Database>,
    database_key: String,
    account_dir: PathBuf,
    mls_dir: PathBuf,
    config_dir: PathBuf,
    aliases: AliasStore,
}

async fn assemble_local_runtime(input: LocalRuntimeInput) -> anyhow::Result<Runtime> {
    let mls = Arc::new(MlsManager::new(&input.mls_dir, &input.did)?);
    let content_root_key =
        crate::storage::keys::load_or_create_content_root_key(&input.config_dir, &input.did)?;
    mls.context()
        .set_content_root_key(content_root_key.clone())?;
    input.database.set_content_root_key(content_root_key);

    let service = Arc::new(ChatService::new(
        input.restored_auth.auth,
        input.restored_auth.token_session,
        Arc::clone(&mls),
        Arc::clone(&input.database),
        input.config.clone(),
        Arc::new(RwLock::new(input.aliases)),
    ));
    let orchestrator_storage = Arc::new(SqliteStorage::new(
        input
            .account_dir
            .join("orchestrator.db")
            .to_string_lossy()
            .as_ref(),
        &input.database_key,
    )?);
    orchestrator_storage.set_mls_context(mls.context().clone());
    let orchestrator_api = Arc::new(CliApiClient::new(Arc::clone(&service)));
    let credentials = Arc::new(
        KeyringCredentialStore::try_new().map_err(|error| anyhow::anyhow!(error.to_string()))?,
    );
    let orchestrator: Arc<CliOrchestrator> =
        Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
            mls.context().clone(),
            orchestrator_storage,
            orchestrator_api,
            credentials,
            catbird_mls::orchestrator::OrchestratorConfig::default(),
        ));
    service.set_orchestrator(Arc::clone(&orchestrator)).await;
    orchestrator
        .initialize(&input.did)
        .await
        .map_err(|error| anyhow::anyhow!("MLS initialization failed: {error}"))?;

    Ok(Runtime {
        did: input.did,
        config: input.config,
        service,
        orchestrator,
        startup_report: RuntimeStartupReport::default(),
    })
}

async fn reconcile_blocked_groups(service: &Arc<ChatService>) -> usize {
    let blocks = match service.list_own_blocks().await {
        Ok(blocks) => blocks,
        Err(error) => {
            tracing::warn!("Failed to fetch own block list: {error}");
            return 0;
        }
    };
    if blocks.is_empty() {
        return 0;
    }

    let blocked: HashSet<String> = blocks.into_iter().collect();
    let conversations_to_leave: Vec<String> = service
        .conversations()
        .await
        .into_iter()
        .filter(|conversation| {
            conversation
                .members
                .iter()
                .any(|member| blocked.contains(&member.user_did))
        })
        .map(|conversation| conversation.group_id)
        .collect();

    let mut left = 0;
    for conversation_id in conversations_to_leave {
        match service.leave_conversation(&conversation_id).await {
            Ok(()) => left += 1,
            Err(error) => tracing::warn!("reconcile leave {conversation_id}: {error}"),
        }
    }
    left
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use catbird_mls::orchestrator::storage::MLSStorageBackend;
    use catbird_mls::orchestrator::types::ConversationState;
    use tempfile::TempDir;

    use crate::auth::{AuthMethod, RestoredAuth};
    use crate::storage::aliases::AliasStore;
    use crate::storage::config::Config;
    use crate::storage::db::Database;

    use super::{assemble_local_runtime, LocalRuntimeInput, RuntimeStartup};

    const DID: &str = "did:plc:runtimeparity";

    async fn fixture() -> (TempDir, LocalRuntimeInput) {
        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let root = tempfile::tempdir().expect("runtime fixture directory");
        let account_dir = root.path().join("account");
        let mls_dir = root.path().join("mls");
        let config_dir = root.path().join("config");
        std::fs::create_dir_all(&account_dir).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        let database_key = "runtime-test-database-key".to_string();
        let database = Arc::new(
            Database::open(&account_dir.join("catmos.db"), &database_key)
                .await
                .unwrap(),
        );
        let config = Config::default();
        let restored_auth = RestoredAuth {
            auth: AuthMethod::OAuth {
                session_cookie: "fixture-cookie".into(),
                did: DID.into(),
                nest_url: config.server.nest_url.clone(),
            },
            token_session: None,
        };
        let input = LocalRuntimeInput {
            did: DID.into(),
            config,
            restored_auth,
            database,
            database_key,
            account_dir,
            mls_dir,
            config_dir,
            aliases: AliasStore::with_path(root.path().join("aliases.json")),
        };
        (root, input)
    }

    #[test]
    fn entrypoint_policies_keep_cli_and_tui_startup_behavior_explicit() {
        assert!(!RuntimeStartup::command(false).run_startup_sync());
        assert!(RuntimeStartup::command(false).network_failures_are_fatal());
        assert!(RuntimeStartup::interactive().run_startup_sync());
        assert!(!RuntimeStartup::interactive().network_failures_are_fatal());
    }

    #[tokio::test]
    async fn local_bootstrap_attaches_the_initialized_authority_used_by_service() {
        let (_root, input) = fixture().await;
        let runtime = assemble_local_runtime(input).await.unwrap();

        assert_eq!(runtime.did(), DID);
        let service_authority = runtime
            .service()
            .orchestrator()
            .await
            .expect("service must expose initialized authority");
        assert!(Arc::ptr_eq(runtime.orchestrator(), &service_authority));
    }

    #[tokio::test]
    async fn local_bootstrap_reopens_the_same_protected_orchestrator_state() {
        let (root, input) = fixture().await;
        let database_key = input.database_key.clone();
        let orchestrator_path = input.account_dir.join("orchestrator.db");
        let runtime = assemble_local_runtime(input).await.unwrap();

        runtime
            .orchestrator()
            .storage()
            .ensure_conversation_exists(
                DID,
                "request-journal-fixture",
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            )
            .await
            .unwrap();
        runtime
            .orchestrator()
            .storage()
            .set_conversation_state("request-journal-fixture", ConversationState::Active)
            .await
            .unwrap();
        drop(runtime);

        assert!(crate::orchestrator_storage::SqliteStorage::new(
            orchestrator_path.to_str().unwrap(),
            "wrong-runtime-key",
        )
        .is_err());
        let reopened = crate::orchestrator_storage::SqliteStorage::new(
            orchestrator_path.to_str().unwrap(),
            &database_key,
        )
        .unwrap();
        assert_eq!(
            reopened
                .get_conversation_state("request-journal-fixture")
                .await
                .unwrap(),
            Some(ConversationState::Active)
        );
        drop(root);
    }
}
