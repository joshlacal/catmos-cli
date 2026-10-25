use std::sync::Arc;

use clap::Parser;
use tokio::sync::RwLock;
use tracing::info;

use catmos_core::auth::app_password::AppPasswordAuth;
use catmos_core::auth::oauth::OAuthAuth;
use catmos_core::auth::restore_saved_auth;
use catmos_core::chat::ChatService;
use catmos_core::mls::{MlsManager, MLS_CIPHER_SUITE};
use catmos_core::orchestrator_api::CliApiClient;
use catmos_core::orchestrator_credentials::KeyringCredentialStore;
use catmos_core::orchestrator_storage::SqliteStorage;
use catmos_core::storage::aliases::AliasStore;
use catmos_core::storage::config::Config;
use catmos_core::storage::db::Database;
use catmos_core::types::MessageContent;
use catmos_core::CliOrchestrator;

#[derive(Parser)]
#[command(name = "catmos", about = "MLS group chat in your terminal")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Launch interactive chat TUI
    Chat,
    /// Send a message
    Send {
        /// Conversation name, alias, or ID
        convo: String,
        /// Message text
        message: String,
    },
    /// List conversations
    Convos,
    /// List members of a conversation
    Members {
        convo: String,
    },
    /// Print recent messages
    Messages {
        convo: String,
    },
    /// Authentication
    Login {
        handle: Option<String>,
        #[arg(long)]
        app_password: bool,
    },
    Logout,
    Accounts,
    Switch {
        handle: String,
    },
    #[command(subcommand)]
    Convo(ConvoCommands),
    React {
        convo: String,
        message_id: String,
        emoji: String,
    },
    Unreact {
        convo: String,
        message_id: String,
        emoji: String,
    },
    #[command(subcommand)]
    KeyPackage(KeyPackageCommands),
    #[command(subcommand)]
    Device(DeviceCommands),
    /// Reset the MLS group for a conversation (admin only)
    ResetGroup {
        /// Conversation name, alias, or ID
        convo: String,
        /// Optional reason for the reset
        #[arg(long)]
        reason: Option<String>,
    },
    #[command(subcommand)]
    Debug(DebugCommands),
    #[command(subcommand)]
    Blob(BlobCommands),
    #[command(subcommand)]
    Alias(AliasCommands),
    /// Manage Bluesky blocks (syncs with MLS group membership).
    #[command(subcommand)]
    Block(BlockCommands),
}

#[derive(clap::Subcommand)]
enum BlockCommands {
    /// Block a user. Leaves any shared MLS conversations (prompts first).
    Add {
        /// DID of the user to block.
        did: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Unblock a user. Does NOT rejoin groups (MLS requires a fresh invite).
    Remove {
        /// DID of the user to unblock.
        did: String,
    },
    /// List all users this account has blocked.
    List,
}

#[derive(clap::Subcommand)]
enum ConvoCommands {
    Create {
        name: String,
        #[arg(long, value_delimiter = ',')]
        members: Option<Vec<String>>,
        #[arg(long)]
        description: Option<String>,
    },
    Join {
        convo_id: String,
    },
    Accept {
        convo: String,
        #[arg(long)]
        inviter_did: Option<String>,
        #[arg(long)]
        inviter_device_id: Option<String>,
        #[arg(long)]
        invitation_transition_id: Option<String>,
        #[arg(long)]
        group_id: Option<String>,
        #[arg(long)]
        confirmation_tag: Option<String>,
        #[arg(long)]
        group_context_hash: Option<String>,
    },
    Fulfill {
        convo: String,
        #[arg(long)]
        recovery_request_id: Option<String>,
        #[arg(long)]
        requester_did: Option<String>,
        #[arg(long)]
        requester_device_id: Option<String>,
        #[arg(long)]
        key_package_base64: Option<String>,
        #[arg(long)]
        key_package_ref_base64: Option<String>,
    },
    JoinWelcome {
        convo: String,
    },
    /// Recover this device using the current server coordinate and any retained Welcome.
    RequestRecovery {
        convo: String,
    },
    Leave {
        convo: String,
    },
    Info {
        convo: String,
    },
    Update {
        convo: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    AddMember {
        convo: String,
        did: String,
    },
    RemoveMember {
        convo: String,
        did: String,
    },
    Promote {
        convo: String,
        did: String,
        #[arg(long)]
        admin: bool,
        #[arg(long)]
        moderator: bool,
    },
}

#[derive(clap::Subcommand)]
enum KeyPackageCommands {
    Status,
    Replenish,
}

#[derive(clap::Subcommand)]
enum DeviceCommands {
    List,
    Register {
        #[arg(long)]
        name: Option<String>,
    },
    Remove {
        device_id: String,
    },
}

#[derive(clap::Subcommand)]
enum DebugCommands {
    Epoch { convo: String },
    GroupState { convo: String },
    TreeHash { convo: String },
}

#[derive(clap::Subcommand)]
enum BlobCommands {
    Upload { convo: String, file: String },
    Download { blob_id: String, output: String },
    Usage,
}

#[derive(clap::Subcommand)]
enum AliasCommands {
    Set { alias: String, convo_id: String },
    List,
    Remove { alias: String },
}
// ── Service initialization ──────────────────────────────────────────────────

/// Load config, open the per-account database, restore auth, and build a ChatService.
async fn init_service() -> anyhow::Result<Arc<ChatService>> {
    let config = Config::load()?;

    let did = config
        .default_account
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No account configured. Run `catmos login` first."))?
        .to_string();

    let account_dir = Config::account_data_dir(&did)?;
    let db_path = account_dir.join("catmos.db");

    let db_key = catmos_core::mls::context::get_or_create_db_key(&did)?;
    let db = Database::open(&db_path, &db_key).await?;

    let restored = restore_saved_auth(&db, &did)
        .await?
        .ok_or_else(|| anyhow::anyhow!("No saved session found. Run `catmos login` first."))?;
    info!("Restored validated session for {did}");
    let auth = restored.auth;
    let token_session = restored.token_session;

    let mls_dir = Config::data_dir()?.join("mls");
    let mls = Arc::new(MlsManager::new(&mls_dir, &did)?);

    // Install the per-DID content-root key for the MLS field-level
    // encryption layer (`catbird_mls::field_encryption`). Materialized to
    // `{config_dir}/mls-content-root/{sha256(did)}.key` on first call;
    // shared between the orchestrator's `MLSContext` and the `Database`
    // write/read paths so encrypted rows round-trip.
    let content_root_key =
        catmos_core::storage::keys::load_or_create_content_root_key(&Config::config_dir()?, &did)?;
    mls.context()
        .set_content_root_key(content_root_key.clone())?;
    db.set_content_root_key(content_root_key);

    let aliases = Arc::new(RwLock::new(AliasStore::load()?));

    let db = Arc::new(db);
    let service = Arc::new(ChatService::new(
        auth,
        token_session,
        mls.clone(),
        db.clone(),
        config,
        aliases,
    ));

    let orchestrator_db = account_dir.join("orchestrator.db");
    let orchestrator_storage = Arc::new(SqliteStorage::new(
        orchestrator_db.to_string_lossy().as_ref(),
        &db_key,
    )?);
    orchestrator_storage.set_mls_context(mls.context().clone());
    let orchestrator_api = Arc::new(CliApiClient::new(service.clone()));
    let credentials =
        Arc::new(KeyringCredentialStore::try_new().map_err(|e| anyhow::anyhow!(e.to_string()))?);
    let orchestrator: Arc<CliOrchestrator> =
        Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
            mls.context().clone(),
            orchestrator_storage,
            orchestrator_api,
            credentials,
            catbird_mls::orchestrator::OrchestratorConfig::default(),
        ));
    service.set_orchestrator(orchestrator.clone()).await;
    if let Err(e) = orchestrator.initialize(&did).await {
        tracing::warn!("orchestrator initialization failed: {e}");
    }
    if let Err(e) = orchestrator.ensure_device_registered().await {
        tracing::warn!("orchestrator ensure_device_registered failed: {e}");
    }

    // Fetch conversations and join any that lack local MLS state
    match service.fetch_conversations().await {
        Ok(_convos) => {
            // Block reconciliation: leave any MLS group containing a
            // user from this account's own block list. Catches up on
            // blocks made from other clients (iOS, web, etc.) before
            // catmos-cli last ran.
            match service.list_own_blocks().await {
                Ok(blocks) if !blocks.is_empty() => {
                    let blocked: std::collections::HashSet<String> = blocks.into_iter().collect();
                    let convos_to_leave: Vec<String> = service
                        .conversations()
                        .await
                        .into_iter()
                        .filter(|c| c.members.iter().any(|m| blocked.contains(&m.user_did)))
                        .map(|c| c.group_id)
                        .collect();

                    let mut left = 0usize;
                    for id in &convos_to_leave {
                        if let Err(e) = service.leave_conversation(id).await {
                            tracing::warn!("reconcile leave {id}: {e}");
                        } else {
                            left += 1;
                        }
                    }
                    if left > 0 {
                        println!("Reconciled: left {left} group(s) containing blocked users.");
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("Failed to fetch own block list: {e}");
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to fetch conversations: {e}");
        }
    }

    Ok(service)
}

/// Open (or create) a per-account database for a login flow where we don't yet
/// have a ChatService. Returns the Database so auth can be saved.
async fn open_account_db(did: &str) -> anyhow::Result<Database> {
    let account_dir = Config::account_data_dir(did)?;
    let db_path = account_dir.join("catmos.db");
    let db_key = catmos_core::mls::context::get_or_create_db_key(did)?;
    let db = Database::open(&db_path, &db_key).await?;
    Ok(db)
}

// ── Command dispatch ────────────────────────────────────────────────────────

async fn handle_command(cmd: Commands) -> anyhow::Result<()> {
    match cmd {
        // ── Auth ─────────────────────────────────────────────────────────
        Commands::Login {
            handle,
            app_password,
        } => {
            let handle = match handle {
                Some(h) => h,
                None => {
                    eprint!("Handle: ");
                    let mut h = String::new();
                    std::io::stdin().read_line(&mut h)?;
                    h.trim().to_string()
                }
            };

            if app_password {
                eprint!("App password: ");
                let password = rpassword::read_password().or_else(|_| {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    Ok::<String, std::io::Error>(line.trim().to_string())
                })?;

                let session = AppPasswordAuth::login(&handle, &password).await?;
                println!("Logged in as {} ({})", session.handle, session.did);

                let db = open_account_db(&session.did).await?;
                session.save(&db).await?;

                let mut config = Config::load()?;
                config.default_account = Some(session.did);
                config.save()?;
            } else {
                let config = Config::load()?;
                let nest_url = &config.server.nest_url;

                println!("Starting OAuth flow for {handle}...");
                let session = OAuthAuth::login(&handle, nest_url).await?;
                println!("Logged in as {}", session.did);

                let db = open_account_db(&session.did).await?;
                session.save(&db).await?;

                let mut config = Config::load()?;
                config.default_account = Some(session.did);
                config.save()?;
            }
        }

        Commands::Logout => {
            let mut config = Config::load()?;
            if let Some(ref acct) = config.default_account {
                println!("Logged out of {acct}");
            }
            config.default_account = None;
            config.save()?;
        }

        Commands::Accounts => {
            let data_dir = Config::data_dir()?;
            let accounts_dir = data_dir.join("accounts");
            if accounts_dir.exists() {
                for entry in std::fs::read_dir(&accounts_dir)? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        println!("  {}", entry.file_name().to_string_lossy());
                    }
                }
            } else {
                println!("No accounts found.");
            }
        }

        Commands::Switch { handle } => {
            // The handle here is actually a DID; update config
            let mut config = Config::load()?;
            config.default_account = Some(handle.clone());
            config.save()?;
            println!("Switched to {handle}");
        }

        // ── Data commands ────────────────────────────────────────────────
        Commands::Convos => {
            let svc = init_service().await?;
            let convos = svc.fetch_conversations().await?;

            if convos.is_empty() {
                println!("No conversations.");
                return Ok(());
            }

            for c in &convos {
                let name = c.name.as_deref().unwrap_or("<unnamed>");
                println!(
                    "  {name}  members={} epoch={} id={}",
                    c.members.len(),
                    c.epoch,
                    &c.group_id[..12.min(c.group_id.len())]
                );
            }
        }

        Commands::Messages { convo } => {
            let svc = init_service().await?;
            svc.fetch_conversations().await?;
            let convo_id = svc.resolve_convo(&convo).await?;
            let messages: Vec<catmos_core::types::Message> =
                if let Some(orch) = svc.orchestrator().await {
                    if let Ok((orch_msgs, _)) = orch
                        .fetch_messages(&convo_id, None, 50, None, None, None)
                        .await
                    {
                        orch_msgs
                            .into_iter()
                            .map(|om| catmos_core::types::Message {
                                id: om.id,
                                convo_id: om.conversation_id,
                                sender_did: Some(om.sender_did),
                                content: MessageContent::Text(om.text),
                                epoch: om.epoch,
                                seq: om.sequence_number,
                                created_at: om.timestamp,
                            })
                            .collect()
                    } else {
                        svc.fetch_messages(&convo_id, 50).await.unwrap_or_default()
                    }
                } else {
                    svc.fetch_messages(&convo_id, 50).await?
                };
            let handle_cache = svc.handle_cache().await;
            let my_did = svc.did().to_string();

            if messages.is_empty() {
                println!("No messages.");
                return Ok(());
            }

            let mut shown_join = false;
            for m in &messages {
                // Skip decryption failures
                if let MessageContent::System(t) = &m.content {
                    if t.contains("Decryption failed") {
                        shown_join = true;
                        continue;
                    }
                }
                if matches!(&m.content, MessageContent::Unknown) {
                    continue;
                }

                if shown_join {
                    shown_join = false;
                    println!("  ── You joined this conversation ──");
                }

                let sender_did = m.sender_did.as_deref().unwrap_or("unknown");
                let sender = if sender_did == my_did {
                    "you".to_string()
                } else if let Some(handle) = handle_cache.get(sender_did) {
                    handle.clone()
                } else {
                    sender_did
                        .rsplit(':')
                        .next()
                        .unwrap_or(sender_did)
                        .to_string()
                };
                let ts = m.created_at.format("%H:%M");
                let body = match &m.content {
                    MessageContent::Text(t) => t.clone(),
                    MessageContent::Reaction { emoji, .. } => format!("[reaction: {emoji}]"),
                    MessageContent::System(t) => t.clone(),
                    MessageContent::Unknown => continue,
                };
                println!("[{ts}] {sender}: {body}");
            }
            if shown_join {
                println!("  ── You joined this conversation ──");
            }
        }

        Commands::Send { convo, message } => {
            let svc = init_service().await?;
            svc.fetch_conversations().await?;
            let convo_id = svc.resolve_convo(&convo).await?;
            let orch = svc
                .orchestrator()
                .await
                .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
            let msg = orch
                .send_message(&convo_id, &message)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            println!("Sent (epoch={})", msg.epoch);
        }

        Commands::Members { convo } => {
            let svc = init_service().await?;
            svc.fetch_conversations().await?;
            let convo_id = svc.resolve_convo(&convo).await?;

            let convos = svc.conversations().await;
            let convo_data = convos
                .iter()
                .find(|c| c.group_id == convo_id)
                .ok_or_else(|| anyhow::anyhow!("Conversation not found after fetch"))?;

            if convo_data.members.is_empty() {
                println!("No members (metadata may be sparse).");
                return Ok(());
            }

            let handle_cache = svc.handle_cache().await;
            for m in &convo_data.members {
                let role = if m.is_admin {
                    " [admin]"
                } else if m.is_moderator {
                    " [mod]"
                } else {
                    ""
                };
                let device = m
                    .device_name
                    .as_deref()
                    .unwrap_or_else(|| m.device_id.as_deref().unwrap_or("?"));
                let display = handle_cache
                    .get(&m.user_did)
                    .map(|h| h.as_str())
                    .unwrap_or(&m.user_did);
                println!("  {display} ({device}){role}");
            }
        }

        // ── Convo management ─────────────────────────────────────────────
        Commands::Convo(sub) => match sub {
            ConvoCommands::Create {
                name,
                members,
                description,
            } => {
                let svc = init_service().await?;
                let member_list = members.unwrap_or_default();
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let convo = orch
                    .create_group(&name, Some(&member_list), description.as_deref())
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Created conversation: {}", convo.group_id);
            }

            ConvoCommands::Leave { convo } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                orch.leave_via_self_remove(&convo_id)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Left conversation {convo}");
            }

            ConvoCommands::Info { convo } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;

                let convos = svc.conversations().await;
                let c = convos
                    .iter()
                    .find(|c| c.group_id == convo_id)
                    .ok_or_else(|| anyhow::anyhow!("Conversation not found"))?;

                println!("Name:         {}", c.name.as_deref().unwrap_or("<unnamed>"));
                println!("Group ID:     {}", c.group_id);
                println!("Creator:      {}", c.creator);
                println!("Epoch:        {}", c.epoch);
                println!("Cipher suite: {}", c.cipher_suite);
                println!("Members:      {}", c.members.len());
                println!("Created:      {}", c.created_at);
                if let Some(ref desc) = c.description {
                    println!("Description:  {desc}");
                }
                if let Some(last) = c.last_message_at {
                    println!("Last message: {last}");
                }
                println!("Unread:       {}", c.unread_count);
            }

            ConvoCommands::Join { convo_id } => {
                let svc = init_service().await?;
                // Route to the real external-commit join flow (fetch GroupInfo
                // → create_external_commit → POST commitGroupChange → merge
                // locally) in `MlsManager::join_via_external_commit`. The
                // former `ChatService::join_conversation` was a broken
                // placeholder (see service.rs task #65 note); removed.
                svc.mls
                    .join_via_external_commit(&svc, &convo_id, svc.did())
                    .await?;
                println!(
                    "Joined conversation {}",
                    &convo_id[..12.min(convo_id.len())]
                );
            }
            ConvoCommands::Accept {
                convo,
                inviter_did,
                inviter_device_id,
                invitation_transition_id,
                group_id,
                confirmation_tag,
                group_context_hash,
            } => {
                let svc = init_service().await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let res = if let (
                    Some(inv_trans),
                    Some(inv_did),
                    Some(inv_dev),
                    Some(gid),
                    Some(tag),
                    Some(gch),
                ) = (
                    invitation_transition_id,
                    inviter_did,
                    inviter_device_id,
                    group_id,
                    confirmation_tag,
                    group_context_hash,
                ) {
                    let prior = serde_json::json!({
                        "conversationId": convo,
                        "groupId": gid,
                        "epoch": 0,
                        "generation": 0,
                        "stateVersion": 0,
                        "groupContextHash": gch,
                        "confirmationTag": tag,
                        "lifecycle": "active"
                    });
                    orch.accept_conversation_with_invitation(
                        &convo, &inv_trans, &inv_did, &inv_dev, prior,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?
                } else {
                    orch.accept_conversation(&convo)
                        .await
                        .map_err(|e| anyhow::anyhow!(e.to_string()))?
                };
                println!(
                    "Accepted conversation {convo}: {}",
                    serde_json::to_string(&res)?
                );
            }

            ConvoCommands::Fulfill {
                convo,
                recovery_request_id,
                requester_did,
                requester_device_id,
                key_package_base64,
                key_package_ref_base64,
            } => {
                let svc = init_service().await?;
                let convo_id = if convo.len() == 36 && convo.contains('-') {
                    convo.clone()
                } else {
                    let _ = svc.fetch_conversations().await;
                    svc.resolve_convo(&convo)
                        .await
                        .unwrap_or_else(|_| convo.clone())
                };
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let res = orch
                    .fulfill_leaf_recovery_with_target(
                        &convo_id,
                        recovery_request_id.as_deref(),
                        requester_did.as_deref(),
                        requester_device_id.as_deref(),
                        key_package_base64.as_deref(),
                        key_package_ref_base64.as_deref(),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!(
                    "Fulfilled leaf recovery for {convo}: {}",
                    serde_json::to_string(&res)?
                );
            }

            ConvoCommands::JoinWelcome { convo } => {
                let svc = init_service().await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let view = orch
                    .join_conversation_from_entries(&convo)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!(
                    "Joined conversation via Welcome: {} (epoch={})",
                    view.group_id, view.epoch
                );
            }
            ConvoCommands::RequestRecovery { convo } => {
                let svc = init_service().await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let convo_id = svc.resolve_convo(&convo).await?;
                let epoch = orch.join_or_rejoin(&convo_id).await.map_err(|error| {
                    anyhow::anyhow!("Recovery has not completed for {convo_id}: {error}")
                })?;
                println!("Rejoined {convo_id} (epoch={epoch})");
            }

            ConvoCommands::Update {
                convo,
                name,
                description,
            } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                orch.update_group_metadata_encrypted(
                    &convo_id,
                    name.as_deref(),
                    description.as_deref(),
                    None,
                    None,
                    None,
                )
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Updated conversation {convo}");
            }

            ConvoCommands::AddMember { convo, did } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                orch.add_members(&convo_id, &[did.clone()])
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Invited {did} to {convo} (pending acceptance)");
            }

            ConvoCommands::RemoveMember { convo, did } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                orch.remove_members(&convo_id, &[did.clone()])
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Removed {did} from {convo}");
            }

            ConvoCommands::Promote {
                convo,
                did,
                admin,
                moderator,
            } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                svc.promote_member(&convo_id, &did, admin, moderator)
                    .await?;
                let role = if admin {
                    "admin"
                } else if moderator {
                    "moderator"
                } else {
                    "member"
                };
                println!("Promoted {did} to {role} in {convo}");
            }
        },

        // ── Devices ──────────────────────────────────────────────────────
        Commands::Device(sub) => match sub {
            DeviceCommands::List => {
                let svc = init_service().await?;
                let devices = svc.list_devices().await?;
                if devices.is_empty() {
                    println!("No devices registered.");
                } else {
                    for d in &devices {
                        println!(
                            "  {} (did={}, id={})",
                            d.device_name, d.mls_did, d.device_id
                        );
                    }
                }
            }
            DeviceCommands::Register { name } => {
                let svc = init_service().await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let device_id = orch
                    .ensure_device_registered()
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Registered device: id={device_id}");
            }
            DeviceCommands::Remove { device_id } => {
                let svc = init_service().await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                orch.remove_device(&device_id)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Removed device {device_id}");
            }
        },

        Commands::KeyPackage(sub) => match sub {
            KeyPackageCommands::Status => {
                let svc = init_service().await?;
                let status = svc.get_key_package_status().await?;
                println!(
                    "Key packages: {}/{} (replenish={})",
                    status.available, status.target, status.needs_replenish
                );
            }
            KeyPackageCommands::Replenish => {
                let svc = init_service().await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                orch.replenish_if_needed()
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Key packages replenished");
            }
        },

        // ── Aliases ──────────────────────────────────────────────────────
        Commands::Alias(sub) => match sub {
            AliasCommands::Set { alias, convo_id } => {
                let mut store = AliasStore::load()?;
                store.set(alias.clone(), convo_id.clone())?;
                println!("Alias '{alias}' -> {convo_id}");
            }
            AliasCommands::List => {
                let store = AliasStore::load()?;
                let all = store.all();
                if all.is_empty() {
                    println!("No aliases set.");
                } else {
                    for (alias, id) in all {
                        println!("  {alias} -> {id}");
                    }
                }
            }
            AliasCommands::Remove { alias } => {
                let mut store = AliasStore::load()?;
                match store.remove(&alias)? {
                    Some(id) => println!("Removed alias '{alias}' (was -> {id})"),
                    None => println!("Alias '{alias}' not found"),
                }
            }
        },

        // ── Reactions ─────────────────────────────────────────────────────
        Commands::React {
            convo,
            message_id,
            emoji,
        } => {
            let svc = init_service().await?;
            svc.fetch_conversations().await?;
            let convo_id = svc.resolve_convo(&convo).await?;
            svc.send_reaction(&convo_id, &message_id, &emoji, false)
                .await?;
            println!("Reacted {emoji} to {message_id}");
        }

        Commands::Unreact {
            convo,
            message_id,
            emoji,
        } => {
            let svc = init_service().await?;
            svc.fetch_conversations().await?;
            let convo_id = svc.resolve_convo(&convo).await?;
            svc.send_reaction(&convo_id, &message_id, &emoji, true)
                .await?;
            println!("Removed reaction {emoji} from {message_id}");
        }

        // ── Reset group ──────────────────────────────────────────────────
        Commands::ResetGroup { convo, reason } => {
            let svc = init_service().await?;
            svc.fetch_conversations().await?;
            let convo_id = svc.resolve_convo(&convo).await?;

            // Generate a new random group ID
            let new_group_id = hex::encode(rand::random::<[u8; 16]>());

            let req = serde_json::json!({
                "convoId": convo_id,
                "newGroupId": new_group_id,
                "cipherSuite": MLS_CIPHER_SUITE,
                "reason": reason,
            });

            let resp: serde_json::Value = svc
                .xrpc_procedure("blue.catbird.chat.requestReset", &req)
                .await?;

            println!(
                "Group reset: {} -> {} (generation {})",
                &convo_id[..12.min(convo_id.len())],
                &new_group_id[..12.min(new_group_id.len())],
                resp["resetGeneration"]
            );
        }

        // ── Debug ────────────────────────────────────────────────────────
        Commands::Debug(sub) => match sub {
            DebugCommands::Epoch { convo } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                match svc.get_epoch(&convo_id) {
                    Ok(epoch) => println!("Local MLS epoch: {epoch}"),
                    Err(e) => println!("Failed to read local epoch: {e}"),
                }
            }
            DebugCommands::GroupState { convo } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                let state = svc.get_group_state(&convo_id).await?;
                println!("{}", serde_json::to_string_pretty(&state)?);
            }
            DebugCommands::TreeHash { convo } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                match svc.get_tree_hash(&convo_id) {
                    Ok(hash) => println!("Tree hash: {}", hex::encode(&hash)),
                    Err(e) => println!("Failed to read tree hash: {e}"),
                }
            }
        },

        // ── Blob ─────────────────────────────────────────────────────────
        Commands::Blob(sub) => match sub {
            BlobCommands::Upload { convo, file } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                let blob_id = svc.upload_blob(&convo_id, &file).await?;
                println!("{blob_id}");
            }
            BlobCommands::Download { blob_id, output } => {
                let svc = init_service().await?;
                svc.download_blob(&blob_id, &output).await?;
                println!("Downloaded blob {blob_id} -> {output}");
            }
            BlobCommands::Usage => {
                let svc = init_service().await?;
                let usage = svc.get_blob_usage().await?;
                let used_mb = usage.used_bytes as f64 / (1024.0 * 1024.0);
                let quota_mb = usage.quota_bytes as f64 / (1024.0 * 1024.0);
                println!(
                    "Blobs: {} ({:.1} / {:.1} MB used)",
                    usage.blob_count, used_mb, quota_mb
                );
            }
        },

        // ── Blocks ───────────────────────────────────────────────────────
        Commands::Block(sub) => match sub {
            BlockCommands::Add { did, yes } => {
                let svc = init_service().await?;
                // Ensure conversation list is populated so we can compute
                // affected groups. init_service attempts this too, but the
                // fetch may have been skipped on MLS registration failure.
                if let Err(e) = svc.fetch_conversations().await {
                    tracing::warn!("fetch_conversations failed before block: {e}");
                }

                let affected: Vec<String> = svc
                    .conversations()
                    .await
                    .into_iter()
                    .filter(|c| c.members.iter().any(|m| m.user_did == did))
                    .map(|c| c.group_id)
                    .collect();

                if !yes {
                    println!(
                        "Blocking {} will leave {} conversation(s). Continue? [y/N]",
                        did,
                        affected.len()
                    );
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }

                let uri = svc.create_block(&did).await?;
                tracing::info!("Created block record: {uri}");

                let mut left = 0usize;
                for id in &affected {
                    match svc.leave_conversation(id).await {
                        Ok(()) => left += 1,
                        Err(e) => eprintln!("leave {id} failed: {e}"),
                    }
                }
                println!(
                    "Blocked {did} and left {left}/{} conversations.",
                    affected.len()
                );
            }
            BlockCommands::Remove { did } => {
                let svc = init_service().await?;
                let deleted = svc.remove_block(&did).await?;
                if deleted == 0 {
                    println!("No existing block record found for {did}.");
                } else {
                    println!(
                        "Unblocked {did} ({deleted} record(s) removed). \
                         Previously-left conversations are NOT rejoined — \
                         MLS requires a fresh invite."
                    );
                }
            }
            BlockCommands::List => {
                let svc = init_service().await?;
                let blocks = svc.list_own_blocks().await?;
                if blocks.is_empty() {
                    println!("(no blocks)");
                } else {
                    for did in blocks {
                        println!("{did}");
                    }
                }
            }
        },

        Commands::Chat => {
            unreachable!("handled in main");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let is_tui = matches!(cli.command, None | Some(Commands::Chat));

    // Default filter: suppress noisy openmls internals
    let default_filter = "warn,catmos=info,catmos_core=info,catmos_core::chat=debug,catmos_tui=info,openmls=off,openmls_rust_crypto=off,openmls_memory_storage=off";
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));

    if is_tui {
        // TUI mode: log to file to avoid polluting the terminal
        let log_dir = catmos_core::storage::config::Config::data_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
        let log_file = std::fs::File::create(log_dir.join("catmos.log")).unwrap_or_else(|_| {
            std::fs::File::create("/tmp/catmos.log").expect("cannot create log file")
        });
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::sync::Mutex::new(log_file))
            .with_ansi(false)
            .init();
    } else {
        // CLI mode: log to stderr
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }

    // Bridge `log` crate (used by openmls) into tracing so the filter above works
    tracing_log::LogTracer::init().ok();

    match cli.command {
        None | Some(Commands::Chat) => {
            catmos_tui::run().await?;
        }
        Some(cmd) => {
            handle_command(cmd).await?;
        }
    }

    Ok(())
}
