mod requests;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

static SKIP_STARTUP_SYNC: AtomicBool = AtomicBool::new(false);

use clap::Parser;

use catmos_core::auth::app_password::AppPasswordAuth;
use catmos_core::auth::oauth::OAuthAuth;
use catmos_core::chat::ChatService;
use catmos_core::runtime::{Runtime, RuntimeStartup};
use catmos_core::storage::aliases::AliasStore;
use catmos_core::storage::config::Config;
use catmos_core::storage::db::Database;
use catmos_core::types::MessageContent;

#[derive(Parser)]
#[command(name = "catmos", about = "MLS group chat in your terminal")]
struct Cli {
    /// Isolated local device profile (also CATMOS_PROFILE); never reuses another profile's keys
    #[arg(long, global = true)]
    profile: Option<String>,
    /// Skip automatic recovery of unrelated conversations before a CLI command
    #[arg(long, global = true)]
    no_startup_sync: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Encrypted direct requests (all outputs are JSON).
    #[command(subcommand)]
    Request(requests::RequestCommands),
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
    /// Fulfill a pending device admission or recovery for one conversation
    #[command(alias = "fulfill-recovery")]
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
    /// Finish one member's pending group leave using this device's MLS state
    FulfillLeave {
        convo: String,
    },
    /// Verify terminal access for one exact conversation ID and show durable state
    ReconcileAccess {
        convo_id: String,
    },
    JoinWelcome {
        convo: String,
    },
    /// Re-admit this device after losing its MLS group: asks a live leaf to
    /// re-add us, or resets the conversation when nobody can (admin only).
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
    Epoch {
        convo: String,
    },
    GroupState {
        convo: String,
    },
    TreeHash {
        convo: String,
    },
    /// Fault injection: drop the local MLS group (simulates a reinstall) and
    /// mark the conversation for rejoin.
    WipeGroup {
        convo: String,
    },
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

/// Build the shared per-account MLS runtime used by CLI and TUI entry points.
async fn init_service() -> anyhow::Result<Arc<ChatService>> {
    let runtime = Runtime::initialize(RuntimeStartup::command(
        !SKIP_STARTUP_SYNC.load(Ordering::Relaxed),
    ))
    .await?;
    let reconciled = runtime.startup_report().reconciled_blocked_groups;
    if reconciled > 0 {
        eprintln!("Reconciled: left {reconciled} group(s) containing blocked users.");
    }
    Ok(Arc::clone(runtime.service()))
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

fn configured_delivery_service() -> anyhow::Result<String> {
    let config = Config::load()?;
    Ok(format!(
        "did:web:{}",
        config
            .server
            .mls_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
    ))
}

// ── Command dispatch ────────────────────────────────────────────────────────

async fn handle_command(cmd: Commands) -> anyhow::Result<()> {
    match cmd {
        Commands::Request(command) => {
            let offline = matches!(
                &command,
                requests::RequestCommands::List { offline: true }
                    | requests::RequestCommands::Status { .. }
            );
            let service = if offline {
                Arc::clone(Runtime::initialize_offline().await?.service())
            } else {
                init_service().await?
            };
            requests::run(service, command).await?;
        }
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
                    &c.conversation_id
                );
            }
        }

        Commands::Messages { convo } => {
            let svc = init_service().await?;
            svc.fetch_conversations().await?;
            let convo_id = svc.resolve_convo(&convo).await?;
            let orch_messages = svc
                .load_canonical_message_history(&convo_id, 50)
                .await
                .map_err(|error| anyhow::anyhow!("Could not load messages: {error}"))?;
            use catbird_mls::orchestrator::types::ConversationState;
            let terminal = matches!(
                svc.canonical_conversation_state(&convo_id).await?,
                Some(ConversationState::DeviceRemoved | ConversationState::Closed)
            );
            let own_device_id = svc.actor_device_id().await?;
            let messages: Vec<catmos_core::types::Message> = orch_messages
                .into_iter()
                .map(|message| {
                    let content =
                        canonical_message_content(&message, svc.did(), &own_device_id, terminal);
                    catmos_core::types::Message {
                        id: message.id,
                        convo_id: message.conversation_id,
                        sender_did: Some(message.sender_did),
                        content,
                        epoch: message.epoch,
                        seq: message.sequence_number,
                        created_at: message.timestamp,
                    }
                })
                .collect();
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
                if let MessageContent::System(label) = &m.content {
                    println!("[{ts}] ── {label} ──");
                    continue;
                }
                let body = match &m.content {
                    MessageContent::GroupInvitation { text, reference } => format!(
                        "{text}\n[Group invitation: {} — acceptance is separate]",
                        reference.conversation_id
                    ),
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
                .find(|c| c.conversation_id == convo_id)
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
                let delivery_service = configured_delivery_service()?;
                svc.require_chat_declaration(&delivery_service).await?;
                anyhow::ensure!(
                    svc.orchestrator().await.is_some(),
                    "MLS orchestrator unavailable"
                );
                let convo = svc
                    .create_conversation(&name, &member_list, description.as_deref())
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Created conversation: {}", convo.conversation_id);
            }

            ConvoCommands::Leave { convo } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                use catbird_mls::orchestrator::lifecycle::LeaveOutcome;
                match orch.leave_conversation(&convo_id).await
                    .map_err(|error| anyhow::anyhow!("Could not leave conversation: {error}"))?
                {
                    LeaveOutcome::Left => println!("Left conversation {convo_id}"),
                    LeaveOutcome::Pending { leave_request_id } => println!(
                        "Leave requested for {convo_id}. Waiting for another member's device to finish removing you (request={leave_request_id})."
                    ),
                }
            }

            ConvoCommands::Info { convo } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;

                let convos = svc.conversations().await;
                let c = convos
                    .iter()
                    .find(|c| c.conversation_id == convo_id)
                    .ok_or_else(|| anyhow::anyhow!("Conversation not found"))?;

                let (creator, created) = creation_info_values(c);
                println!("Name:         {}", c.name.as_deref().unwrap_or("<unnamed>"));
                println!("Group ID:     {}", c.group_id);
                println!("Creator:      {creator}");
                println!("Epoch:        {}", c.epoch);
                println!("Cipher suite: {}", c.cipher_suite);
                println!("Members:      {}", c.members.len());
                println!("Created:      {created}");
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
                let convo_id = svc.resolve_convo(&convo_id).await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let epoch = orch
                    .join_or_rejoin(&convo_id)
                    .await
                    .map_err(|error| anyhow::anyhow!("Could not join conversation: {error}"))?;
                println!("Joined conversation {convo_id} (epoch={epoch})");
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

            ConvoCommands::FulfillLeave { convo } => {
                let svc = init_service().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let fulfilled = orch
                    .fulfill_pending_group_leave(&convo_id)
                    .await
                    .map_err(|error| anyhow::anyhow!("Could not fulfill group leave: {error}"))?;
                if fulfilled {
                    println!("Finished pending group leave for {convo_id}");
                } else {
                    println!("No pending group leave was completed for {convo_id}");
                }
            }

            ConvoCommands::ReconcileAccess { convo_id } => {
                use catbird_mls::orchestrator::storage::MLSStorageBackend;
                catbird_mls::chat_v2::ids::ConversationId::parse(&convo_id)
                    .map_err(|error| anyhow::anyhow!("Use the exact conversation UUID: {error}"))?;
                let svc = init_service().await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let reconciled = orch
                    .reconcile_terminal_conversation(&convo_id)
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("Could not verify conversation access: {error}")
                    })?;
                let state = orch
                    .storage()
                    .get_conversation_state(&convo_id)
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("Could not read persisted access state: {error}")
                    })?;
                println!(
                    "{}",
                    serde_json::json!({
                        "conversationId": convo_id, "terminalProofApplied": reconciled,
                        "persistedState": state,
                    })
                );
            }

            ConvoCommands::JoinWelcome { convo } => {
                let svc = init_service().await?;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                // Welcome-first join (pending-welcome inventory → process →
                // acknowledgeWelcome), the same path iOS takes; entries never
                // carry a Welcome for a device that is not yet a leaf.
                let convo_id = svc.resolve_convo(&convo).await?;
                let epoch = orch
                    .join_or_rejoin(&convo_id)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Joined conversation via Welcome: {convo} (epoch={epoch})");
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
                orch.remove_accounts(&convo_id, &[did.clone()])
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
            DeviceCommands::Register { name: _ } => {
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
                // A registered device is invisible to other users until the
                // account's repo declares which DS serves it.
                let ds_did = configured_delivery_service()?;
                svc.ensure_chat_declaration(&ds_did).await?;
                println!("Secure chat ready: deliveryService={ds_did}");
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
            let orch = svc
                .orchestrator()
                .await
                .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
            let outcome = orch
                .reset_conversation(&convo, reason.as_deref().unwrap_or("manualRecovery"))
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            println!("Reset {convo}: {outcome:?}");
        }

        // ── Debug ────────────────────────────────────────────────────────
        Commands::Debug(sub) => match sub {
            DebugCommands::Epoch { convo } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let group_id = svc.resolve_mls_group_id(&convo).await?;
                match svc.get_epoch(&group_id) {
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
                let group_id = svc.resolve_mls_group_id(&convo).await?;
                match svc.get_tree_hash(&group_id) {
                    Ok(hash) => println!("Tree hash: {}", hex::encode(&hash)),
                    Err(e) => println!("Failed to read tree hash: {e}"),
                }
            }
            DebugCommands::WipeGroup { convo } => {
                let svc = init_service().await?;
                let convo_id = convo;
                let orch = svc
                    .orchestrator()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("MLS orchestrator unavailable"))?;
                let res = orch
                    .debug_wipe_local_group_for_recovery(&convo_id)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!("Wiped local group for {convo_id}: {res:?}");
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

fn canonical_message_content(
    message: &catbird_mls::orchestrator::types::Message,
    own_did: &str,
    own_device_id: &str,
    has_durable_terminal_state: bool,
) -> MessageContent {
    use catbird_mls::orchestrator::types::MLSMessageType;
    if let Some(payload) = message.payload() {
        if payload.version == 1 && payload.message_type == MLSMessageType::System {
            let label = match payload.text.as_deref() {
                Some("history_boundary.new_member") => Some("You joined this conversation. Earlier messages are not available on this device."),
                Some("history_boundary.device_rejoined") => Some("This device rejoined the conversation. Earlier messages may not be available."),
                Some("conversation.closed") => Some("Conversation status changed."),
                Some("membership.left") => Some(if catmos_core::types::is_local_membership_left_marker(message, own_did, own_device_id, has_durable_terminal_state) {
                    "You left this conversation."
                } else {
                    "Membership update"
                }),
                _ => None,
            };
            if let Some(label) = label {
                return MessageContent::System(label.to_owned());
            }
        }
    }
    // Literal marker keys and JSON in ordinary text are still user messages.
    MessageContent::Text(message.text.clone())
}

fn creation_info_values(conversation: &catmos_core::types::Conversation) -> (String, String) {
    (
        conversation
            .creator
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("<unknown>")
            .to_owned(),
        conversation
            .created_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<unknown>".to_owned()),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let environment_profile = std::env::var("CATMOS_PROFILE").ok();
    Config::initialize_profile(cli.profile.as_deref().or(environment_profile.as_deref()))?;
    let is_tui = matches!(cli.command, None | Some(Commands::Chat));
    anyhow::ensure!(
        !is_tui || !cli.no_startup_sync,
        "--no-startup-sync requires a CLI command"
    );
    SKIP_STARTUP_SYNC.store(cli.no_startup_sync, Ordering::Relaxed);

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

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn history_boundary_labels_require_a_supported_structured_system_payload() {
        use catbird_mls::orchestrator::types::{MLSMessagePayload, Message};
        let own_device = "11111111-1111-4111-8111-111111111111";
        let render = |message: &Message| {
            canonical_message_content(message, "did:plc:test", own_device, true)
        };
        let make = |text: &str, payload: Option<String>| -> Message {
            serde_json::from_value(serde_json::json!({
                "id": format!("membership-left:22222222-2222-4222-8222-222222222222:{own_device}"),
                "conversation_id": "conversation", "sender_did": "did:plc:test",
                "text": text, "timestamp": "2026-09-05T02:34:00Z", "epoch": 1,
                "sequence_number": 0, "is_own": true, "payload_json": payload,
            }))
            .unwrap()
        };
        for (key, expected) in [
            (
                "history_boundary.new_member",
                "You joined this conversation. Earlier messages are not available on this device.",
            ),
            (
                "history_boundary.device_rejoined",
                "This device rejoined the conversation. Earlier messages may not be available.",
            ),
            ("membership.left", "You left this conversation."),
            ("conversation.closed", "Conversation status changed."),
        ] {
            let payload = serde_json::to_string(&MLSMessagePayload::system(key)).unwrap();
            assert!(
                matches!(render(&make(key, Some(payload))), MessageContent::System(label) if label == expected)
            );
            assert!(matches!(render(&make(key, None)), MessageContent::Text(text) if text == key));
            let text_payload = serde_json::to_string(&MLSMessagePayload::text(key)).unwrap();
            assert!(
                matches!(render(&make(key, Some(text_payload))), MessageContent::Text(text) if text == key)
            );
            let mut future = MLSMessagePayload::system(key);
            future.version = 2;
            assert!(
                matches!(render(&make(key, Some(serde_json::to_string(&future).unwrap()))), MessageContent::Text(text) if text == key)
            );
        }
        let membership = make(
            "You left this conversation.",
            Some(serde_json::to_string(&MLSMessagePayload::system("membership.left")).unwrap()),
        );
        for (wrong_id, wrong_sender, own_flag, terminal) in [
            ("peer-chosen-id", "did:plc:test", true, true),
            ("membership-left:22222222-2222-1222-8222-222222222222:11111111-1111-4111-8111-111111111111", "did:plc:test", true, true),
            ("membership-left:22222222-2222-4222-8222-222222222222:33333333-3333-4333-8333-333333333333", "did:plc:test", true, true),
            (membership.id.as_str(), "did:plc:peer", true, true),
            (membership.id.as_str(), "did:plc:test", false, true),
            (membership.id.as_str(), "did:plc:test", true, false),
        ] {
            let mut unverified = membership.clone();
            unverified.id = wrong_id.into();
            unverified.sender_did = wrong_sender.into();
            unverified.is_own = own_flag;
            assert!(matches!(canonical_message_content(&unverified, "did:plc:test", own_device, terminal), MessageContent::System(label) if label == "Membership update"));
        }
        let literal_json =
            r#"{"version":1,"messageType":"system","text":"history_boundary.new_member"}"#;
        assert!(
            matches!(render(&make(literal_json, None)), MessageContent::Text(text) if text == literal_json)
        );
        let closed = make(
            "Conversation closed.",
            Some(serde_json::to_string(&MLSMessagePayload::system("conversation.closed")).unwrap()),
        );
        assert!(
            matches!(canonical_message_content(&closed, "did:plc:other", own_device, false), MessageContent::System(label) if label == "Conversation status changed.")
        );
    }

    #[test]
    fn creation_info_renders_unknown_without_inventing_a_member_or_timestamp() {
        let mut value = serde_json::json!({
            "conversation_id": "conversation", "group_id": "group", "epoch": 0,
            "cipher_suite": "suite", "members": [], "unread_count": 0,
        });
        let unknown = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            creation_info_values(&unknown),
            ("<unknown>".into(), "<unknown>".into())
        );
        value["creator"] = serde_json::json!("did:plc:creator");
        value["created_at"] = serde_json::json!("2026-09-05T02:34:00Z");
        let explicit = serde_json::from_value(value).unwrap();
        assert_eq!(
            creation_info_values(&explicit),
            ("did:plc:creator".into(), "2026-09-05 02:34:00 UTC".into(),)
        );
    }

    #[test]
    fn scoped_profile_flags_work_after_subcommands() {
        let cli = Cli::try_parse_from([
            "catmos",
            "convo",
            "fulfill-leave",
            "conversation",
            "--profile",
            "device-b",
            "--no-startup-sync",
        ])
        .unwrap();
        assert_eq!(cli.profile.as_deref(), Some("device-b"));
        assert!(cli.no_startup_sync);
        assert!(matches!(
            cli.command,
            Some(Commands::Convo(ConvoCommands::FulfillLeave { .. }))
        ));
    }

    #[test]
    fn explicit_recovery_alias_targets_the_same_command() {
        let cli =
            Cli::try_parse_from(["catmos", "convo", "fulfill-recovery", "conversation"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Convo(ConvoCommands::Fulfill { .. }))
        ));
    }

    #[test]
    fn scoped_terminal_reconciliation_keeps_exact_conversation_id() {
        let id = "11111111-1111-4111-8111-111111111111";
        let cli = Cli::try_parse_from([
            "catmos",
            "--profile",
            "device-a2",
            "--no-startup-sync",
            "convo",
            "reconcile-access",
            id,
        ])
        .unwrap();
        assert!(cli.no_startup_sync);
        assert!(
            matches!(cli.command, Some(Commands::Convo(ConvoCommands::ReconcileAccess { convo_id })) if convo_id == id)
        );
    }
}
