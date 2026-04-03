use std::sync::Arc;

use clap::Parser;
use tokio::sync::RwLock;
use tracing::info;

use catmos_core::auth::app_password::AppPasswordAuth;
use catmos_core::auth::oauth::OAuthAuth;
use catmos_core::auth::AuthMethod;
use catmos_core::chat::ChatService;
use catmos_core::mls::MlsManager;
use catmos_core::storage::aliases::AliasStore;
use catmos_core::storage::config::Config;
use catmos_core::storage::db::Database;
use catmos_core::types::MessageContent;

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
    Members { convo: String },
    /// Print recent messages
    Messages { convo: String },
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
    #[command(subcommand)]
    Debug(DebugCommands),
    #[command(subcommand)]
    Blob(BlobCommands),
    #[command(subcommand)]
    Alias(AliasCommands),
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
async fn init_service() -> anyhow::Result<ChatService> {
    let config = Config::load()?;

    let did = config
        .default_account
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No account configured. Run `catmos login` first."))?;

    let account_dir = Config::account_data_dir(did)?;
    let db_path = account_dir.join("catmos.db");

    let db_key = catmos_core::mls::context::get_or_create_db_key(did)?;
    let db = Database::open(&db_path, &db_key)?;

    // Try to restore auth: OAuth first, then AppPassword
    let auth = if let Some(oauth) = OAuthAuth::load(&db)? {
        info!("Restored OAuth session for {did}");
        AuthMethod::OAuth {
            session_cookie: oauth.session_cookie,
            nest_url: oauth.nest_url,
        }
    } else if let Some(ap) = AppPasswordAuth::load(&db)? {
        info!("Restored app password session for {}", ap.handle);
        AuthMethod::AppPassword {
            handle: ap.handle,
            did: ap.did,
            access_jwt: ap.access_jwt,
            refresh_jwt: ap.refresh_jwt,
            pds_url: ap.pds_url,
        }
    } else {
        anyhow::bail!("No saved session found. Run `catmos login` first.");
    };

    let mls_dir = Config::data_dir()?.join("mls");
    let mls = Arc::new(MlsManager::new(&mls_dir, did)?);

    let aliases = Arc::new(RwLock::new(AliasStore::load()?));

    let service = ChatService::new(auth, mls, Arc::new(db), config, aliases);
    Ok(service)
}

/// Open (or create) a per-account database for a login flow where we don't yet
/// have a ChatService. Returns the Database so auth can be saved.
fn open_account_db(did: &str) -> anyhow::Result<Database> {
    let account_dir = Config::account_data_dir(did)?;
    let db_path = account_dir.join("catmos.db");
    let db_key = catmos_core::mls::context::get_or_create_db_key(did)?;
    let db = Database::open(&db_path, &db_key)?;
    Ok(db)
}

// ── Command dispatch ────────────────────────────────────────────────────────

async fn handle_command(cmd: Commands) -> anyhow::Result<()> {
    match cmd {
        // ── Auth ─────────────────────────────────────────────────────────
        Commands::Login { handle, app_password } => {
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
                let password = rpassword::read_password()?;

                let session = AppPasswordAuth::login(&handle, &password).await?;
                println!("Logged in as {} ({})", session.handle, session.did);

                let db = open_account_db(&session.did)?;
                session.save(&db)?;

                let mut config = Config::load()?;
                config.default_account = Some(session.did);
                config.save()?;
            } else {
                let config = Config::load()?;
                let nest_url = &config.server.nest_url;

                println!("Starting OAuth flow for {handle}...");
                let session = OAuthAuth::login(&handle, nest_url).await?;
                println!("Logged in as {}", session.did);

                let db = open_account_db(&session.did)?;
                session.save(&db)?;

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
            let messages = svc.fetch_messages(&convo_id, 50).await?;

            if messages.is_empty() {
                println!("No messages.");
                return Ok(());
            }

            for m in &messages {
                let sender = m.sender_did.as_deref().unwrap_or("unknown");
                let ts = m.created_at.format("%H:%M");
                let body = match &m.content {
                    MessageContent::Text(t) => t.clone(),
                    MessageContent::Reaction { emoji, .. } => format!("[reaction: {emoji}]"),
                    MessageContent::System(t) => format!("[system] {t}"),
                    MessageContent::Unknown => "[unknown]".to_string(),
                };
                println!("[{ts}] {sender}: {body}");
            }
        }

        Commands::Send { convo, message } => {
            let svc = init_service().await?;
            svc.fetch_conversations().await?;
            let convo_id = svc.resolve_convo(&convo).await?;
            let msg = svc.send_message(&convo_id, &message).await?;
            println!("Sent (seq={}, epoch={})", msg.seq, msg.epoch);
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
                println!("  {} ({device}){role}", m.user_did);
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
                let convo = svc
                    .create_conversation(&name, &member_list, description.as_deref())
                    .await?;
                println!("Created conversation: {}", convo.group_id);
            }

            ConvoCommands::Leave { convo } => {
                let svc = init_service().await?;
                svc.fetch_conversations().await?;
                let convo_id = svc.resolve_convo(&convo).await?;
                svc.leave_conversation(&convo_id).await?;
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

            _ => {
                println!("Not yet implemented");
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
            _ => {
                println!("Not yet implemented");
            }
        },

        // ── Key packages ─────────────────────────────────────────────────
        Commands::KeyPackage(sub) => match sub {
            KeyPackageCommands::Status => {
                let svc = init_service().await?;
                let status = svc.get_key_package_status().await?;
                println!(
                    "Key packages: {}/{} (replenish={})",
                    status.available, status.target, status.needs_replenish
                );
            }
            _ => {
                println!("Not yet implemented");
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

        // ── Not yet implemented ──────────────────────────────────────────
        Commands::React { .. }
        | Commands::Unreact { .. }
        | Commands::Debug(_)
        | Commands::Blob(_) => {
            println!("Not yet implemented");
        }

        Commands::Chat => {
            unreachable!("handled in main");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        None | Some(Commands::Chat) => {
            println!("TUI not yet implemented");
        }
        Some(cmd) => {
            handle_command(cmd).await?;
        }
    }

    Ok(())
}
