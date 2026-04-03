use clap::Parser;

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
        Some(_cmd) => {
            println!("Command not yet implemented");
        }
    }

    Ok(())
}
