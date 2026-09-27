use catmos_core::chat::{requests::RequestDraftCancellation, ChatService};
use clap::Subcommand;
use serde_json::json;
use std::sync::Arc;

#[derive(Subcommand)]
pub enum RequestCommands {
    /// Persist a protected draft locally without attempting publication.
    Draft {
        recipient: String,
        #[arg(long, default_value = "-")]
        file: String,
        #[arg(long)]
        draft_id: Option<String>,
        #[arg(long)]
        invitation: Option<String>,
    },
    /// Persist a protected draft, then send one introduction. Text is never a process argument.
    Send {
        recipient: String,
        #[arg(long, default_value = "-")]
        file: String,
        #[arg(long)]
        draft_id: Option<String>,
        #[arg(long)]
        invitation: Option<String>,
    },
    /// Send an existing invitation-note draft into an accepted direct. Ambiguous attempts require inspection.
    Note {
        draft_id: String,
        conversation: String,
    },
    /// List verified request states; previews are omitted.
    List {
        #[arg(long)]
        offline: bool,
    },
    /// Explicitly display a decrypted protected preview.
    Show {
        conversation: String,
    },
    Accept {
        conversation: String,
    },
    Decline {
        conversation: String,
    },
    /// Resume exactly the same protected draft.
    Resume {
        draft_id: String,
    },
    Cancel {
        draft_id: String,
    },
    /// Report draft/outcome metadata without printing its text.
    Status {
        draft_id: String,
    },
    /// Read or explicitly change this device's request delivery preference.
    Delivery {
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
    },
}
fn summary(v: &catmos_core::chat::requests::RequestView) -> serde_json::Value {
    json!({"conversationId":v.conversation_id,"firstMessageId":v.first_message_id,"consent":v.consent,"crypto":v.crypto,"capabilities":v.capabilities,"generation":v.generation,"stateVersion":v.state_version})
}
pub async fn run(service: Arc<ChatService>, command: RequestCommands) -> anyhow::Result<()> {
    let value = match command {
        RequestCommands::Draft {
            recipient,
            file,
            draft_id,
            invitation,
        } => {
            let id = save_draft(&service, recipient, file, draft_id, invitation).await?;
            json!({"draftId":id,"status":"localDraftSaved"})
        }
        RequestCommands::Send {
            recipient,
            file,
            draft_id,
            invitation,
        } => {
            let id = save_draft(&service, recipient, file, draft_id, invitation).await?;
            send(&service, &id).await
        }
        RequestCommands::Resume { draft_id } => send(&service, &draft_id).await,
        RequestCommands::Note {
            draft_id,
            conversation,
        } => {
            json!({"draftId":draft_id,"messageId":service.send_accepted_invitation_note(&draft_id,&conversation).await?})
        }
        RequestCommands::List { offline } => {
            json!({"requests":service.request_views(!offline).await?.iter().map(summary).collect::<Vec<_>>(),"drafts":service.db.list_request_drafts(service.did()).await?.iter().map(|d|json!({"draftId":d.input.draft_id,"recipientDid":d.input.recipient_did,"attempted":d.attempted,"outcome":d.outcome})).collect::<Vec<_>>() })
        }
        RequestCommands::Show { conversation } => {
            serde_json::to_value(service.request_view(&conversation).await?)?
        }
        RequestCommands::Accept { conversation } => {
            summary(&service.accept_request(&conversation).await?)
        }
        RequestCommands::Decline { conversation } => {
            summary(&service.close_request(&conversation).await?)
        }
        RequestCommands::Cancel { draft_id } => {
            match service.cancel_request_draft(&draft_id).await? {
                RequestDraftCancellation::LocalDraftDeleted { draft_id } => {
                    json!({"draftId":draft_id,"status":"localDraftCancelled"})
                }
                RequestDraftCancellation::Native(outcome) => {
                    json!({"draftId":draft_id,"outcome":outcome})
                }
            }
        }
        RequestCommands::Status { draft_id } => {
            let (draft, _) = service
                .db
                .read_request_draft(service.did(), &draft_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Unknown local draft"))?;
            json!({"draftId":draft_id,"recipientDid":draft.input.recipient_did,"attempted":draft.attempted,"outcome":draft.outcome,"noteStarted":draft.note_started,"noteMessageId":draft.note_message_id})
        }
        RequestCommands::Delivery { enable, disable } => {
            let authority = service.request_authority().await?;
            if enable || disable {
                authority
                    .set_direct_request_delivery_enabled(enable)
                    .await?;
            }
            json!({"enabled":authority.get_direct_request_delivery_enabled().await?})
        }
    };
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}
async fn send(service: &ChatService, id: &str) -> serde_json::Value {
    match service.send_request_draft(id).await {
        Ok(outcome) => json!({"draftId":id,"outcome":outcome}),
        Err(error) => json!({"draftId":id,"status":"unconfirmed","error":error.to_string()}),
    }
}
async fn save_draft(
    service: &ChatService,
    recipient: String,
    file: String,
    draft_id: Option<String>,
    invitation: Option<String>,
) -> anyhow::Result<String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    if file == "-" {
        std::io::stdin().take(16385).read_to_end(&mut bytes)?;
    } else {
        std::fs::File::open(file)?
            .take(16385)
            .read_to_end(&mut bytes)?;
    }
    let text = String::from_utf8(bytes)?;
    let id = draft_id.unwrap_or_else(|| catmos_core::chat::requests::new_draft_id());
    let reference = match invitation {
        Some(cid) => Some(service.invitation_note_reference(&cid, &recipient).await?),
        None => None,
    };
    service
        .save_request_draft(catmos_core::chat::requests::RequestInput {
            draft_id: id.clone(),
            recipient_did: recipient,
            text,
            invitation: reference,
        })
        .await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[test]
    fn ordinary_reply_accepts_stdin_without_plaintext_arguments() {
        assert!(
            crate::Cli::try_parse_from(["catmos", "send", "conversation", "--file", "-"]).is_ok()
        );
        assert!(
            crate::Cli::try_parse_from(["catmos", "send", "conversation", "legacy text"]).is_ok()
        );
        assert!(crate::Cli::try_parse_from(["catmos", "send", "conversation"]).is_err());
        assert!(crate::Cli::try_parse_from([
            "catmos",
            "send",
            "conversation",
            "text",
            "--file",
            "-"
        ])
        .is_err());
    }
    #[test]
    fn request_cli_requires_explicit_content_source_and_never_positional_plaintext() {
        assert!(crate::Cli::try_parse_from([
            "catmos",
            "request",
            "send",
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            "--file",
            "-"
        ])
        .is_ok());
        assert!(crate::Cli::try_parse_from([
            "catmos",
            "request",
            "send",
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            "private text"
        ])
        .is_err());
        assert!(crate::Cli::try_parse_from([
            "catmos",
            "request",
            "delivery",
            "--enable",
            "--disable"
        ])
        .is_err());
        assert!(crate::Cli::try_parse_from(["catmos", "request", "list", "--offline"]).is_ok());
    }
}
