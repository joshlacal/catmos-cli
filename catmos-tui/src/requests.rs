use crate::app::{App, Screen};
use catmos_core::chat::requests::{RequestConsent, RequestInput, RequestPreview};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
pub async fn open(app: &mut App) -> anyhow::Result<()> {
    app.screen = Screen::Requests;
    app.request_scroll = 0;
    app.requests = app.service.request_views(false).await?;
    app.request_delivery = app
        .service
        .request_authority()
        .await?
        .get_direct_request_delivery_enabled()
        .await?;
    // Retain every durable outcome, including ambiguous attempts and existing-direct
    // note drafts. Selecting a row never retries it automatically.
    app.request_drafts = app
        .service
        .db
        .list_request_drafts(app.service.did())
        .await?;
    app.selected_draft = app
        .selected_draft
        .min(app.request_drafts.len().saturating_sub(1));
    app.selected_request = app
        .selected_request
        .min(app.requests.len().saturating_sub(1));
    Ok(())
}
pub async fn handle(app: &mut App, key: KeyEvent) -> anyhow::Result<()> {
    handle_viewport_key(key.code, app.screen, &mut app.request_scroll);
    if key.code == KeyCode::Esc {
        app.screen = Screen::Chat;
        return Ok(());
    }
    match app.screen {
        Screen::Requests => match key.code {
            KeyCode::Down | KeyCode::Tab => {
                if !app.requests.is_empty() {
                    app.selected_request = (app.selected_request + 1) % app.requests.len();
                }
            }
            KeyCode::Up => app.selected_request = app.selected_request.saturating_sub(1),
            KeyCode::Char('r') => {
                app.requests = app.service.request_views(true).await?;
                app.selected_request = app
                    .selected_request
                    .min(app.requests.len().saturating_sub(1));
            }
            KeyCode::Char('a') | KeyCode::Char('d') => {
                if let Some(view) = app.requests.get(app.selected_request).cloned() {
                    if key.code == KeyCode::Char('a') {
                        app.service.accept_request(&view.conversation_id).await?;
                    } else {
                        app.service.close_request(&view.conversation_id).await?;
                    }
                    open(app).await?;
                }
            }
            KeyCode::Char('e') => {
                app.service
                    .request_authority()
                    .await?
                    .set_direct_request_delivery_enabled(true)
                    .await?;
                open(app).await?;
            }
            KeyCode::Char('x') => {
                app.service
                    .request_authority()
                    .await?
                    .set_direct_request_delivery_enabled(false)
                    .await?;
                open(app).await?;
            }
            KeyCode::Char('n') => {
                app.input.clear();
                app.cursor_pos = 0;
                app.screen = Screen::RequestRecipient;
            }
            KeyCode::Char(']') => {
                if !app.request_drafts.is_empty() {
                    app.selected_draft = (app.selected_draft + 1) % app.request_drafts.len();
                }
            }
            KeyCode::Char('[') => app.selected_draft = app.selected_draft.saturating_sub(1),
            KeyCode::Char('u') => {
                app.request_draft = app.request_drafts.get(app.selected_draft).cloned();
                if let Some(d) = &app.request_draft {
                    app.input = d.input.text.clone();
                    app.cursor_pos = app.input.len();
                    app.screen = Screen::RequestCompose;
                }
            }
            _ => {}
        },
        Screen::RequestRecipient | Screen::RequestCompose => match key.code {
            KeyCode::Enter => {
                if app.screen == Screen::RequestRecipient {
                    let recipient = app.input.trim().to_owned();
                    if !recipient.starts_with("did:") {
                        anyhow::bail!("Enter a recipient DID");
                    }
                    let draft = app
                        .service
                        .save_request_draft(RequestInput {
                            draft_id: catmos_core::chat::requests::new_draft_id(),
                            recipient_did: recipient,
                            text: String::new(),
                            invitation: None,
                        })
                        .await?;
                    app.request_draft = Some(draft);
                    app.input.clear();
                    app.cursor_pos = 0;
                    app.screen = Screen::RequestCompose;
                } else {
                    let draft = app
                        .request_draft
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("No draft"))?
                        .clone();
                    if !draft.attempted {
                        app.service
                            .edit_request_draft(&draft.input.draft_id, app.input.clone())
                            .await?;
                    }
                    let result = app.service.send_request_draft(&draft.input.draft_id).await;
                    app.request_draft = app
                        .service
                        .db
                        .read_request_draft(app.service.did(), &draft.input.draft_id)
                        .await?
                        .map(|p| p.0);
                    app.set_status(match result {
                        Ok(outcome) => format!("{outcome:?}"),
                        Err(error) => format!("Unconfirmed; draft retained: {error}"),
                    });
                    open(app).await?;
                }
            }
            KeyCode::Char(c) => {
                if !app
                    .request_draft
                    .as_ref()
                    .is_some_and(|d| app.screen == Screen::RequestCompose && d.attempted)
                {
                    app.insert_char(c);
                }
            }
            KeyCode::Backspace => {
                if !app
                    .request_draft
                    .as_ref()
                    .is_some_and(|d| app.screen == Screen::RequestCompose && d.attempted)
                {
                    app.delete_char_before();
                }
            }
            _ => {}
        },
        _ => {}
    }
    if app.screen == Screen::RequestCompose {
        if let Some(d) = &app.request_draft {
            if !d.attempted {
                app.service
                    .edit_request_draft(&d.input.draft_id, app.input.clone())
                    .await?;
            }
        }
    }
    Ok(())
}
fn handle_viewport_key(key: KeyCode, screen: Screen, offset: &mut u16) {
    if screen != Screen::Requests {
        *offset = 0;
        return;
    }
    match key {
        KeyCode::PageDown => *offset = offset.saturating_add(10),
        KeyCode::PageUp => *offset = offset.saturating_sub(10),
        KeyCode::Home
        | KeyCode::Esc
        | KeyCode::Up
        | KeyCode::Down
        | KeyCode::Tab
        | KeyCode::Char('n' | 'u' | '[' | ']') => *offset = 0,
        _ => {}
    }
}
pub fn render(frame: &mut Frame, app: &App) {
    let mut text=match app.screen {
        Screen::RequestRecipient=>format!("New request — recipient DID\nSelecting a recipient saves only a local draft.\n\n{}\n\nEnter: compose   Esc: chat",app.input),
        Screen::RequestCompose=>format!("One encrypted introduction\nRecipient: {}\n\n{}\n\nEnter: send / exact retry   Esc: chat\nDraft is saved on this device.",app.request_draft.as_ref().map(|d|d.input.recipient_did.as_str()).unwrap_or(""),app.input),
        _=>{
            let delivery=match app.request_delivery {Some(true)=>"Enabled",Some(false)=>"Disabled",None=>"Unconfirmed"};
            let mut out=format!("Requests    Delivery: {}\na accept · d decline · r refresh · n new draft · [/] select draft · u resume draft\ne enable delivery · x disable delivery · Tab select · PgUp/PgDn scroll · Esc chat\n\n",delivery);
            for (i,view) in app.requests.iter().enumerate(){out.push_str(&format!("{} {}  {:?} / {:?}\n",if i==app.selected_request {">"}else{" "},view.conversation_id,view.consent,view.crypto));}
            out.push_str("\nDurable drafts (select, then explicitly resume):\n");
            for (i,draft) in app.request_drafts.iter().enumerate() { out.push_str(&format!("{} {} → {}: {:?}\n", if i==app.selected_draft {">"}else{" "}, draft.input.draft_id, draft.input.recipient_did, draft.outcome)); }
            if let Some(view)=app.requests.get(app.selected_request){
                out.push_str(&preview_text(view.preview.as_ref(),view.consent));
            }
            out
        }
    };
    text.push_str(&format!("\n\n{}", app.status));
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((
                if app.screen == Screen::Requests {
                    app.request_scroll
                } else {
                    0
                },
                0,
            ))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Encrypted requests"),
            ),
        frame.area(),
    );
}

fn preview_text(preview: Option<&RequestPreview>, consent: RequestConsent) -> String {
    let mut out = String::from("\nProtected preview:\n");
    match preview {
        Some(RequestPreview::Ready { text, invitation }) => {
            out.extend(text.chars().map(|c| {
                if c.is_control() && c != '\n' && c != '\t' {
                    '�'
                } else {
                    c
                }
            }));
            if let Some(link) = invitation {
                out.push_str(&format!(
                    "\nGroup invitation: {} (accept separately)",
                    link.conversation_id
                ));
            }
        }
        Some(RequestPreview::Unavailable { code }) => out.push_str(&format!("Unavailable: {code}")),
        None => out.push_str("Not yet available"),
    }
    if consent != RequestConsent::Accepted {
        out.push_str("\nReplies, media and receipts remain disabled.");
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn navigation_resets_preview_scroll_before_recipient_or_draft_screen() {
        for key in [
            KeyCode::Char('n'),
            KeyCode::Char('u'),
            KeyCode::Down,
            KeyCode::Tab,
        ] {
            let mut offset = 0;
            for _ in 0..40 {
                handle_viewport_key(KeyCode::PageDown, Screen::Requests, &mut offset);
            }
            assert_eq!(offset, 400);
            handle_viewport_key(key, Screen::Requests, &mut offset);
            assert_eq!(offset, 0);
        }
        let mut offset = 400;
        handle_viewport_key(KeyCode::PageDown, Screen::RequestCompose, &mut offset);
        assert_eq!(offset, 0);
    }

    #[test]
    fn maximum_introduction_can_scroll_to_its_tail() {
        let preview = RequestPreview::Ready {
            text: format!("{}TAIL", "line\n".repeat(3276)),
            invitation: None,
        };
        let text = preview_text(Some(&preview), RequestConsent::IncomingPending);
        assert!(text.len() > 16384);
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 12)).unwrap();
        terminal
            .draw(|frame| {
                frame.render_widget(
                    Paragraph::new(text)
                        .wrap(Wrap { trim: false })
                        .scroll((3270, 0)),
                    frame.area(),
                )
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let rendered = (0..12)
            .map(|y| {
                (0..100)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("TAIL"));
        assert!(rendered.contains("Replies, media"));
    }

    #[test]
    fn protected_preview_renders_literal_text_and_keeps_pending_effects_disabled() {
        let preview = RequestPreview::Ready {
            text: "Hello <script> https://example.invalid\u{1b}[2J".into(),
            invitation: Some(catmos_core::chat::requests::InvitationReference {
                authority_did: "did:web:chat.catbird.blue".into(),
                conversation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                invitation_transition_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
                invited_by_did: "did:plc:alice".into(),
                invited_by_device_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
                recipient_did: "did:plc:bob".into(),
            }),
        };
        let text = preview_text(Some(&preview), RequestConsent::IncomingPending);
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("<script>"));
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 12)).unwrap();
        terminal
            .draw(|frame| {
                frame.render_widget(
                    Paragraph::new(text.clone()).wrap(Wrap { trim: false }),
                    frame.area(),
                )
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let rendered = (0..12)
            .map(|y| {
                (0..100)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("accept separately"));
        assert!(rendered.contains("Replies, media and receipts remain disabled"));
        if let Ok(path) = std::env::var("CATMOS_TUI_RENDER_EVIDENCE") {
            std::fs::write(path, rendered).unwrap();
        }
    }
}
