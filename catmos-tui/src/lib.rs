pub mod app;
pub mod event;
pub mod keybinds;
pub mod widgets;

use std::io;
use std::sync::Arc;

use crossterm::event::KeyEventKind;
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::RwLock;
use tracing::{error, info};

use catmos_core::auth::app_password::AppPasswordAuth;
use catmos_core::auth::AuthMethod;
use catmos_core::chat::service::ChatService;
use catmos_core::mls::context::MlsManager;
use catmos_core::storage::aliases::AliasStore;
use catmos_core::storage::config::Config;
use catmos_core::storage::db::Database;

use app::{App, Screen};
use event::{AppEvent, EventLoop};
use keybinds::{map_key, Action};

/// Run the interactive TUI.
pub async fn run() -> anyhow::Result<()> {
    // ── 1. Load config ─────────────────────────────────────────────────
    let config = Config::load()?;

    // ── 2. Open DB and load auth ───────────────────────────────────────
    let data_dir = Config::data_dir()?;
    let db_path = data_dir.join("catmos.db");

    // Use unencrypted DB for session store (auth credentials)
    let db = Arc::new(Database::open_unencrypted(&db_path).await?);

    let auth_info = AppPasswordAuth::load(&db).await?
        .ok_or_else(|| anyhow::anyhow!("Not authenticated. Run `catmos login` first."))?;

    let did = auth_info.did.clone();

    let auth = AuthMethod::AppPassword {
        handle: auth_info.handle,
        did: auth_info.did,
        access_jwt: auth_info.access_jwt,
        refresh_jwt: auth_info.refresh_jwt,
        pds_url: auth_info.pds_url,
    };

    // ── 3. Initialize MLS ──────────────────────────────────────────────
    let mls_dir = data_dir.join("mls");
    let mls = Arc::new(MlsManager::new(&mls_dir, &did)?);

    // ── 4. Create ChatService ──────────────────────────────────────────
    let aliases = Arc::new(RwLock::new(AliasStore::load()?));
    let service = Arc::new(ChatService::new(
        auth,
        mls,
        db,
        config.clone(),
        aliases,
    ));

    // ── 5. Initial sync ────────────────────────────────────────────────
    let mut app = App::new(
        Arc::clone(&service),
        config.ui.sidebar_visible,
        config.ui.member_panel_visible,
    );

    info!("Fetching conversations...");
    match service.fetch_conversations().await {
        Ok(convos) => {
            app.conversations = convos;
            // Load messages for the first conversation
            if let Some(convo) = app.active_conversation() {
                let group_id = convo.group_id.clone();
                match service.fetch_messages(&group_id, 50).await {
                    Ok(msgs) => app.messages = msgs,
                    Err(e) => error!("Failed to fetch messages: {e}"),
                }
            }
        }
        Err(e) => {
            error!("Failed to fetch conversations: {e}");
            // Continue with empty state — user can retry
        }
    }

    // ── 6. Set up terminal ─────────────────────────────────────────────
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // ── 7. Event loop ──────────────────────────────────────────────────
    let (mut events, event_tx) = EventLoop::new(250);

    // ── 7a. Start WebSocket subscription ──────────────────────────────
    // Call subscribe() on the current task, then hand only the receiver
    // to the spawned task.
    match service.subscribe().await {
        Ok(mut ws_rx) => {
            let ws_tx = event_tx.clone();
            tokio::spawn(async move {
                info!("WebSocket subscription active");
                while let Some(ws_event) = ws_rx.recv().await {
                    match ws_event {
                        catmos_core::chat::WsEvent::Message {
                            convo_id,
                            plaintext,
                            sender_did,
                            message_id,
                            epoch,
                            seq,
                        } => {
                            let content = parse_ws_plaintext(&plaintext);
                            let msg = catmos_core::types::Message {
                                id: message_id,
                                convo_id,
                                sender_did,
                                content,
                                epoch,
                                seq,
                                created_at: chrono::Utc::now(),
                            };
                            if ws_tx.send(AppEvent::ChatMessage(msg)).is_err() {
                                break;
                            }
                        }
                        catmos_core::chat::WsEvent::Error(e) => {
                            error!("WebSocket error: {e}");
                            let _ = ws_tx.send(AppEvent::Error(e));
                        }
                        catmos_core::chat::WsEvent::Reconnecting => {
                            info!("WebSocket reconnecting...");
                        }
                        _ => {
                            // Typing, MemberJoined, MemberLeft, EpochAdvanced,
                            // Reaction — future enhancements
                        }
                    }
                }
            });
        }
        Err(e) => {
            error!("Failed to start WebSocket subscription: {e}");
            // Non-fatal: TUI still works without live updates
        }
    }

    let result = main_loop(&mut terminal, &mut app, &mut events).await;

    // ── 8. Restore terminal ────────────────────────────────────────────
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// The main draw-handle loop.
async fn main_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    events: &mut EventLoop,
) -> anyhow::Result<()> {
    loop {
        // Draw
        terminal.draw(|frame| {
            widgets::render(frame, app);
        })?;

        // Handle events
        if let Some(event) = events.next().await {
            match event {
                AppEvent::Key(key) => {
                    // Only handle key press events (not release/repeat)
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    match app.screen {
                        Screen::Chat => handle_chat_key(app, key).await,
                        Screen::CommandPalette => {
                            // Command palette is a future enhancement
                            if map_key(key) == Action::Cancel {
                                app.screen = Screen::Chat;
                            }
                        }
                        Screen::NewConvo => {
                            // New convo screen is a future enhancement
                            if map_key(key) == Action::Cancel {
                                app.screen = Screen::Chat;
                            }
                        }
                    }
                }
                AppEvent::Tick => {
                    // Nothing to do on tick for now (future: refresh, animate)
                }
                AppEvent::ChatMessage(msg) => {
                    // If message belongs to the active conversation, append it
                    if let Some(convo) = app.active_conversation() {
                        if msg.convo_id == convo.group_id {
                            app.messages.push(msg);
                        }
                    }
                }
                AppEvent::ConvoListUpdated(convos) => {
                    app.conversations = convos;
                }
                AppEvent::Error(e) => {
                    error!("Event error: {e}");
                }
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

/// Handle a key event in the Chat screen.
async fn handle_chat_key(app: &mut App, key: crossterm::event::KeyEvent) {
    let action = map_key(key);

    match action {
        Action::Quit => app.should_quit = true,
        Action::ToggleSidebar => app.sidebar_visible = !app.sidebar_visible,
        Action::ToggleMembers => app.member_panel_visible = !app.member_panel_visible,
        Action::NewConvo => app.screen = Screen::NewConvo,
        Action::JoinConvo => {
            // Future: open join dialog
        }
        Action::CommandPalette => app.screen = Screen::CommandPalette,
        Action::NextConvo => {
            app.next_conversation();
            reload_messages(app).await;
        }
        Action::PrevConvo => {
            app.prev_conversation();
            reload_messages(app).await;
        }
        Action::SendMessage => {
            let text = app.take_input();
            if !text.is_empty() {
                if let Some(convo) = app.active_conversation() {
                    let convo_id = convo.group_id.clone();
                    match app.service.send_message(&convo_id, &text).await {
                        Ok(msg) => {
                            app.messages.push(msg);
                            app.scroll_offset = 0;
                        }
                        Err(e) => {
                            error!("Failed to send message: {e}");
                        }
                    }
                }
            }
        }
        Action::ScrollUp => {
            let max = app.messages.len().saturating_sub(1);
            app.scroll_offset = (app.scroll_offset + 5).min(max);
        }
        Action::ScrollDown => {
            app.scroll_offset = app.scroll_offset.saturating_sub(5);
        }
        Action::Cancel => {
            // Clear input or reset scroll
            if !app.input.is_empty() {
                app.input.clear();
                app.cursor_pos = 0;
            } else {
                app.scroll_offset = 0;
            }
        }
        Action::TypeChar(c) => app.insert_char(c),
        Action::Backspace => app.delete_char_before(),
        Action::Delete => app.delete_char_at(),
        Action::CursorLeft => app.cursor_left(),
        Action::CursorRight => app.cursor_right(),
        Action::CursorHome => app.cursor_pos = 0,
        Action::CursorEnd => app.cursor_pos = app.input.len(),
        Action::None => {}
    }
}

/// Reload messages for the currently active conversation.
async fn reload_messages(app: &mut App) {
    if let Some(convo) = app.active_conversation() {
        let group_id = convo.group_id.clone();
        match app.service.fetch_messages(&group_id, 50).await {
            Ok(msgs) => app.messages = msgs,
            Err(e) => error!("Failed to fetch messages: {e}"),
        }
    }
}

/// Parse a WebSocket plaintext JSON payload into a `MessageContent`.
fn parse_ws_plaintext(plaintext: &str) -> catmos_core::types::MessageContent {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(plaintext) {
        match v.get("type").and_then(|t| t.as_str()) {
            Some("text") => {
                let text = v
                    .get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                catmos_core::types::MessageContent::Text(text)
            }
            Some("reaction") => {
                let target = v
                    .get("targetMessageId")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                let emoji = v
                    .get("emoji")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                let action = match v.get("action").and_then(|a| a.as_str()) {
                    Some("remove") => catmos_core::types::ReactionAction::Remove,
                    _ => catmos_core::types::ReactionAction::Add,
                };
                catmos_core::types::MessageContent::Reaction {
                    target_message_id: target,
                    emoji,
                    action,
                }
            }
            Some("system") => {
                let text = v
                    .get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                catmos_core::types::MessageContent::System(text)
            }
            _ => catmos_core::types::MessageContent::Unknown,
        }
    } else {
        catmos_core::types::MessageContent::Text(plaintext.to_string())
    }
}
