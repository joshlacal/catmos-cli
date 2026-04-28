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
use tracing::{debug, error, info, warn};

use catmos_core::auth::app_password::AppPasswordAuth;
use catmos_core::auth::oauth::OAuthAuth;
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

    let did = config
        .default_account
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No account configured. Run `catmos login` first."))?
        .to_string();

    // ── 2. Open DB and load auth ───────────────────────────────────────
    let account_dir = Config::account_data_dir(&did)?;
    let db_path = account_dir.join("catmos.db");
    let db_key = catmos_core::mls::context::get_or_create_db_key(&did)?;
    let db = Arc::new(Database::open(&db_path, &db_key).await?);

    // Try OAuth first, then AppPassword
    let (auth, token_session) = if let Some(oauth) = OAuthAuth::load(&db).await? {
        info!("Restored OAuth session for {did}");
        (
            AuthMethod::OAuth {
                session_cookie: oauth.session_cookie,
                did: oauth.did.clone(),
                nest_url: oauth.nest_url,
            },
            None,
        )
    } else if let Some(ap) = AppPasswordAuth::load(&db).await? {
        info!("Restored app password session for {}", ap.handle);
        (
            AuthMethod::AppPassword {
                handle: ap.handle,
                did: ap.did,
                pds_url: ap.pds_url,
            },
            Some(ap.session),
        )
    } else {
        anyhow::bail!("No saved session found. Run `catmos login` first.");
    };

    // ── 3. Initialize MLS ──────────────────────────────────────────────
    let mls_dir = Config::data_dir()?.join("mls");
    let mls = Arc::new(MlsManager::new(&mls_dir, &did)?);

    // ── 4. Create ChatService ──────────────────────────────────────────
    let aliases = Arc::new(RwLock::new(AliasStore::load()?));
    let service = Arc::new(ChatService::new(
        auth,
        token_session,
        mls.clone(),
        db.clone(),
        config.clone(),
        aliases,
    ));

    // ── 4a. MLS device registration + join missing conversations ──────
    // Timeout the entire registration/join phase so a slow server can't block startup
    let reg_result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let device_info = mls.ensure_registered(&service, &did, &db).await?;
        info!("MLS device ready: {}", device_info.device_id);
        // Fetch conversations first so join_missing knows what groups exist
        service.fetch_conversations().await?;
        info!("Joining missing conversations (10s timeout)...");
        let did_clone = did.clone();
        let svc = Arc::clone(&service);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            svc.join_missing_conversations(&did_clone),
        )
        .await;
        Ok::<_, catmos_core::error::CatmosError>(())
    })
    .await;
    match reg_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("MLS setup failed: {e}"),
        Err(_) => info!("MLS setup timed out — will continue with background sync"),
    }

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
            // Populate handle cache from service for sender display
            app.handle_cache = service.handle_cache().await;

            // Load cached messages for the active conversation immediately
            if let Some(convo) = app.active_conversation() {
                let convo_id = convo.conversation_id.clone();
                if let Ok(cached) = service.load_local_messages(&convo_id, 50).await {
                    if !cached.is_empty() {
                        app.messages = cached;
                    }
                }
            }

            // Pre-fetch messages for ALL conversations in background (populates SQLCipher cache).
            // Don't block startup — TUI renders immediately with cached messages.
            let group_ids: Vec<String> = app
                .conversations
                .iter()
                .map(|c| c.group_id.clone())
                .collect();
            for gid in group_ids {
                let svc = Arc::clone(&service);
                tokio::spawn(async move {
                    if let Err(e) = svc.fetch_messages(&gid, 50).await {
                        debug!("Pre-fetch failed for {}: {e}", &gid[..12.min(gid.len())]);
                    }
                });
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
                        catmos_core::chat::WsEvent::EpochAdvanced {
                            convo_id,
                            new_epoch,
                        } => {
                            info!(
                                "WS epoch advanced: convo={} epoch={new_epoch}",
                                &convo_id[..12.min(convo_id.len())]
                            );
                            if ws_tx
                                .send(AppEvent::EpochAdvanced {
                                    convo_id,
                                    new_epoch,
                                })
                                .is_err()
                            {
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
                        catmos_core::chat::WsEvent::TreeChanged {
                            convo_id,
                            confirmation_tag: _,
                            epoch,
                        } => {
                            // Forward to TUI for silent repair.
                            // The convert_event already compared tags and logged.
                            info!(
                                "WS treeChanged: convo={} epoch={epoch}",
                                &convo_id[..12.min(convo_id.len())]
                            );
                            let _ = ws_tx.send(AppEvent::TreeDiverged { convo_id });
                        }
                        catmos_core::chat::WsEvent::GroupReset {
                            convo_id,
                            new_group_id,
                            reset_generation,
                            ..
                        } => {
                            info!(
                                "WS group reset: convo={} new_group={} gen={reset_generation}",
                                &convo_id[..12.min(convo_id.len())],
                                &new_group_id[..12.min(new_group_id.len())]
                            );
                            if ws_tx
                                .send(AppEvent::GroupReset {
                                    convo_id,
                                    new_group_id,
                                    reset_generation,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        catmos_core::chat::WsEvent::ResetRequested {
                            convo_id,
                            crypto_session_id,
                            generation,
                            trigger,
                            request_event_id,
                            expected_new_mls_group_id,
                        } => {
                            info!(
                                phase_2_5_path = "request_only",
                                "WS reset requested: convo={} crypto_session={} gen={generation} trigger={trigger}",
                                &convo_id[..12.min(convo_id.len())],
                                &crypto_session_id[..12.min(crypto_session_id.len())]
                            );
                            if ws_tx
                                .send(AppEvent::ResetRequested {
                                    convo_id,
                                    crypto_session_id,
                                    generation,
                                    trigger,
                                    request_event_id,
                                    expected_new_mls_group_id,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        _ => {
                            // Typing, MemberJoined, MemberLeft,
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

    // ── 7b. Background sync loop — 5s interval (spec section 6.1) ────────
    // Includes a circuit breaker: after SYNC_CIRCUIT_BREAKER_THRESHOLD
    // consecutive failures, applies exponential cooldown before retrying.
    let _sync_handle = {
        let svc = Arc::clone(&service);
        let tx = event_tx.clone();
        tokio::spawn(async move {
            const SYNC_CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
            let mut consecutive_failures: u32 = 0;
            let mut circuit_open_until: Option<std::time::Instant> = None;

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                // Circuit breaker: skip sync while in cooldown
                if let Some(until) = circuit_open_until {
                    if std::time::Instant::now() < until {
                        continue;
                    }
                    // Cooldown elapsed — reset and try once
                    info!("Sync circuit breaker: cooldown elapsed, retrying");
                    circuit_open_until = None;
                    consecutive_failures = 0;
                }

                match svc.fetch_conversations().await {
                    Ok(convos) => {
                        consecutive_failures = 0;
                        circuit_open_until = None;
                        let _ = tx.send(AppEvent::ConvoListUpdated(convos));
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        debug!("Background sync error (consecutive: {consecutive_failures}): {e:?}");

                        if consecutive_failures >= SYNC_CIRCUIT_BREAKER_THRESHOLD {
                            // Exponential cooldown: min(30 * 2^(failures-1), 300) seconds
                            let exponent = consecutive_failures.saturating_sub(1);
                            let cooldown_secs = std::cmp::min(
                                30u64.saturating_mul(2u64.saturating_pow(exponent)),
                                300,
                            );
                            warn!(
                                "Sync circuit breaker: {consecutive_failures} consecutive failures, \
                                 cooling down for {cooldown_secs}s"
                            );
                            circuit_open_until = Some(
                                std::time::Instant::now()
                                    + std::time::Duration::from_secs(cooldown_secs),
                            );
                        }
                    }
                }
            }
        })
    };

    let result = main_loop(&mut terminal, &mut app, &mut events, event_tx).await;

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
    event_tx: tokio::sync::mpsc::UnboundedSender<AppEvent>,
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
                        Screen::Chat => handle_chat_key(app, key, &event_tx).await,
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
                    // Persist to SQLCipher so it survives conversation switches
                    if let Err(e) = app.service.db.store_message(&msg).await {
                        error!("Failed to store WS message {}: {e}", msg.id);
                    }
                    // Append to in-memory list if it belongs to the active conversation
                    if let Some(convo) = app.active_conversation() {
                        if msg.convo_id == convo.conversation_id {
                            app.messages.push(msg);
                        }
                    }
                }
                AppEvent::EpochAdvanced {
                    convo_id,
                    new_epoch,
                } => {
                    info!(
                        "Epoch advanced for {} to {new_epoch}",
                        &convo_id[..12.min(convo_id.len())]
                    );
                    // Non-blocking: messages arrive via WebSocket ChatMessage events
                }
                AppEvent::ConvoListUpdated(convos) => {
                    app.conversations = convos;
                }
                AppEvent::GroupReset {
                    convo_id,
                    new_group_id,
                    reset_generation,
                } => {
                    let label = &convo_id[..12.min(convo_id.len())];
                    info!(
                        "Group reset for {} to {} (gen {}) — persisting RESET_PENDING",
                        label,
                        &new_group_id[..12.min(new_group_id.len())],
                        reset_generation
                    );
                    // Spec §8.6: persist the RESET_PENDING payload so the
                    // next deferred-recovery cycle (Phase 1) adopts the new
                    // group id. We do NOT call External Commit inline here —
                    // that's the deferred-recovery loop's job, which already
                    // gates on RecoveryTracker / circuit breaker.
                    let svc = Arc::clone(&app.service);
                    let cid = convo_id.clone();
                    let new_gid = new_group_id.clone();
                    tokio::spawn(async move {
                        svc.handle_group_reset_event(&cid, &new_gid, reset_generation)
                            .await;
                    });
                }
                AppEvent::ResetRequested {
                    convo_id,
                    crypto_session_id,
                    generation,
                    trigger,
                    request_event_id,
                    expected_new_mls_group_id,
                } => {
                    let label = &convo_id[..12.min(convo_id.len())];
                    info!(
                        phase_2_5_path = "request_only",
                        "Reset requested for {} (gen {}, trigger {}) — persisting RESET_PENDING",
                        label,
                        generation,
                        trigger
                    );
                    // Phase 2.5 (plan §3, §5 Stage 2): persist RESET_PENDING so
                    // the existing deferred-recovery loop drives the
                    // first-responder bootstrap. We do NOT call External
                    // Commit inline — same invariant as `GroupReset`.
                    let svc = Arc::clone(&app.service);
                    let cid = convo_id.clone();
                    let csid = crypto_session_id.clone();
                    let trig = trigger.clone();
                    let req_id = request_event_id.clone();
                    let exp = expected_new_mls_group_id.clone();
                    tokio::spawn(async move {
                        svc.handle_reset_requested_event(
                            &cid,
                            &csid,
                            generation,
                            &trig,
                            &req_id,
                            exp.as_deref(),
                        )
                        .await;
                    });
                }
                AppEvent::TreeDiverged { convo_id } => {
                    // Spec: treeChanged should NOT trigger an immediate External
                    // Commit. Flag the conversation as NEEDS_REJOIN and let
                    // deferred recovery (post-sync) handle it.
                    let label = &convo_id[..12.min(convo_id.len())];
                    warn!(
                        "Tree diverged for {label} — flagging NEEDS_REJOIN (deferred recovery)"
                    );
                    let svc = Arc::clone(&app.service);
                    let cid = convo_id.clone();
                    tokio::spawn(async move {
                        svc.flag_needs_rejoin(&cid).await;
                    });
                }
                AppEvent::MessageSent(msg) => {
                    if let Some(convo) = app.active_conversation() {
                        if msg.convo_id == convo.conversation_id {
                            app.messages.push(msg);
                            app.scroll_offset = 0;
                        }
                    }
                }
                AppEvent::SendFailed(e) => {
                    error!("Send failed: {e}");
                }
                AppEvent::SyncCompleted => {
                    // No-op: background sync now sends ConvoListUpdated directly
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
async fn handle_chat_key(app: &mut App, key: crossterm::event::KeyEvent, event_tx: &tokio::sync::mpsc::UnboundedSender<AppEvent>) {
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
                    let convo_id = convo.conversation_id.clone();
                    let svc = Arc::clone(&app.service);
                    let tx = event_tx.clone();
                    tokio::spawn(async move {
                        match svc.send_message(&convo_id, &text).await {
                            Ok(msg) => {
                                let _ = tx.send(AppEvent::MessageSent(msg));
                            }
                            Err(e) => {
                                let _ = tx.send(AppEvent::SendFailed(format!("{e}")));
                            }
                        }
                    });
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
///
/// Loads from local SQLCipher (instant). Server data was pre-fetched at startup
/// and stays current via WebSocket events.
async fn reload_messages(app: &mut App) {
    if let Some(convo) = app.active_conversation() {
        let convo_id = convo.conversation_id.clone();
        match app.service.load_local_messages(&convo_id, 50).await {
            Ok(msgs) => app.messages = msgs,
            Err(e) => error!("Failed to load messages from local DB: {e}"),
        }
    }
}

/// Parse a WebSocket plaintext JSON payload into a `MessageContent`.
fn parse_ws_plaintext(plaintext: &str) -> catmos_core::types::MessageContent {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(plaintext) {
        // iOS uses "messageType", legacy uses "type"
        let msg_type = v
            .get("messageType")
            .or_else(|| v.get("type"))
            .and_then(|t| t.as_str());
        match msg_type {
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
