use crossterm::event::{self, Event, KeyEvent};
use tokio::sync::mpsc;
use tracing::error;

use catmos_core::types::{Conversation, Message};

/// Events the TUI main loop can receive.
#[derive(Debug)]
pub enum AppEvent {
    /// A keyboard event from crossterm.
    Key(KeyEvent),
    /// Periodic tick for UI refresh.
    Tick,
    /// An incoming chat message (from WebSocket).
    ChatMessage(Message),
    /// The MLS epoch advanced for a conversation — re-fetch messages.
    EpochAdvanced { convo_id: String, new_epoch: u64 },
    /// The conversation list was updated.
    ConvoListUpdated(Vec<Conversation>),
    /// The MLS tree diverged for a conversation — needs silent repair.
    TreeDiverged { convo_id: String },
    /// The MLS group was reset by an admin — rejoin with new group ID.
    GroupReset { convo_id: String, new_group_id: String, reset_generation: u64 },
    /// Background sync completed — refresh conversation list.
    SyncCompleted,
    /// A message we sent was confirmed by the server.
    MessageSent(Message),
    /// A message send failed.
    SendFailed(String),
    /// An error to display in the status bar.
    Error(String),
}

/// Manages the event channel: polls crossterm for key events and ticks,
/// and exposes an `UnboundedSender` for injecting external events (WS messages, etc.).
pub struct EventLoop {
    rx: mpsc::UnboundedReceiver<AppEvent>,
}

impl EventLoop {
    /// Spawn the event loop.
    ///
    /// `tick_rate` — how often to emit `Tick` events (in milliseconds).
    ///
    /// Returns `(EventLoop, UnboundedSender)`. The sender can be cloned and given
    /// to WebSocket tasks or other async producers.
    pub fn new(tick_rate_ms: u64) -> (Self, mpsc::UnboundedSender<AppEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let event_tx = tx.clone();

        let tick_rate = std::time::Duration::from_millis(tick_rate_ms);

        tokio::spawn(async move {
            loop {
                // Poll crossterm with a timeout equal to tick_rate
                let has_event = tokio::task::spawn_blocking({
                    let tick = tick_rate;
                    move || event::poll(tick).unwrap_or(false)
                })
                .await
                .unwrap_or(false);

                if has_event {
                    // Read the event (non-blocking since poll said one is ready)
                    let read_result = tokio::task::spawn_blocking(|| event::read()).await;

                    match read_result {
                        Ok(Ok(Event::Key(key))) => {
                            if event_tx.send(AppEvent::Key(key)).is_err() {
                                return; // receiver dropped
                            }
                        }
                        Ok(Err(e)) => {
                            error!("crossterm read error: {e}");
                        }
                        Err(e) => {
                            error!("crossterm blocking task panicked: {e}");
                        }
                        _ => {} // mouse, resize, etc. — ignore for now
                    }
                } else {
                    // Timeout elapsed — send a tick
                    if event_tx.send(AppEvent::Tick).is_err() {
                        return;
                    }
                }
            }
        });

        (Self { rx }, tx)
    }

    /// Wait for the next event.
    pub async fn next(&mut self) -> Option<AppEvent> {
        self.rx.recv().await
    }
}
