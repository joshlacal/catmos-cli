use std::collections::HashMap;
use std::sync::Arc;

use catmos_core::chat::service::ChatService;
use catmos_core::types::{Conversation, Message};

/// Which screen the TUI is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Chat,
    CommandPalette,
    NewConvo,
    Requests,
    RequestRecipient,
    RequestCompose,
}

/// Central application state for the TUI.
pub struct App {
    pub requests: Vec<catmos_core::chat::requests::RequestView>,
    pub selected_request: usize,
    pub request_drafts: Vec<catmos_core::chat::requests::RequestDraft>,
    pub selected_draft: usize,
    pub request_scroll: u16,
    pub request_draft: Option<catmos_core::chat::requests::RequestDraft>,
    pub request_delivery: Option<bool>,
    pub send_allowed: bool,
    /// The chat service for XRPC calls, encryption, etc.
    pub service: Arc<ChatService>,

    /// Current screen/mode.
    pub screen: Screen,

    /// Cached conversation list.
    pub conversations: Vec<Conversation>,

    /// Index of the active conversation in `conversations`.
    pub active_convo: usize,

    /// Messages for the active conversation.
    pub messages: Vec<Message>,

    /// Current text in the input bar.
    pub input: String,

    /// Cursor position within `input` (byte offset).
    pub cursor_pos: usize,

    /// Whether the sidebar is visible.
    pub sidebar_visible: bool,

    /// Whether the member panel is visible.
    pub member_panel_visible: bool,

    /// Scroll offset from the bottom of the message list (0 = latest).
    pub scroll_offset: usize,

    /// When true the main loop should exit.
    pub should_quit: bool,

    /// Cache of DID → handle for display.
    pub handle_cache: HashMap<String, String>,

    /// Human-readable operation state shown in the status bar.
    pub status: String,
}

impl App {
    pub fn new(
        service: Arc<ChatService>,
        sidebar_visible: bool,
        member_panel_visible: bool,
    ) -> Self {
        Self {
            requests: Vec::new(),
            selected_request: 0,
            request_drafts: Vec::new(),
            selected_draft: 0,
            request_scroll: 0,
            request_draft: None,
            request_delivery: None,
            send_allowed: false,
            service,
            screen: Screen::Chat,
            conversations: Vec::new(),
            active_convo: 0,
            messages: Vec::new(),
            input: String::new(),
            cursor_pos: 0,
            sidebar_visible,
            member_panel_visible,
            scroll_offset: 0,
            should_quit: false,
            handle_cache: HashMap::new(),
            status: "ready".to_string(),
        }
    }

    /// The currently active conversation, if any.
    pub fn active_conversation(&self) -> Option<&Conversation> {
        self.conversations.get(self.active_convo)
    }

    /// Select a conversation by index and reset scroll/input state.
    pub fn select_conversation(&mut self, index: usize) {
        if index < self.conversations.len() {
            self.active_convo = index;
            self.scroll_offset = 0;
            self.messages.clear();
        }
    }

    /// Move to the next conversation.
    pub fn next_conversation(&mut self) {
        if !self.conversations.is_empty() {
            let next = (self.active_convo + 1) % self.conversations.len();
            self.select_conversation(next);
        }
    }

    /// Move to the previous conversation.
    pub fn prev_conversation(&mut self) {
        if !self.conversations.is_empty() {
            let prev = if self.active_convo == 0 {
                self.conversations.len() - 1
            } else {
                self.active_convo - 1
            };
            self.select_conversation(prev);
        }
    }

    /// Insert a character at the cursor position.
    pub fn insert_char(&mut self, c: char) {
        self.input.insert(self.cursor_pos, c);
        self.cursor_pos += c.len_utf8();
    }

    /// Delete the character before the cursor.
    pub fn delete_char_before(&mut self) {
        if self.cursor_pos > 0 {
            // Find the previous char boundary
            let prev = self.input[..self.cursor_pos]
                .char_indices()
                .next_back()
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.input.remove(prev);
            self.cursor_pos = prev;
        }
    }

    /// Delete the character at the cursor.
    pub fn delete_char_at(&mut self) {
        if self.cursor_pos < self.input.len() {
            self.input.remove(self.cursor_pos);
        }
    }

    /// Move cursor left by one character.
    pub fn cursor_left(&mut self) {
        if self.cursor_pos > 0 {
            self.cursor_pos = self.input[..self.cursor_pos]
                .char_indices()
                .next_back()
                .map(|(i, _)| i)
                .unwrap_or(0);
        }
    }

    /// Move cursor right by one character.
    pub fn cursor_right(&mut self) {
        if self.cursor_pos < self.input.len() {
            self.cursor_pos = self.input[self.cursor_pos..]
                .char_indices()
                .nth(1)
                .map(|(i, _)| self.cursor_pos + i)
                .unwrap_or(self.input.len());
        }
    }

    /// Get display name for a DID: handle if cached, otherwise short DID.
    pub fn display_name(&self, did: &str) -> String {
        if let Some(handle) = self.handle_cache.get(did) {
            handle.clone()
        } else {
            did.rsplit(':').next().unwrap_or(did).to_string()
        }
    }

    /// Take the current input, clearing it and resetting cursor.
    pub fn take_input(&mut self) -> String {
        self.cursor_pos = 0;
        std::mem::take(&mut self.input)
    }

    /// Replace the transient operation state shown to the user.
    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
    }
}
