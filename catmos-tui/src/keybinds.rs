use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// High-level actions the TUI can perform, mapped from key events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Quit,
    ToggleSidebar,
    ToggleMembers,
    NewConvo,
    Requests,
    JoinConvo,
    CommandPalette,
    NextConvo,
    PrevConvo,
    SendMessage,
    ScrollUp,
    ScrollDown,
    Cancel,
    TypeChar(char),
    Backspace,
    Delete,
    CursorLeft,
    CursorRight,
    CursorHome,
    CursorEnd,
    /// Key press we don't handle.
    None,
}

/// Map a crossterm `KeyEvent` to a high-level `Action`.
pub fn map_key(key: KeyEvent) -> Action {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);

    match key.code {
        // ── Ctrl combinations ───────────────────────────────────────
        KeyCode::Char('q') if ctrl => Action::Quit,
        KeyCode::Char('c') if ctrl => Action::Quit,
        KeyCode::Char('s') if ctrl => Action::ToggleSidebar,
        KeyCode::Char('m') if ctrl => Action::ToggleMembers,
        KeyCode::Char('n') if ctrl => Action::NewConvo,
        KeyCode::Char('r') if ctrl => Action::Requests,
        KeyCode::Char('j') if ctrl => Action::JoinConvo,
        KeyCode::Char('k') if ctrl => Action::CommandPalette,

        // ── Tab navigation ──────────────────────────────────────────
        KeyCode::BackTab => Action::PrevConvo,
        KeyCode::Tab if shift => Action::PrevConvo,
        KeyCode::Tab => Action::NextConvo,

        // ── Enter ───────────────────────────────────────────────────
        KeyCode::Enter => Action::SendMessage,

        // ── Scroll ──────────────────────────────────────────────────
        KeyCode::PageUp => Action::ScrollUp,
        KeyCode::PageDown => Action::ScrollDown,

        // ── Escape ──────────────────────────────────────────────────
        KeyCode::Esc => Action::Cancel,

        // ── Text editing ────────────────────────────────────────────
        KeyCode::Char(c) => Action::TypeChar(c),
        KeyCode::Backspace => Action::Backspace,
        KeyCode::Delete => Action::Delete,

        // ── Cursor movement ─────────────────────────────────────────
        KeyCode::Left => Action::CursorLeft,
        KeyCode::Right => Action::CursorRight,
        KeyCode::Home => Action::CursorHome,
        KeyCode::End => Action::CursorEnd,

        _ => Action::None,
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;
    #[test]
    fn request_navigation_is_an_explicit_action() {
        assert_eq!(
            map_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL)),
            Action::Requests
        );
        assert_eq!(
            map_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
            Action::TypeChar('r')
        );
    }
}
