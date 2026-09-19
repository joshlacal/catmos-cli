pub mod avatar;
pub mod input;
pub mod members;
pub mod messages;
pub mod sidebar;
pub mod status_bar;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;

use crate::app::App;

/// Render the full TUI layout into the terminal frame.
pub fn render(frame: &mut Frame, app: &App) {
    if matches!(
        app.screen,
        crate::app::Screen::Requests
            | crate::app::Screen::RequestRecipient
            | crate::app::Screen::RequestCompose
    ) {
        crate::requests::render(frame, app);
        return;
    }
    let size = frame.area();

    // Top-level vertical split: status bar | middle | input
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status bar
            Constraint::Min(1),    // message area (fills remaining)
            Constraint::Length(3), // input bar
        ])
        .split(size);

    // Status bar
    status_bar::render(frame, app, vertical[0]);

    // Middle: optional sidebar | messages | optional members
    render_middle(frame, app, vertical[1]);

    // Input bar
    input::render(frame, app, vertical[2]);
}

/// Render the middle section with optional sidebar and member panel.
fn render_middle(frame: &mut Frame, app: &App, area: Rect) {
    let mut constraints = Vec::new();

    if app.sidebar_visible {
        constraints.push(Constraint::Length(22));
    }

    constraints.push(Constraint::Min(1)); // messages

    if app.member_panel_visible {
        constraints.push(Constraint::Length(20));
    }

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(area);

    let mut col = 0;

    if app.sidebar_visible {
        sidebar::render(frame, app, horizontal[col]);
        col += 1;
    }

    messages::render(frame, app, horizontal[col]);
    col += 1;

    if app.member_panel_visible {
        members::render(frame, app, horizontal[col]);
    }
}
