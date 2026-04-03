use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;

/// Render the input bar at the bottom of the screen.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let hints = "^Q quit  ^S sidebar  ^M members  Tab next  Enter send";

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray))
        .title_bottom(Line::from(Span::styled(
            hints,
            Style::default().fg(Color::DarkGray),
        )));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.input.is_empty() {
        let placeholder = Paragraph::new(Span::styled(
            "Type a message...",
            Style::default().fg(Color::DarkGray),
        ));
        frame.render_widget(placeholder, inner);
    } else {
        let text = Paragraph::new(app.input.as_str());
        frame.render_widget(text, inner);
    }

    // Position the cursor
    let cursor_x = inner.x + app.cursor_pos as u16;
    let cursor_y = inner.y;
    if cursor_x < inner.x + inner.width {
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}
