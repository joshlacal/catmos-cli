use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;

/// Render the input bar at the bottom of the screen.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Message ");

    let paragraph = Paragraph::new(app.input.as_str()).block(block);
    frame.render_widget(paragraph, area);
}
