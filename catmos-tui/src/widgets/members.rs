use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;

/// Render the member panel on the right side.
pub fn render(frame: &mut Frame, _app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Members ");

    let paragraph = Paragraph::new("(no members loaded)").block(block);
    frame.render_widget(paragraph, area);
}
