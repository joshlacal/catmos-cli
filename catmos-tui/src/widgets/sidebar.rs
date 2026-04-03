use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

use crate::app::App;

/// Render the conversation sidebar.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .conversations
        .iter()
        .enumerate()
        .map(|(i, convo)| {
            let is_active = i == app.active_convo;
            let has_unread = convo.unread_count > 0;

            let name = convo
                .alias
                .as_deref()
                .or(convo.name.as_deref())
                .unwrap_or(&convo.group_id[..8.min(convo.group_id.len())]);

            let mut spans = Vec::new();

            // Active marker or unread indicator
            if is_active {
                spans.push(Span::styled(
                    "\u{25b8} ",
                    Style::default().fg(Color::Cyan),
                ));
            } else if has_unread {
                spans.push(Span::styled(
                    "\u{25cf} ",
                    Style::default().fg(Color::Green),
                ));
            } else {
                spans.push(Span::raw("  "));
            }

            let style = if is_active {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else if has_unread {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };

            spans.push(Span::styled(name.to_string(), style));

            ListItem::new(Line::from(spans))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Conversations ");

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}
