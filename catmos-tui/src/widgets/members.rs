use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

use crate::app::App;

/// Render the member panel on the right side.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let members = app
        .active_conversation()
        .map(|c| &c.members[..])
        .unwrap_or(&[]);

    let items: Vec<ListItem> = members
        .iter()
        .map(|member| {
            let did_short = member
                .user_did
                .rsplit(':')
                .next()
                .unwrap_or(&member.user_did);

            let mut spans = vec![Span::styled(
                did_short.to_string(),
                Style::default().fg(Color::White),
            )];

            if member.is_admin {
                spans.push(Span::styled(
                    " [admin]",
                    Style::default().fg(Color::Yellow),
                ));
            } else if member.is_moderator {
                spans.push(Span::styled(
                    " [mod]",
                    Style::default().fg(Color::Cyan),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::LEFT)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Members ");

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}
