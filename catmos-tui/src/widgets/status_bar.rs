use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;

/// Render the 1-line status bar at the top of the screen.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let bg = Style::default().bg(Color::DarkGray).fg(Color::White);

    let account = app.service.did();
    let account_display = if account.is_empty() {
        "not logged in"
    } else {
        account
    };

    let mut parts: Vec<Span> = vec![
        Span::styled(" catmos", bg.fg(Color::Cyan)),
        Span::styled(" \u{00b7} ", bg),
        Span::styled(account_display, bg),
    ];

    if let Some(convo) = app.active_conversation() {
        let name = convo
            .alias
            .as_deref()
            .or(convo.name.as_deref())
            .unwrap_or(&convo.group_id[..8.min(convo.group_id.len())]);

        parts.push(Span::styled(" \u{00b7} ", bg));
        parts.push(Span::styled(name.to_string(), bg.fg(Color::Yellow)));
        parts.push(Span::styled(
            format!(
                " \u{00b7} epoch {} \u{00b7} {} members",
                convo.epoch,
                convo.members.len()
            ),
            bg,
        ));
    }

    parts.push(Span::styled(" · ", bg));
    parts.push(Span::styled(app.status.clone(), bg.fg(Color::LightGreen)));

    // Pad the rest of the line with background color
    let content_len: usize = parts.iter().map(|s| s.content.len()).sum();
    let padding = if area.width as usize > content_len {
        " ".repeat(area.width as usize - content_len)
    } else {
        String::new()
    };
    parts.push(Span::styled(padding, bg));

    let line = Line::from(parts);
    let bar = Paragraph::new(line);
    frame.render_widget(bar, area);
}
