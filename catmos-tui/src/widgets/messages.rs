use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use catmos_core::types::MessageContent;

use crate::app::App;

/// Color palette for sender names, indexed by hashing the DID.
const SENDER_COLORS: &[Color] = &[
    Color::Cyan,
    Color::Green,
    Color::Yellow,
    Color::Blue,
    Color::Magenta,
    Color::Red,
    Color::LightCyan,
    Color::LightGreen,
    Color::LightYellow,
    Color::LightBlue,
    Color::LightMagenta,
    Color::LightRed,
];

/// Simple hash of a DID string to pick a consistent color.
fn did_color(did: &str) -> Color {
    let hash = did
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    SENDER_COLORS[hash as usize % SENDER_COLORS.len()]
}

/// Render the message list.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    if app.messages.is_empty() {
        let placeholder = Paragraph::new("  No messages yet. Send one with Enter.")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(placeholder, area);
        return;
    }

    let my_did = app.service.did();
    let height = area.height as usize;

    // Build lines from messages
    let mut lines: Vec<Line> = Vec::new();

    for msg in &app.messages {
        let timestamp = msg.created_at.format("%H:%M").to_string();
        let sender = msg.sender_did.as_deref().unwrap_or("unknown");

        let sender_display = if sender == my_did {
            "you".to_string()
        } else {
            // Show last segment of DID or truncated
            sender
                .rsplit(':')
                .next()
                .unwrap_or(sender)
                .to_string()
        };

        let color = if sender == my_did {
            Color::Cyan
        } else {
            did_color(sender)
        };

        let content_text = match &msg.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Reaction { emoji, .. } => format!("[reaction: {emoji}]"),
            MessageContent::System(text) => format!("[system: {text}]"),
            MessageContent::Unknown => "[unknown message]".to_string(),
        };

        let line = Line::from(vec![
            Span::styled(
                format!("{timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(format!("{sender_display}: "), Style::default().fg(color)),
            Span::raw(content_text),
        ]);

        lines.push(line);
    }

    // Apply scroll offset: show lines ending at (len - scroll_offset)
    let total = lines.len();
    let end = total.saturating_sub(app.scroll_offset);
    let start = end.saturating_sub(height);
    let visible: Vec<Line> = lines.into_iter().skip(start).take(end - start).collect();

    let paragraph = Paragraph::new(visible);
    frame.render_widget(paragraph, area);
}
