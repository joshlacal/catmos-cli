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

    // Build lines from messages, filtering out decryption failures
    let mut lines: Vec<Line> = Vec::new();
    let mut shown_join_marker = false;

    for msg in &app.messages {
        // Skip decryption failures (pre-join messages we can't read)
        match &msg.content {
            MessageContent::System(text) if text.contains("Decryption failed") => {
                if !shown_join_marker {
                    shown_join_marker = true;
                    // We'll add the join marker after skipping all old messages
                }
                continue;
            }
            MessageContent::Unknown => continue,
            _ => {}
        }

        // Insert "joined" marker before first readable message
        if shown_join_marker {
            shown_join_marker = false; // only show once
            lines.push(Line::from(Span::styled(
                "  ── You joined this conversation ──",
                Style::default().fg(Color::DarkGray),
            )));
        }

        let timestamp = msg.created_at.format("%H:%M").to_string();
        let sender = msg.sender_did.as_deref().unwrap_or("unknown");

        let sender_display = if sender == my_did {
            "you".to_string()
        } else {
            app.display_name(sender)
        };

        let color = if sender == my_did {
            Color::Cyan
        } else {
            did_color(sender)
        };

        let content_text = match &msg.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Reaction { emoji, .. } => format!("[reaction: {emoji}]"),
            MessageContent::System(text) => text.clone(),
            _ => continue,
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

    // If all messages were undecryptable, still show the join marker
    if shown_join_marker {
        lines.push(Line::from(Span::styled(
            "  ── You joined this conversation ──",
            Style::default().fg(Color::DarkGray),
        )));
    }

    // Apply scroll offset: show lines ending at (len - scroll_offset)
    let total = lines.len();
    let end = total.saturating_sub(app.scroll_offset);
    let start = end.saturating_sub(height);
    let visible: Vec<Line> = lines.into_iter().skip(start).take(end - start).collect();

    let paragraph = Paragraph::new(visible);
    frame.render_widget(paragraph, area);
}
