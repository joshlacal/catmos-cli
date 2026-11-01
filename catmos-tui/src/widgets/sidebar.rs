use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

use crate::app::App;

/// Render the conversation sidebar.
///
/// Each list item is a two-line block: the first line is the
/// active-marker plus the conversation title (alias > decrypted name >
/// truncated group id); the second line is the decrypted description in
/// dim grey, or a small placeholder line indicating the avatar
/// availability when the description is empty (parity with iOS row UX).
/// Both lines render only from locally-decrypted state — the server is
/// cryptographically blind to titles after the metadata cutover.
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

            let style = if is_active {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else if has_unread {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };

            // Title line: marker + name.
            let mut title_spans = Vec::new();
            if is_active {
                title_spans.push(Span::styled("\u{25b8} ", Style::default().fg(Color::Cyan)));
            } else if has_unread {
                title_spans.push(Span::styled("\u{25cf} ", Style::default().fg(Color::Green)));
            } else {
                title_spans.push(Span::raw("  "));
            }
            title_spans.push(Span::styled(name.to_string(), style));

            // Description / avatar hint line. Dim grey, indented under the
            // marker. Skipped entirely when there's nothing to show so
            // groups without metadata don't get a stray blank row.
            let mut lines = vec![Line::from(title_spans)];
            let dim = Style::default().fg(Color::DarkGray);
            let detail_text = match (convo.description.as_deref(), convo.avatar_bytes.is_some()) {
                (Some(desc), _) if !desc.is_empty() => {
                    Some(truncate_for_sidebar(desc, area.width as usize))
                }
                (_, true) => Some("[avatar]".to_string()),
                _ => None,
            };
            if let Some(detail) = detail_text {
                lines.push(Line::from(vec![Span::raw("  "), Span::styled(detail, dim)]));
            }

            ListItem::new(lines)
        })
        .collect();

    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Conversations ");

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::truncate_for_sidebar;

    #[test]
    fn truncate_returns_empty_when_width_below_padding() {
        assert_eq!(truncate_for_sidebar("hello world", 0), "");
        assert_eq!(truncate_for_sidebar("hello world", 3), "");
        assert_eq!(truncate_for_sidebar("hello world", 4), "");
    }

    #[test]
    fn truncate_keeps_short_strings_intact() {
        assert_eq!(truncate_for_sidebar("hi", 22), "hi");
    }

    #[test]
    fn truncate_appends_ellipsis_when_clipping() {
        let out = truncate_for_sidebar("aaaaaaaaaaaaaaaaaaaa", 10);
        assert!(out.ends_with('\u{2026}'));
        // budget = 10 - 4 = 6; output must be at most 6 chars including ellipsis.
        assert!(out.chars().count() <= 6);
    }
}

/// Trim `s` to fit roughly within the sidebar's width, accounting for the
/// 2-char indent + 1-char border on the right. Adds a Unicode ellipsis when
/// truncated. `width` is the area width, may be zero on first render.
fn truncate_for_sidebar(s: &str, width: usize) -> String {
    let budget = width.saturating_sub(4); // 2 for indent, 2 slack for border/ellipsis
    if budget == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(budget);
    for (taken, ch) in s.chars().enumerate() {
        if taken + 1 >= budget {
            out.push('\u{2026}');
            return out;
        }
        out.push(ch);
    }
    out
}
