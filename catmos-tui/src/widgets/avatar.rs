//! Avatar rendering for the TUI conversation header.
//!
//! Two implementations:
//!
//! - **Default (no `terminal-images` feature):** returns a unicode
//!   placeholder string (`[avatar]`) that the sidebar / status bar embed
//!   inline. Avatar bytes from the encrypted bootstrap pipeline are
//!   persisted to local storage regardless — the feature flag only gates
//!   the rendering path.
//!
//! - **`terminal-images` feature:** detects kitty / sixel terminals via
//!   the standard environment variables (`$TERM` matching `*kitty*` or
//!   `*sixel*`, or `$KITTY_WINDOW_ID` set) and emits the inline-image
//!   escape sequence for the decrypted avatar bytes. Falls back to the
//!   placeholder when the terminal does not advertise either protocol.
//!
//! The implementation here is intentionally minimal: kitty graphics
//! protocol with raw image data + base64 chunking, no compositor. A
//! richer renderer (resizing, cell-aware placement) is a follow-up that
//! can plug into the same gate without touching the storage layer.

#![allow(dead_code)]

/// Detected terminal image protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvatarProtocol {
    /// No image protocol detected — render a placeholder.
    None,
    /// Kitty graphics protocol (also iTerm2 ≥3.5 / Ghostty / WezTerm).
    Kitty,
    /// Sixel-capable xterm.
    Sixel,
}

/// Inspect environment variables to decide which inline-image protocol
/// the host terminal supports. Pure function — no I/O — so it is safe to
/// call on every render.
pub fn detect_protocol() -> AvatarProtocol {
    if std::env::var_os("KITTY_WINDOW_ID").is_some() {
        return AvatarProtocol::Kitty;
    }
    let term = std::env::var("TERM").unwrap_or_default().to_lowercase();
    if term.contains("kitty") || term.contains("ghostty") || term.contains("wezterm") {
        return AvatarProtocol::Kitty;
    }
    if term.contains("sixel") || term == "xterm-sixel" {
        return AvatarProtocol::Sixel;
    }
    AvatarProtocol::None
}

/// Build a one-line placeholder string for terminals that do not support
/// inline images, or for builds without the `terminal-images` feature.
pub fn placeholder_label(content_type: Option<&str>) -> String {
    match content_type {
        Some(ct) if !ct.is_empty() => format!("[avatar {ct}]"),
        _ => "[avatar]".to_string(),
    }
}

/// Render an avatar to a string fragment that the caller can embed in a
/// `Span` / `Line`. With the `terminal-images` feature enabled and a
/// supported terminal, the returned string contains escape sequences
/// that decode inline; otherwise this is the placeholder label.
///
/// Returns `None` when `bytes` is empty.
pub fn render_inline(bytes: Option<&[u8]>, content_type: Option<&str>) -> Option<String> {
    let bytes = bytes?;
    if bytes.is_empty() {
        return None;
    }

    #[cfg(feature = "terminal-images")]
    {
        match detect_protocol() {
            AvatarProtocol::Kitty => Some(render_kitty(bytes, content_type)),
            // Sixel encoding requires real pixel data; we don't bundle a
            // raster decoder yet, so fall back to the placeholder. Plug
            // a `viuer` / `sixel-rs` dependency in here when ready.
            AvatarProtocol::Sixel | AvatarProtocol::None => Some(placeholder_label(content_type)),
        }
    }

    #[cfg(not(feature = "terminal-images"))]
    {
        let _ = content_type;
        Some(placeholder_label(content_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_label_contains_content_type() {
        assert_eq!(placeholder_label(Some("image/png")), "[avatar image/png]");
        assert_eq!(placeholder_label(None), "[avatar]");
        assert_eq!(placeholder_label(Some("")), "[avatar]");
    }

    #[test]
    fn render_inline_returns_none_for_empty_bytes() {
        assert!(render_inline(None, None).is_none());
        assert!(render_inline(Some(&[]), None).is_none());
    }

    #[test]
    fn render_inline_returns_some_for_nonempty_bytes() {
        assert!(render_inline(Some(&[1, 2, 3]), Some("image/png")).is_some());
    }
}

#[cfg(feature = "terminal-images")]
fn render_kitty(bytes: &[u8], content_type: Option<&str>) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    // Determine the format byte for the kitty graphics protocol. 100 =
    // PNG, 101 = JPEG, 32 = RGBA32. We only support compressed image
    // formats here because the alternative requires width/height plus a
    // raster decoder; PNG/JPEG cover the catbird-mls metadata flow.
    let f = match content_type.unwrap_or("") {
        "image/png" => "100",
        "image/jpeg" | "image/jpg" => "101",
        _ => return placeholder_label(content_type),
    };

    let encoded = STANDARD.encode(bytes);
    // Chunked transmit: each chunk ≤ 4096 base64 chars; m=1 on all but
    // the last chunk per protocol (escape: ESC _G ... ESC \).
    let chunk_size = 4096;
    let mut out = String::new();
    let mut i = 0;
    while i < encoded.len() {
        let end = (i + chunk_size).min(encoded.len());
        let last = end == encoded.len();
        let m = if last { "0" } else { "1" };
        if i == 0 {
            out.push_str(&format!("\x1b_Ga=T,f={f},m={m};{}\x1b\\", &encoded[i..end]));
        } else {
            out.push_str(&format!("\x1b_Gm={m};{}\x1b\\", &encoded[i..end]));
        }
        i = end;
    }
    out
}
