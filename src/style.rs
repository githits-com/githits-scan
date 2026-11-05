//! Terminal styling for human-readable reports.
//!
//! Color never carries meaning: every report reads the same with styling
//! disabled. The command layer decides whether styling is enabled (a flag,
//! `NO_COLOR`, and whether the stream is a terminal) and passes a [`Palette`]
//! to the renderer, so renderers stay pure and testable.

use std::borrow::Cow;

/// ANSI styling that can be switched off wholesale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    enabled: bool,
}

impl Palette {
    /// Styling with ANSI escape sequences.
    pub const ENABLED: Self = Self { enabled: true };
    /// Plain text.
    pub const PLAIN: Self = Self { enabled: false };

    /// Emphasize a headline.
    #[must_use]
    pub fn bold(self, text: &str) -> Cow<'_, str> {
        self.wrap("1", text)
    }

    /// De-emphasize secondary text such as table headers.
    #[must_use]
    pub fn dim(self, text: &str) -> Cow<'_, str> {
        self.wrap("2", text)
    }

    /// Draw attention to something the user should act on.
    #[must_use]
    pub fn warning(self, text: &str) -> Cow<'_, str> {
        self.wrap("33", text)
    }

    fn wrap<'a>(self, code: &str, text: &'a str) -> Cow<'a, str> {
        if self.enabled {
            Cow::Owned(format!("\x1b[{code}m{text}\x1b[0m"))
        } else {
            Cow::Borrowed(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_palette_returns_text_unchanged() {
        assert_eq!(Palette::PLAIN.bold("x"), "x");
        assert_eq!(Palette::PLAIN.dim("x"), "x");
        assert_eq!(Palette::PLAIN.warning("x"), "x");
    }

    #[test]
    fn enabled_palette_wraps_text_in_escape_sequences() {
        assert_eq!(Palette::ENABLED.bold("x"), "\x1b[1mx\x1b[0m");
        assert_eq!(Palette::ENABLED.dim("x"), "\x1b[2mx\x1b[0m");
        assert_eq!(Palette::ENABLED.warning("x"), "\x1b[33mx\x1b[0m");
    }
}
