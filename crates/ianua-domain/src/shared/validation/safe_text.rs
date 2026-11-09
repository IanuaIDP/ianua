//! The one way text from outside is made safe to store, log and show.
//!
//! Refusals, validation messages, untrusted records and event labels all
//! carry words someone else chose. Each is cut to a length and has every
//! character replaced that could start a new log line, drive a terminal, or
//! make text read differently from what it says: control characters, the
//! Unicode line and paragraph separators, bidirectional overrides and
//! isolates, and zero-width and tag characters.

use crate::shared::validation::invisible::is_invisible;

/// What an unsafe character is recorded as.
const REPLACEMENT: char = '\u{FFFD}';

/// `value` cut to `limit` characters, with every unsafe character replaced.
pub(crate) fn made_safe(value: &str, limit: usize) -> String {
    value
        .chars()
        .take(limit)
        .map(|c| if is_unsafe(c) { REPLACEMENT } else { c })
        .collect()
}

/// Whether `c` could forge a line, drive a terminal, or hide what text says.
fn is_unsafe(c: char) -> bool {
    c.is_control() || is_invisible(c) || matches!(c, '\u{2028}' | '\u{2029}')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// German, Japanese and Arabic text, with a middle dot between, comes
    /// back unchanged. Only unsafe characters are replaced, not foreign ones.
    #[test]
    fn ordinary_text_in_any_script_is_kept() {
        let text = "Zahlung prüfen · 支払いを確認 · مراجعة الدفع";

        assert_eq!(made_safe(text, 100), text);
    }

    /// Unicode line and paragraph separators become replacement characters.
    #[test]
    fn line_and_paragraph_separators_are_replaced() {
        assert_eq!(
            made_safe("evil\u{2028}level=INFO\u{2029}x", 100),
            "evil\u{FFFD}level=INFO\u{FFFD}x"
        );
    }

    /// Bidirectional overrides, isolates, and zero-width spaces become replacement characters.
    #[test]
    fn bidi_overrides_and_zero_width_characters_are_replaced() {
        assert_eq!(
            made_safe("a\u{202E}b\u{2066}c\u{200B}d", 100),
            "a\u{FFFD}b\u{FFFD}c\u{FFFD}d"
        );
    }

    /// Newline and escape controls become replacement characters while printable text remains.
    #[test]
    fn control_characters_are_replaced() {
        assert_eq!(made_safe("a\nb\u{1b}[31m", 100), "a\u{FFFD}b\u{FFFD}[31m");
    }

    /// Fifty characters with a limit of ten come back as ten characters.
    #[test]
    fn text_is_cut_to_the_limit() {
        assert_eq!(made_safe(&"x".repeat(50), 10).chars().count(), 10);
    }
}
