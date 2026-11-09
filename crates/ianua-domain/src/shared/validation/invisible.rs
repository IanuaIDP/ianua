//! Invisible characters: text that renders differently from what it says.
//!
//! Bidirectional overrides reorder what a reader sees. Zero-width characters
//! hide boundaries. Unicode tag characters carry a whole hidden string inside
//! one that looks short. None of them belongs in text a person decides on.
//! So agent-authored text is cleaned of them before it is shown, and values a
//! person reviews refuse them.

/// Whether `c` changes how text renders without being visible itself.
///
/// Every format character (Unicode general category `Cf`), plus the fillers
/// and variation selectors that also render as nothing.
#[must_use]
pub fn is_invisible(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x034F
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

/// `text` without its invisible characters.
#[must_use]
pub fn strip_invisible(text: &str) -> String {
    text.chars().filter(|c| !is_invisible(*c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The right-to-left override, a bidi isolate, zero-width space and
    /// joiner, the byte order mark and the Arabic letter mark all count as
    /// invisible.
    #[test]
    fn bidi_overrides_and_zero_width_characters_are_invisible() {
        for c in [
            '\u{202E}', '\u{2066}', '\u{200B}', '\u{200D}', '\u{FEFF}', '\u{061C}',
        ] {
            assert!(is_invisible(c), "{:04X}", u32::from(c));
        }
    }

    /// Every code point in the Unicode 16 format category `Cf` counts as
    /// invisible. The ranges are listed by hand, so a gap in the matcher shows.
    #[test]
    fn every_format_character_is_invisible() {
        let format_ranges: [(u32, u32); 21] = [
            (0x00AD, 0x00AD),
            (0x0600, 0x0605),
            (0x061C, 0x061C),
            (0x06DD, 0x06DD),
            (0x070F, 0x070F),
            (0x0890, 0x0891),
            (0x08E2, 0x08E2),
            (0x180E, 0x180E),
            (0x200B, 0x200F),
            (0x202A, 0x202E),
            (0x2060, 0x2064),
            (0x2066, 0x206F),
            (0xFEFF, 0xFEFF),
            (0xFFF9, 0xFFFB),
            (0x110BD, 0x110BD),
            (0x110CD, 0x110CD),
            (0x13430, 0x1343F),
            (0x1BCA0, 0x1BCA3),
            (0x1D173, 0x1D17A),
            (0xE0001, 0xE0001),
            (0xE0020, 0xE007F),
        ];

        for (first, last) in format_ranges {
            for code in first..=last {
                let c = char::from_u32(code).unwrap();
                assert!(is_invisible(c), "{code:04X}");
            }
        }
    }

    /// Stripping hidden tag characters removes the appended word and preserves "read report".
    #[test]
    fn tag_characters_are_invisible() {
        let hidden: String = "approve"
            .chars()
            .map(|c| char::from_u32(0xE0000 + u32::from(c)).unwrap())
            .collect();

        assert_eq!(
            strip_invisible(&format!("read report{hidden}")),
            "read report"
        );
    }

    /// German, Japanese and Arabic text comes back unchanged. Right-to-left
    /// script itself is not invisible, only the characters that steer it.
    #[test]
    fn ordinary_text_in_any_script_is_kept() {
        let text = "Zahlung prüfen · 支払いを確認 · مراجعة الدفع";

        assert_eq!(strip_invisible(text), text);
    }

    /// Stripping a right-to-left override preserves the filename's actual character order.
    #[test]
    fn a_right_to_left_override_is_removed() {
        assert_eq!(strip_invisible("invoice\u{202E}txt.exe"), "invoicetxt.exe");
    }
}
