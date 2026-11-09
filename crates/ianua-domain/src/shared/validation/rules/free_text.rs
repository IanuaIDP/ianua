//! Text a person writes for other people to read: names, labels,
//! descriptions, reasons.

use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Checks text a person writes for others to read.
    ///
    /// The rules:
    /// - not blank
    /// - 1 to `max_chars` characters, counted as Unicode characters
    /// - no ASCII control characters, such as null, tab, escape or a line
    ///   break, which would break the line it is shown on or the header it
    ///   is sent in
    /// - no invisible characters, such as bidirectional overrides,
    ///   zero-width or tag characters, which make text read differently from
    ///   what it says
    #[must_use]
    pub fn free_text(self, max_chars: usize) -> Self {
        self.not_blank()
            .char_length(1..=max_chars)
            .no_control_chars()
            .no_invisible_chars()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A security key named `YubiKey 5` passes. Spaces and digits are fine.
    #[test]
    fn a_label_accepts_simple_name() {
        assert!(
            Validator::new("name", "YubiKey 5")
                .free_text(100)
                .validate()
                .is_empty()
        );
    }

    /// `MacBook de José` passes. Accented letters are ordinary text.
    #[test]
    fn a_label_accepts_unicode() {
        assert!(
            Validator::new("name", "MacBook de José")
                .free_text(100)
                .validate()
                .is_empty()
        );
    }

    /// A label starting with a key emoji passes. Emoji are visible text.
    #[test]
    fn a_label_accepts_emoji() {
        assert!(
            Validator::new("name", "\u{1F511} My Key")
                .free_text(100)
                .validate()
                .is_empty()
        );
    }

    /// An empty label is refused with the code `required`.
    #[test]
    fn a_label_rejects_empty() {
        let err = Validator::new("name", "")
            .free_text(100)
            .validate_first()
            .unwrap_err();
        assert_eq!(err.code(), "required");
    }

    /// A 101-character label is refused under a limit of 100.
    #[test]
    fn a_label_rejects_over_100_chars() {
        let long = "a".repeat(101);
        assert!(
            Validator::new("name", &long)
                .free_text(100)
                .validate_first()
                .is_err()
        );
    }

    /// A label of exactly 100 characters passes a limit of 100.
    #[test]
    fn a_label_accepts_exactly_100_chars() {
        let exactly = "a".repeat(100);
        assert!(
            Validator::new("name", &exactly)
                .free_text(100)
                .validate()
                .is_empty()
        );
    }

    /// A label with a null byte between two words is refused. Code that
    /// stops at the null would show only the first word.
    #[test]
    fn a_label_rejects_null_byte() {
        assert!(
            Validator::new("name", "Key\x00Name")
                .free_text(100)
                .validate_first()
                .is_err()
        );
    }

    /// A label with a tab in it is refused. Tabs are control characters.
    #[test]
    fn a_label_rejects_tab() {
        assert!(
            Validator::new("name", "Key\tName")
                .free_text(100)
                .validate_first()
                .is_err()
        );
    }

    /// A label containing a newline fails validation.
    #[test]
    fn a_label_rejects_newline() {
        assert!(
            Validator::new("name", "Key\nName")
                .free_text(100)
                .validate_first()
                .is_err()
        );
    }

    /// An escape control character is invalid in a label.
    #[test]
    fn a_label_rejects_escape_sequence() {
        assert!(
            Validator::new("name", "Key\x1BName")
                .free_text(100)
                .validate_first()
                .is_err()
        );
    }

    /// A break-glass reason naming an incident, with a colon, passes a limit
    /// of 500.
    #[test]
    fn free_text_accepts_normal_sentence() {
        assert!(
            Validator::new(
                "reason",
                "Production incident INC-1234: database migration failed"
            )
            .free_text(500)
            .validate()
            .is_empty()
        );
    }

    /// A reason written in German passes.
    #[test]
    fn free_text_accepts_unicode() {
        assert!(
            Validator::new("reason", "Ursache: Datenmigration fehlgeschlagen")
                .free_text(500)
                .validate()
                .is_empty()
        );
    }

    /// An empty reason is refused with `required`, so no action is logged
    /// without one.
    #[test]
    fn free_text_rejects_empty() {
        let err = Validator::new("reason", "")
            .free_text(500)
            .validate_first()
            .unwrap_err();
        assert_eq!(err.code(), "required");
    }

    /// A 501-character reason is refused under a limit of 500.
    #[test]
    fn free_text_rejects_over_500_chars() {
        let long = "a".repeat(501);
        assert!(
            Validator::new("reason", &long)
                .free_text(500)
                .validate_first()
                .is_err()
        );
    }

    /// A reason of exactly 500 characters passes a limit of 500.
    #[test]
    fn free_text_accepts_exactly_500_chars() {
        let exactly = "a".repeat(500);
        assert!(
            Validator::new("reason", &exactly)
                .free_text(500)
                .validate()
                .is_empty()
        );
    }

    /// A reason with a null byte in it is refused.
    #[test]
    fn free_text_rejects_null_byte() {
        assert!(
            Validator::new("reason", "reason\x00here")
                .free_text(500)
                .validate_first()
                .is_err()
        );
    }

    /// A reason holding the control byte 0x01 is refused, not only the
    /// well-known ones such as null and tab.
    #[test]
    fn free_text_rejects_control_chars() {
        assert!(
            Validator::new("reason", "reason\x01here")
                .free_text(500)
                .validate_first()
                .is_err()
        );
    }

    /// A right-to-left override within a label is rejected.
    #[test]
    fn free_text_rejects_text_that_reads_differently_from_what_it_says() {
        assert!(
            Validator::new("name", "admin\u{202E}nimda")
                .free_text(100)
                .validate_first()
                .is_err()
        );
    }

    /// A name of three spaces is refused as blank, though it is not empty.
    #[test]
    fn free_text_rejects_blank_text() {
        assert!(
            Validator::new("name", "   ")
                .free_text(100)
                .validate_first()
                .is_err()
        );
    }
}
