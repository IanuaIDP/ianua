//! Opaque values a protocol carries as one word: nonces, key ids,
//! audiences, challenges.

use std::ops::RangeInclusive;

use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Checks an opaque token whose length falls in `length`.
    ///
    /// The rules:
    /// - not empty, ASCII only
    /// - length within `length`
    /// - no control characters or whitespace, which would split the token or
    ///   end the header it travels in
    #[must_use]
    pub fn token(self, length: RangeInclusive<usize>) -> Self {
        self.not_empty()
            .ascii_only()
            .length(length)
            .no_control_chars()
            .no_whitespace()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(value: &str) -> bool {
        Validator::new("token", value)
            .token(4..=16)
            .validate_first()
            .is_ok()
    }

    /// A token of letters, digits and `-_.~` passes.
    #[test]
    fn a_token_of_printable_characters_is_accepted() {
        assert!(token("a1-B2_c3.d4~"));
    }

    /// Tokens reject whitespace and non-ASCII characters, and must fit the configured length bounds.
    #[test]
    fn a_token_that_could_be_split_is_refused() {
        for value in [
            "",
            "abc",
            "ab cd",
            "ab\tcd",
            "ab\r\ncd",
            "abcdé",
            "abcdefghijklmnopq",
        ] {
            assert!(!token(value), "{value:?} was accepted");
        }
    }
}
