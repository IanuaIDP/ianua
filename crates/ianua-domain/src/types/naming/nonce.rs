//! The OIDC nonce, an opaque string that ties an ID token to an
//! authorization request.

use crate::shared::validation::{TextValue, Validator, text_value};

/// The longest nonce accepted.
const MAX_NONCE_LENGTH: usize = 256;

/// The shortest nonce accepted, so it cannot be guessed easily.
const MIN_NONCE_LENGTH: usize = 16;

text_value! {
    /// An OIDC nonce.
    ///
    /// It ties the ID token to the authorization request, so a token cannot
    /// be replayed into another sign-in. It must be unpredictable and long
    /// enough.
    ///
    /// # Validation
    ///
    /// - At least 16 characters, so it cannot be guessed easily.
    /// - At most 256 characters.
    /// - ASCII only, with no control characters or whitespace.
    pub struct Nonce;
}

impl TextValue for Nonce {
    const FIELD: &'static str = "nonce";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(MIN_NONCE_LENGTH..=MAX_NONCE_LENGTH)
    }
}

impl Nonce {
    /// The nonce as an owned string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 32-character nonce is accepted and kept whole.
    #[test]
    fn accepts_valid_nonce() {
        let n = Nonce::new("a".repeat(32)).unwrap();
        assert_eq!(n.as_str().len(), 32);
    }

    /// A nonce of exactly 16 characters, the shortest allowed, is accepted.
    #[test]
    fn accepts_at_min_length() {
        assert!(Nonce::new("a".repeat(16)).is_ok());
    }

    /// A nonce of exactly 256 characters, the longest allowed, is accepted.
    #[test]
    fn accepts_at_max_length() {
        assert!(Nonce::new("a".repeat(256)).is_ok());
    }

    /// A five-character correlation value is refused for falling below the
    /// minimum nonce length.
    #[test]
    fn rejects_too_short() {
        assert!(Nonce::new("short").is_err());
    }

    /// A 257-character nonce is refused.
    #[test]
    fn rejects_too_long() {
        assert!(Nonce::new("a".repeat(257)).is_err());
    }

    /// Empty text cannot supply the nonce that ties a token to its request.
    #[test]
    fn an_empty_nonce_is_refused() {
        assert!(Nonce::new("").is_err());
    }

    /// A nonce long enough but holding a NUL byte is refused.
    #[test]
    fn rejects_control_chars() {
        assert!(Nonce::new(format!("{}nonce\x00value", "a".repeat(16))).is_err());
    }

    /// A nonce prints as the text it holds.
    #[test]
    fn display_returns_value() {
        let n = Nonce::new("a".repeat(32)).unwrap();
        assert_eq!(n.to_string(), "a".repeat(32));
    }
}
