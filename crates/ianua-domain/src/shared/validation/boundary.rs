/// What the first and last characters of a string must be.
///
/// Used with [`Validator::boundaries`](crate::shared::validation::Validator::boundaries) for
/// rules like "a slug starts and ends with a letter or digit", as RFC 952
/// asks of DNS labels.
#[derive(Debug, Clone, Copy)]
pub enum Boundary {
    /// An ASCII letter or digit: `a-z`, `A-Z`, `0-9`.
    Alphanumeric,

    /// A lowercase ASCII letter: `a-z`.
    LowercaseLetter,

    /// An ASCII letter of either case: `a-z`, `A-Z`.
    Letter,

    /// A lowercase ASCII letter or a digit: `a-z`, `0-9`.
    LowercaseAlphanumeric,
}

impl Boundary {
    /// Whether `byte` may stand first or last.
    #[must_use]
    pub fn matches(&self, byte: u8) -> bool {
        match self {
            Self::Alphanumeric => byte.is_ascii_alphanumeric(),
            Self::LowercaseLetter => byte.is_ascii_lowercase(),
            Self::Letter => byte.is_ascii_alphabetic(),
            Self::LowercaseAlphanumeric => byte.is_ascii_lowercase() || byte.is_ascii_digit(),
        }
    }

    /// The allowed characters in words, for an error message.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Alphanumeric => "an alphanumeric character",
            Self::LowercaseLetter => "a lowercase letter",
            Self::Letter => "a letter",
            Self::LowercaseAlphanumeric => "a lowercase letter or digit",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `a`, `Z` and `0` may start or end an alphanumeric string. A hyphen
    /// may not.
    #[test]
    fn alphanumeric_accepts_letters_and_digits() {
        assert!(Boundary::Alphanumeric.matches(b'a'));
        assert!(Boundary::Alphanumeric.matches(b'Z'));
        assert!(Boundary::Alphanumeric.matches(b'0'));
        assert!(!Boundary::Alphanumeric.matches(b'-'));
    }

    /// Only `a` passes the lowercase-letter boundary. `A` and `0` fail it.
    #[test]
    fn lowercase_letter_rejects_uppercase_and_digits() {
        assert!(Boundary::LowercaseLetter.matches(b'a'));
        assert!(!Boundary::LowercaseLetter.matches(b'A'));
        assert!(!Boundary::LowercaseLetter.matches(b'0'));
    }

    /// The letter boundary takes `a` and `Z` but refuses the digit `0`.
    #[test]
    fn letter_accepts_both_cases_rejects_digits() {
        assert!(Boundary::Letter.matches(b'a'));
        assert!(Boundary::Letter.matches(b'Z'));
        assert!(!Boundary::Letter.matches(b'0'));
    }
}
