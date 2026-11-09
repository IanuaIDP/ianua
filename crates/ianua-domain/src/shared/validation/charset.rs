/// A set of bytes a string may hold.
///
/// Join charsets with `|` to get a [`CharsetUnion`], which takes a byte that
/// any member takes.
///
/// # Examples
///
/// ```
/// # use ianua_domain::shared::validation::Charset;
/// let slug_chars = Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN;
/// assert!(slug_chars.matches(b'a'));
/// assert!(slug_chars.matches(b'5'));
/// assert!(!slug_chars.matches(b'A'));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Charset {
    test: fn(u8) -> bool,
    description: &'static str,
}

impl Charset {
    /// Lowercase ASCII letters (`a-z`).
    pub const LOWERCASE: Self = Self {
        test: |b| b.is_ascii_lowercase(),
        description: "lowercase letters",
    };

    /// Uppercase ASCII letters (`A-Z`).
    pub const UPPERCASE: Self = Self {
        test: |b| b.is_ascii_uppercase(),
        description: "uppercase letters",
    };

    /// ASCII digits (`0-9`).
    pub const DIGIT: Self = Self {
        test: |b| b.is_ascii_digit(),
        description: "digits",
    };

    /// The hyphen character (`-`).
    pub const HYPHEN: Self = Self {
        test: |b| b == b'-',
        description: "hyphens",
    };

    /// The dot character (`.`).
    pub const DOT: Self = Self {
        test: |b| b == b'.',
        description: "dots",
    };

    /// The underscore character (`_`).
    pub const UNDERSCORE: Self = Self {
        test: |b| b == b'_',
        description: "underscores",
    };

    /// The at sign (`@`).
    pub const AT: Self = Self {
        test: |b| b == b'@',
        description: "at sign",
    };

    /// The plus sign (`+`).
    pub const PLUS: Self = Self {
        test: |b| b == b'+',
        description: "plus sign",
    };

    /// The asterisk (`*`), often a wildcard.
    pub const ASTERISK: Self = Self {
        test: |b| b == b'*',
        description: "asterisk",
    };

    /// The colon (`:`), used as a separator in scopes and permissions.
    pub const COLON: Self = Self {
        test: |b| b == b':',
        description: "colons",
    };

    /// The slash (`/`), the separator between URL path segments.
    pub const SLASH: Self = Self {
        test: |b| b == b'/',
        description: "slashes",
    };

    /// The tilde (`~`), an unreserved URL character.
    pub const TILDE: Self = Self {
        test: |b| b == b'~',
        description: "tildes",
    };

    /// The lowercase letters a hex digit may be (`a-f`).
    pub const HEX_LETTER: Self = Self {
        test: |b| matches!(b, b'a'..=b'f'),
        description: "hex letters a-f",
    };

    /// The symbols an HTTP token may hold besides letters and digits:
    /// ``!#$%&'*+-.^_`|~``.
    ///
    /// The list is from RFC 9110 section 5.6.2.
    pub const HTTP_TOKEN_SYMBOL: Self = Self {
        test: |b| b"!#$%&'*+-.^_`|~".contains(&b),
        description: "the symbols !#$%&'*+-.^_`|~",
    };

    /// Whether this charset takes `byte`.
    #[must_use]
    pub fn matches(&self, byte: u8) -> bool {
        (self.test)(byte)
    }

    /// The set in words, for an error message.
    #[must_use]
    pub fn description(&self) -> &'static str {
        self.description
    }
}

impl std::ops::BitOr for Charset {
    type Output = CharsetUnion;

    /// A union that takes a byte either charset takes.
    fn bitor(self, rhs: Self) -> CharsetUnion {
        CharsetUnion {
            sets: vec![self, rhs],
        }
    }
}

/// Several [`Charset`]s joined with `|`.
///
/// It takes a byte that any member takes.
#[derive(Debug, Clone)]
pub struct CharsetUnion {
    pub(crate) sets: Vec<Charset>,
}

impl CharsetUnion {
    /// Whether any member takes `byte`.
    #[must_use]
    pub fn matches(&self, byte: u8) -> bool {
        self.sets.iter().any(|cs| cs.matches(byte))
    }

    /// Every member in words, joined by commas, for an error message.
    pub fn description(&self) -> String {
        self.sets
            .iter()
            .map(Charset::description)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl std::ops::BitOr<Charset> for CharsetUnion {
    type Output = CharsetUnion;

    /// The union with one more charset.
    fn bitor(self, rhs: Charset) -> CharsetUnion {
        let mut sets = self.sets;
        sets.push(rhs);
        CharsetUnion { sets }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `a` and `z` are lowercase. `A` and `0` are not.
    #[test]
    fn lowercase_matches_only_lowercase() {
        assert!(Charset::LOWERCASE.matches(b'a'));
        assert!(Charset::LOWERCASE.matches(b'z'));
        assert!(!Charset::LOWERCASE.matches(b'A'));
        assert!(!Charset::LOWERCASE.matches(b'0'));
    }

    /// Each one-character set, such as `HYPHEN` or `AT`, takes its own
    /// character and refuses a letter, digit, space and slash. These decide
    /// what slugs, header names and email local parts may hold.
    #[test]
    fn each_punctuation_set_matches_only_its_own_character() {
        let sets = [
            (Charset::HYPHEN, b'-'),
            (Charset::DOT, b'.'),
            (Charset::COLON, b':'),
            (Charset::UNDERSCORE, b'_'),
            (Charset::AT, b'@'),
            (Charset::PLUS, b'+'),
        ];

        for (charset, own) in sets {
            assert!(charset.matches(own), "{}", charset.description());
            for other in *b"aA0 /" {
                assert!(
                    !charset.matches(other),
                    "{} matched {}",
                    charset.description(),
                    other as char
                );
            }
        }
    }

    /// Lowercase, digit and hyphen joined take `a`, `5` and `-`. They still
    /// refuse `A` and a space, which no member takes.
    #[test]
    fn union_matches_any_member() {
        let union = Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN;
        assert!(union.matches(b'a'));
        assert!(union.matches(b'5'));
        assert!(union.matches(b'-'));
        assert!(!union.matches(b'A'));
        assert!(!union.matches(b' '));
    }

    /// Lowercase joined with digit reads "lowercase letters, digits" in an
    /// error message, in the order they were joined.
    #[test]
    fn union_description_lists_all_members() {
        let union = Charset::LOWERCASE | Charset::DIGIT;
        assert_eq!(union.description(), "lowercase letters, digits");
    }
}
