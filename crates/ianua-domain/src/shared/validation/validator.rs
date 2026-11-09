use std::ops::RangeInclusive;

use crate::message;
use crate::shared::validation::boundary::Boundary;
use crate::shared::validation::charset::{Charset, CharsetUnion};
use crate::shared::validation::error::ValidationError;
use crate::shared::validation::host_check::{
    domain_label_problem, host_problem, unusual_ipv4_problem,
};
use crate::shared::validation::rule::Rule;

/// A chain of checks on one piece of text.
///
/// Every value object in the domain validates through it, such as
/// `TenantSlug`, `Email` and `DisplayName`. So each check is written once.
///
/// Methods cover the common checks, such as length, charset and boundary.
/// [`rule`](Self::rule) takes any [`Rule`] for a check particular to one
/// value.
///
/// # Safety considerations
///
/// - Put [`max_bytes`](Self::max_bytes) first on user-facing inputs. Then a
///   huge payload is refused before any costly check runs.
/// - [`charset`](Self::charset) and [`boundaries`](Self::boundaries) look at
///   raw bytes and are meant for ASCII-only fields. Put
///   [`ascii_only`](Self::ascii_only) before them, so multi-byte UTF-8 gets
///   a clear error.
/// - [`length`](Self::length) counts bytes. Use
///   [`char_length`](Self::char_length) to count Unicode scalar values.
///
/// # Examples
///
/// ```
/// # use ianua_domain::shared::validation::{Validator, Charset, Boundary};
/// let errors = Validator::new("slug", "acme")
///     .ascii_only()
///     .length(2..=63)
///     .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
///     .boundaries(Boundary::Alphanumeric)
///     .validate();
///
/// assert!(errors.is_empty());
/// ```
pub struct Validator<'a> {
    pub(crate) field: &'static str,
    pub(crate) value: &'a str,
    pub(crate) errors: Vec<ValidationError>,
}

impl<'a> Validator<'a> {
    /// Starts a chain of checks on `value`.
    ///
    /// Every error this chain produces carries `field`, so the API layer
    /// knows which input failed without extra mapping.
    #[must_use]
    pub fn new(field: &'static str, value: &'a str) -> Self {
        Self {
            field,
            value,
            errors: Vec::new(),
        }
    }

    /// Refuses input longer than `limit` bytes.
    ///
    /// Put this first in the chain on user-facing inputs. Then a huge
    /// payload is refused before any costly check runs. Callers pass the
    /// limit themselves. No caller passes
    /// [`ValidationLimits::max_input_bytes`](crate::shared::config::ValidationLimits)
    /// into it.
    #[must_use]
    pub fn max_bytes(mut self, limit: usize) -> Self {
        if self.value.len() > limit {
            self.errors.push(ValidationError::Length {
                field: self.field,
                min: 0,
                max: limit,
                actual: self.value.len(),
            });
        }
        self
    }

    /// Requires the length in bytes to fall inside `range`, both ends
    /// included.
    ///
    /// For ASCII-only fields such as slugs and identifiers, bytes and
    /// characters are the same count. For fields that may hold Unicode, use
    /// [`char_length`](Self::char_length).
    #[must_use]
    pub fn length(mut self, range: RangeInclusive<usize>) -> Self {
        let actual = self.value.len();
        if !range.contains(&actual) {
            self.errors.push(ValidationError::Length {
                field: self.field,
                min: *range.start(),
                max: *range.end(),
                actual,
            });
        }
        self
    }

    /// Requires the number of Unicode scalar values to fall inside `range`,
    /// both ends included.
    ///
    /// Use this in place of [`length`](Self::length) where people may type
    /// non-ASCII text, such as display names and descriptions. A character
    /// like `"é"` counts as 1, though UTF-8 spends more than one byte on it.
    #[must_use]
    pub fn char_length(mut self, range: RangeInclusive<usize>) -> Self {
        let actual = self.value.chars().count();
        if !range.contains(&actual) {
            self.errors.push(ValidationError::Length {
                field: self.field,
                min: *range.start(),
                max: *range.end(),
                actual,
            });
        }
        self
    }

    /// Refuses empty input.
    #[must_use]
    pub fn not_empty(mut self) -> Self {
        if self.value.is_empty() {
            self.errors
                .push(ValidationError::Empty { field: self.field });
        }
        self
    }

    /// Refuses input that is empty or holds nothing but whitespace.
    #[must_use]
    pub fn not_blank(mut self) -> Self {
        if self.value.trim().is_empty() {
            self.errors
                .push(ValidationError::Empty { field: self.field });
        }
        self
    }

    /// Requires every byte to be ASCII, from 0x00 to 0x7F.
    ///
    /// Put this before [`charset`](Self::charset) or
    /// [`boundaries`](Self::boundaries) on fields that must be pure ASCII.
    /// Without it, the byte-level charset check refuses multi-byte UTF-8
    /// with a confusing "invalid characters" error. This one says "must be
    /// ASCII".
    #[must_use]
    pub fn ascii_only(mut self) -> Self {
        if !self.value.is_ascii() {
            self.errors
                .push(ValidationError::NotAscii { field: self.field });
        }
        self
    }

    /// Requires every byte to be one that `allowed` takes.
    ///
    /// It reads raw bytes. On ASCII-only fields, put
    /// [`ascii_only`](Self::ascii_only) first for a clearer error.
    #[must_use]
    // By value so callers write `.charset(A | B)` with the union built in
    // place; a reference would make every caller borrow a temporary.
    #[allow(clippy::needless_pass_by_value)]
    pub fn charset(mut self, allowed: CharsetUnion) -> Self {
        let all_valid = self.value.bytes().all(|b| allowed.matches(b));
        if !all_valid {
            self.errors.push(ValidationError::InvalidCharacters {
                field: self.field,
                allowed: allowed.description(),
            });
        }
        self
    }

    /// Requires every byte to be one that the single charset `allowed` takes.
    ///
    /// It reads raw bytes. On ASCII-only fields, put
    /// [`ascii_only`](Self::ascii_only) first for a clearer error.
    #[must_use]
    pub fn charset_single(mut self, allowed: Charset) -> Self {
        let all_valid = self.value.bytes().all(|b| allowed.matches(b));
        if !all_valid {
            self.errors.push(ValidationError::InvalidCharacters {
                field: self.field,
                allowed: allowed.description().to_owned(),
            });
        }
        self
    }

    /// Requires the first and last characters to fit `boundary`.
    ///
    /// Empty input passes this check. Use [`not_empty`](Self::not_empty) to
    /// refuse it.
    #[must_use]
    pub fn boundaries(mut self, boundary: Boundary) -> Self {
        if self.value.is_empty() {
            return self;
        }

        let bytes = self.value.as_bytes();
        let start_ok = bytes.first().is_some_and(|&b| boundary.matches(b));
        let end_ok = bytes.last().is_some_and(|&b| boundary.matches(b));

        if !start_ok || !end_ok {
            self.errors.push(ValidationError::InvalidBoundary {
                field: self.field,
                expected: boundary.description(),
            });
        }
        self
    }

    /// Refuses input with `byte` twice in a row.
    ///
    /// For example `..` in an email or `--` in a slug.
    #[must_use]
    pub fn no_consecutive(mut self, byte: u8) -> Self {
        let has_consecutive = self
            .value
            .as_bytes()
            .windows(2)
            .any(|pair| pair == [byte, byte]);

        if has_consecutive {
            self.errors.push(ValidationError::Custom {
                field: self.field,
                code: "consecutive_character".to_owned(),
                message: message!(
                    "values-must-not-contain-consecutive-characters",
                    format!(
                        "{} must not contain consecutive '{}' characters.",
                        self.field,
                        char::from(byte)
                    )
                ),
            });
        }
        self
    }

    /// Requires `byte` to appear exactly once.
    ///
    /// For example the one `@` in an email address.
    #[must_use]
    pub fn contains_once(mut self, byte: u8) -> Self {
        let count = self.value.bytes().filter(|&b| b == byte).count();

        if count != 1 {
            self.errors.push(ValidationError::Custom {
                field: self.field,
                code: "invalid_format".to_owned(),
                message: message!(
                    "values-must-contain-exactly-one-character",
                    format!(
                        "{} must contain exactly one '{}' character.",
                        self.field,
                        char::from(byte)
                    )
                ),
            });
        }
        self
    }

    /// Checks each label of a domain name, the parts between its dots.
    ///
    /// The rules:
    /// - at least one dot exists, so there are at least two labels
    /// - each label is 1 to 63 characters, the DNS limit
    /// - no label starts or ends with a hyphen
    /// - no label is empty, so no leading, trailing or consecutive dots
    /// - a name ending in a number is an ordinary IPv4 address, since
    ///   resolvers read `127.1` or `0x7f.0.0.1` as one
    #[must_use]
    pub fn domain_labels(mut self) -> Self {
        let problem = if self.value.contains('.') {
            self.value
                .split('.')
                .find_map(domain_label_problem)
                .or_else(|| unusual_ipv4_problem(self.value))
        } else {
            Some("must contain at least one dot (e.g. example.com)")
        };
        let Some(problem) = problem else {
            return self;
        };
        self.errors.push(ValidationError::Custom {
            field: self.field,
            code: "invalid_domain".to_owned(),
            message: message!("values-message", format!("{} {problem}.", self.field)),
        });
        self
    }

    /// Checks a host to connect to: an IP address written the ordinary way,
    /// or a DNS name of one or more labels.
    ///
    /// A link-local IPv6 address may carry a `%zone`. A name's labels are 1 to 63 letters, digits and hyphens, not starting
    /// or ending with a hyphen. A name ending in a number must be an ordinary
    /// IPv4 address, for the reason given on
    /// [`domain_labels`](Self::domain_labels).
    #[must_use]
    pub fn host_name(mut self) -> Self {
        let Some(problem) = host_problem(self.value) else {
            return self;
        };
        self.errors.push(ValidationError::Custom {
            field: self.field,
            code: "invalid_host".to_owned(),
            message: message!("values-message", format!("{} {problem}.", self.field)),
        });
        self
    }

    /// Refuses characters that change how text renders without being seen:
    /// bidirectional overrides, zero-width and tag characters.
    #[must_use]
    pub fn no_invisible_chars(mut self) -> Self {
        if self
            .value
            .chars()
            .any(crate::shared::validation::invisible::is_invisible)
        {
            self.errors.push(ValidationError::Custom {
                field: self.field,
                code: "invisible_characters".to_owned(),
                message: message!("values-must-not-contain-invisible-characters-bidirectional", format!(
                    "{} must not contain invisible characters (bidirectional overrides, zero-width or tag characters).",
                    self.field
                )),
            });
        }
        self
    }

    /// Refuses ASCII control characters, 0x00 to 0x1F and 0x7F.
    ///
    /// Printable ASCII and any non-ASCII text, such as accents, CJK or emoji,
    /// pass. Use this for free text where Unicode is fine but null bytes,
    /// tabs, carriage returns and escape sequences are not.
    #[must_use]
    pub fn no_control_chars(mut self) -> Self {
        let has_control = self.value.bytes().any(|b| b.is_ascii_control());

        if has_control {
            self.errors.push(ValidationError::Custom {
                field: self.field,
                code: "control_characters".to_owned(),
                message: message!("values-must-not-contain-control-characters-null", format!(
                    "{} must not contain control characters (null bytes, tabs, escape sequences).",
                    self.field
                )),
            });
        }
        self
    }

    /// Refuses ASCII control characters other than line breaks.
    ///
    /// For text written over several lines, such as a plain-text email body.
    #[must_use]
    pub fn no_control_chars_but_line_breaks(mut self) -> Self {
        let has_control = self
            .value
            .bytes()
            .any(|b| b.is_ascii_control() && !matches!(b, b'\n' | b'\r'));
        if has_control {
            self.errors.push(ValidationError::Custom {
                field: self.field,
                code: "control_characters".to_owned(),
                message: message!(
                    "values-must-not-contain-control-characters-other",
                    format!(
                        "{} must not contain control characters other than line breaks.",
                        self.field
                    )
                ),
            });
        }
        self
    }

    /// Refuses any whitespace, such as spaces, tabs and line breaks.
    ///
    /// For values a protocol treats as a single token, where a space would
    /// split it into two.
    #[must_use]
    pub fn no_whitespace(mut self) -> Self {
        if self.value.chars().any(char::is_whitespace) {
            self.errors.push(ValidationError::Custom {
                field: self.field,
                code: "whitespace".to_owned(),
                message: message!(
                    "values-must-not-contain-spaces-or-line",
                    format!("{} must not contain spaces or line breaks.", self.field)
                ),
            });
        }
        self
    }

    /// Refuses a backslash.
    ///
    /// Some URL and path readers treat it as a slash and others do not.
    #[must_use]
    pub fn no_backslash(mut self) -> Self {
        if self.value.contains('\\') {
            self.errors.push(ValidationError::Custom {
                field: self.field,
                code: "backslash".to_owned(),
                message: message!(
                    "values-must-not-contain-a-backslash",
                    format!("{} must not contain a backslash.", self.field)
                ),
            });
        }
        self
    }

    /// Runs one [`Rule`].
    ///
    /// For a check particular to one value, such as the shape of a hex
    /// color. The rule gets the field name and the value.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// Validator::new("color", "#1a2b3c")
    ///     .rule(&HexColorShape)
    ///     .validate_first()?;
    /// ```
    #[must_use]
    pub fn rule(mut self, rule: &dyn Rule) -> Self {
        if let Some(err) = rule.check(self.field, self.value) {
            self.errors.push(err);
        }
        self
    }

    /// Runs several [`Rule`]s in order.
    #[must_use]
    pub fn rules(mut self, rules: &[&dyn Rule]) -> Self {
        for rule in rules {
            if let Some(err) = rule.check(self.field, self.value) {
                self.errors.push(err);
            }
        }
        self
    }

    /// Every error from the chain. Empty when the input passed every rule.
    ///
    /// For reporting all problems at once.
    #[must_use]
    pub fn validate(self) -> Vec<ValidationError> {
        self.errors
    }

    /// Fails with the first error from the chain, if any.
    ///
    /// For value object constructors, where one error is enough.
    ///
    /// # Errors
    ///
    /// - The first [`ValidationError`] in the chain.
    pub fn validate_first(self) -> Result<(), ValidationError> {
        match self.errors.into_iter().next() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slug `acme` passes ASCII, length, charset and boundary checks
    /// with no errors.
    #[test]
    fn valid_ascii_input_passes_all_checks() {
        let errors = Validator::new("slug", "acme")
            .ascii_only()
            .length(2..=63)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
            .boundaries(Boundary::Alphanumeric)
            .validate();

        assert!(errors.is_empty());
    }

    /// The display name `José García` passes a check of 1 to 100 characters.
    #[test]
    fn valid_unicode_input_with_char_length() {
        let errors = Validator::new("display_name", "José García")
            .not_empty()
            .char_length(1..=100)
            .validate();

        assert!(errors.is_empty());
    }

    /// A one-letter slug under a minimum of 2 is refused. The message ends
    /// "You provided 1 character", in the singular.
    #[test]
    fn too_short_reports_friendly_singular_message() {
        let err = Validator::new("slug", "a")
            .length(2..=63)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.field(), Some("slug"));
        assert_eq!(err.code(), "invalid_length");
        assert_eq!(
            err.to_string(),
            "slug must be between 2 and 63 characters long. You provided 1 character."
        );
    }

    /// A 64-letter slug over a maximum of 63 is refused. The message says
    /// "You provided 64 characters", in the plural.
    #[test]
    fn too_long_reports_friendly_plural_message() {
        let long = "a".repeat(64);
        let err = Validator::new("slug", &long)
            .length(2..=63)
            .validate_first()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "slug must be between 2 and 63 characters long. You provided 64 characters."
        );
    }

    /// With a range of 2 to 4, both `ab` and `abcd` pass. Both ends of the
    /// range are included.
    #[test]
    fn exact_boundary_lengths_pass() {
        assert!(
            Validator::new("x", "ab")
                .length(2..=4)
                .validate()
                .is_empty()
        );
        assert!(
            Validator::new("x", "abcd")
                .length(2..=4)
                .validate()
                .is_empty()
        );
    }

    /// An empty slug under a minimum of 1 fails the length check with
    /// `invalid_length`, even with no `not_empty` in the chain.
    #[test]
    fn zero_length_input_with_length_check() {
        let err = Validator::new("slug", "")
            .length(1..=63)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "invalid_length");
    }

    /// `café` is five bytes but four characters. A limit of 4 passes it by
    /// character count and refuses it by byte count.
    #[test]
    fn char_length_counts_unicode_scalars_not_bytes() {
        let value = "café";
        assert_eq!(value.len(), 5);
        assert_eq!(value.chars().count(), 4);

        assert!(
            Validator::new("name", value)
                .char_length(1..=4)
                .validate()
                .is_empty()
        );

        let err = Validator::new("name", value)
            .length(1..=4)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "invalid_length");
    }

    /// Three Japanese characters count as three and pass a limit of 10.
    #[test]
    fn char_length_handles_cjk_characters() {
        let value = "日本語";
        assert_eq!(value.chars().count(), 3);

        assert!(
            Validator::new("name", value)
                .char_length(1..=10)
                .validate()
                .is_empty()
        );
    }

    /// `hello` with a space and two emoji counts as eight characters and
    /// passes a limit of 10.
    #[test]
    fn char_length_handles_emoji() {
        let value = "hello 👋🌍";
        assert_eq!(value.chars().count(), 8);

        assert!(
            Validator::new("bio", value)
                .char_length(1..=10)
                .validate()
                .is_empty()
        );
    }

    /// `café` fails the ASCII check with `not_ascii` and a message asking to
    /// remove special or international characters.
    #[test]
    fn ascii_only_rejects_multibyte_utf8() {
        let err = Validator::new("slug", "café")
            .ascii_only()
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "not_ascii");
        assert_eq!(
            err.to_string(),
            "slug must contain only ASCII characters. \
             Please remove any special or international characters."
        );
    }

    /// `hello` followed by an emoji fails the ASCII check.
    #[test]
    fn ascii_only_rejects_emoji() {
        let err = Validator::new("slug", "hello👋")
            .ascii_only()
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "not_ascii");
    }

    /// An embedded zero-width space fails ASCII validation.
    #[test]
    fn ascii_only_rejects_zero_width_space() {
        let err = Validator::new("slug", "ab\u{200B}cd")
            .ascii_only()
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "not_ascii");
    }

    /// A no-break space looks like a plain space but is not ASCII. The ASCII
    /// check refuses it.
    #[test]
    fn ascii_only_rejects_nbsp() {
        let err = Validator::new("slug", "ab\u{00A0}cd")
            .ascii_only()
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "not_ascii");
    }

    /// `hello-world-123` is all ASCII and passes.
    #[test]
    fn ascii_only_passes_pure_ascii() {
        assert!(
            Validator::new("slug", "hello-world-123")
                .ascii_only()
                .validate()
                .is_empty()
        );
    }

    /// `ACME` fails a lowercase-and-digits charset with
    /// `invalid_characters`, and the message lists what is allowed.
    #[test]
    fn charset_rejects_invalid_characters() {
        let err = Validator::new("slug", "ACME")
            .charset(Charset::LOWERCASE | Charset::DIGIT)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "invalid_characters");
        assert_eq!(
            err.to_string(),
            "slug can only contain lowercase letters, digits. \
             Please remove any other characters."
        );
    }

    /// `abc123` fails a digits-only charset given as one set, not a union.
    #[test]
    fn charset_single_works_standalone() {
        let err = Validator::new("code", "abc123")
            .charset_single(Charset::DIGIT)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "invalid_characters");
    }

    /// A null byte inside a slug fails the charset check, even with no
    /// control-character check in the chain.
    #[test]
    fn charset_rejects_control_characters() {
        let err = Validator::new("slug", "abc\x00def")
            .charset(Charset::LOWERCASE | Charset::DIGIT)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "invalid_characters");
    }

    /// A tab or a line feed in a slug fails a lowercase-and-digits charset.
    #[test]
    fn charset_rejects_tab_and_newline() {
        assert!(
            Validator::new("slug", "abc\tdef")
                .charset(Charset::LOWERCASE | Charset::DIGIT)
                .validate_first()
                .is_err()
        );
        assert!(
            Validator::new("slug", "abc\ndef")
                .charset(Charset::LOWERCASE | Charset::DIGIT)
                .validate_first()
                .is_err()
        );
    }

    /// Every lowercase letter, every digit and a hyphen together pass the
    /// slug charset.
    #[test]
    fn charset_accepts_all_valid_characters() {
        let all_valid = "abcdefghijklmnopqrstuvwxyz0123456789-";
        assert!(
            Validator::new("slug", all_valid)
                .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
                .validate()
                .is_empty()
        );
    }

    /// `-acme` fails the alphanumeric boundary with `invalid_boundary` and a
    /// message saying how the slug must start and end.
    #[test]
    fn boundaries_rejects_leading_hyphen() {
        let err = Validator::new("slug", "-acme")
            .boundaries(Boundary::Alphanumeric)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "invalid_boundary");
        assert_eq!(
            err.to_string(),
            "slug must start and end with an alphanumeric character."
        );
    }

    /// `acme-` fails the alphanumeric boundary at its last character.
    #[test]
    fn boundaries_rejects_trailing_hyphen() {
        assert!(
            Validator::new("slug", "acme-")
                .boundaries(Boundary::Alphanumeric)
                .validate_first()
                .is_err()
        );
    }

    /// An empty value passes the boundary check, which leaves emptiness to
    /// `not_empty`.
    #[test]
    fn boundaries_skips_empty_input() {
        let errors = Validator::new("slug", "")
            .boundaries(Boundary::Alphanumeric)
            .validate();

        assert!(errors.is_empty());
    }

    /// A one-character value is its own first and last character. `a`
    /// passes and `-` fails.
    #[test]
    fn boundaries_single_character_checks_both_ends() {
        assert!(
            Validator::new("x", "a")
                .boundaries(Boundary::Alphanumeric)
                .validate()
                .is_empty()
        );
        assert!(
            Validator::new("x", "-")
                .boundaries(Boundary::Alphanumeric)
                .validate_first()
                .is_err()
        );
    }

    /// An empty email fails with `required` and the message "email is
    /// required and cannot be left blank."
    #[test]
    fn not_empty_rejects_empty_string() {
        let err = Validator::new("email", "")
            .not_empty()
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "required");
        assert_eq!(
            err.to_string(),
            "email is required and cannot be left blank."
        );
    }

    /// Three spaces pass `not_empty`. Refusing blank text is the job of
    /// `not_blank`.
    #[test]
    fn not_empty_accepts_whitespace_only() {
        assert!(
            Validator::new("field", "   ")
                .not_empty()
                .validate()
                .is_empty()
        );
    }

    /// The slug `-` breaks length, charset and boundary. `validate` returns
    /// all three errors, not only the first.
    #[test]
    fn collects_all_errors_from_chain() {
        let errors = Validator::new("slug", "-")
            .length(2..=63)
            .charset(Charset::LOWERCASE | Charset::DIGIT)
            .boundaries(Boundary::Alphanumeric)
            .validate();

        assert_eq!(errors.len(), 3);

        let codes: Vec<&str> = errors
            .iter()
            .map(crate::shared::validation::ValidationError::code)
            .collect();
        assert!(codes.contains(&"invalid_length"));
        assert!(codes.contains(&"invalid_characters"));
        assert!(codes.contains(&"invalid_boundary"));
    }

    /// An empty slug breaks `not_empty` and then `length`. `validate_first`
    /// returns `required`, the check that ran first.
    #[test]
    fn validate_first_returns_earliest_failure() {
        let err = Validator::new("slug", "")
            .not_empty()
            .length(2..=63)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "required");
    }

    /// With `not_empty` before `boundaries`, an empty slug is reported as
    /// `required`, the clearest error for it.
    #[test]
    fn empty_input_with_not_empty_before_boundaries_gives_clear_error() {
        let err = Validator::new("slug", "")
            .not_empty()
            .boundaries(Boundary::Alphanumeric)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "required");
    }

    /// `café` checked with `ascii_only` then a charset gives two errors, with
    /// `not_ascii` first.
    #[test]
    fn ascii_guard_before_charset_gives_clear_error_for_unicode() {
        let errors = Validator::new("slug", "café")
            .ascii_only()
            .charset(Charset::LOWERCASE | Charset::DIGIT)
            .validate();

        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].code(), "not_ascii");
        assert_eq!(errors[1].code(), "invalid_characters");
    }

    /// For the same chain, `validate_first` reports `not_ascii`, the message
    /// that tells the person what to fix.
    #[test]
    fn ascii_guard_first_reports_ascii_error_not_charset() {
        let err = Validator::new("slug", "café")
            .ascii_only()
            .charset(Charset::LOWERCASE | Charset::DIGIT)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "not_ascii");
    }

    /// A 1,001-byte value exceeds a 1,000-byte maximum and returns `invalid_length`.
    #[test]
    fn max_bytes_rejects_oversized_input() {
        let huge = "a".repeat(1001);
        let err = Validator::new("slug", &huge)
            .max_bytes(1000)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.code(), "invalid_length");
    }

    /// Exactly 1,000 bytes passes a limit of 1,000.
    #[test]
    fn max_bytes_accepts_input_at_limit() {
        let exact = "a".repeat(1000);
        let errors = Validator::new("slug", &exact).max_bytes(1000).validate();

        assert!(errors.is_empty());
    }

    /// A chain with no checks passes 10,000 bytes. No size limit applies
    /// unless one is added.
    #[test]
    fn no_max_bytes_allows_any_size() {
        let large = "a".repeat(10_000);
        let errors = Validator::new("slug", &large).validate();

        assert!(errors.is_empty());
    }

    /// A rule that refuses everything adds its own error. The error names
    /// the chain's field and keeps the rule's code and message.
    #[test]
    fn custom_rule_integrates_with_chain() {
        struct RejectAll;

        impl Rule for RejectAll {
            fn check(&self, field: &'static str, _value: &str) -> Option<ValidationError> {
                Some(ValidationError::Custom {
                    field,
                    code: "always_rejected".to_owned(),
                    message: "This value is not accepted.".into(),
                })
            }
        }

        let err = Validator::new("test", "anything")
            .rule(&RejectAll)
            .validate_first()
            .unwrap_err();

        assert_eq!(err.field(), Some("test"));
        assert_eq!(err.code(), "always_rejected");
        assert_eq!(err.to_string(), "This value is not accepted.");
    }

    /// A rule that accepts everything adds no error.
    #[test]
    fn passing_rule_adds_no_errors() {
        struct AcceptAll;

        impl Rule for AcceptAll {
            fn check(&self, _field: &'static str, _value: &str) -> Option<ValidationError> {
                None
            }
        }

        assert!(
            Validator::new("test", "anything")
                .rule(&AcceptAll)
                .validate()
                .is_empty()
        );
    }

    /// A fixture rule that rejects text without an ASCII digit.
    struct MustContainDigit;

    impl Rule for MustContainDigit {
        fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
            if value.bytes().any(|b| b.is_ascii_digit()) {
                return None;
            }
            Some(ValidationError::Custom {
                field,
                code: "missing_digit".to_owned(),
                message: format!("{field} must contain at least one digit.").into(),
            })
        }
    }

    /// A fixture rule that rejects text without an ASCII letter.
    struct MustContainLetter;

    impl Rule for MustContainLetter {
        fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
            if value.bytes().any(|b| b.is_ascii_alphabetic()) {
                return None;
            }
            Some(ValidationError::Custom {
                field,
                code: "missing_letter".to_owned(),
                message: format!("{field} must contain at least one letter.").into(),
            })
        }
    }

    /// `1234` is checked by a digit rule and a letter rule. Only the letter
    /// rule fails, so there is one error, `missing_letter`.
    #[test]
    fn rules_method_applies_multiple_rules_in_order() {
        let digit_rule = MustContainDigit;
        let letter_rule = MustContainLetter;

        let errors = Validator::new("password", "1234")
            .rules(&[&digit_rule, &letter_rule])
            .validate();

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code(), "missing_letter");
    }

    /// The length, empty, charset, boundary and ASCII checks fail with the
    /// codes clients match on: `invalid_length`, `required`,
    /// `invalid_characters`, `invalid_boundary` and `not_ascii`.
    #[test]
    fn all_built_in_codes_are_stable() {
        let length = Validator::new("x", "")
            .length(1..=5)
            .validate_first()
            .unwrap_err();
        let empty = Validator::new("x", "")
            .not_empty()
            .validate_first()
            .unwrap_err();
        let chars = Validator::new("x", "!")
            .charset_single(Charset::LOWERCASE)
            .validate_first()
            .unwrap_err();
        let boundary = Validator::new("x", "-a")
            .boundaries(Boundary::Alphanumeric)
            .validate_first()
            .unwrap_err();
        let ascii = Validator::new("x", "é")
            .ascii_only()
            .validate_first()
            .unwrap_err();

        assert_eq!(length.code(), "invalid_length");
        assert_eq!(empty.code(), "required");
        assert_eq!(chars.code(), "invalid_characters");
        assert_eq!(boundary.code(), "invalid_boundary");
        assert_eq!(ascii.code(), "not_ascii");
    }

    /// A slug of three spaces passes `not_empty` but fails the charset. The
    /// one error is `invalid_characters`.
    #[test]
    fn only_whitespace_passes_not_empty_but_fails_ascii_charset() {
        let errors = Validator::new("slug", "   ")
            .not_empty()
            .charset(Charset::LOWERCASE | Charset::DIGIT)
            .validate();

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code(), "invalid_characters");
    }

    /// A null byte at the end of a slug fails the charset check.
    #[test]
    fn null_byte_rejected_by_charset() {
        assert!(
            Validator::new("slug", "abc\x00")
                .charset(Charset::LOWERCASE | Charset::DIGIT)
                .validate_first()
                .is_err()
        );
    }

    /// `valid-INVALID` starts with allowed characters, but its uppercase
    /// tail fails the whole value.
    #[test]
    fn mixed_valid_and_invalid_still_fails() {
        assert!(
            Validator::new("slug", "valid-INVALID")
                .charset(Charset::LOWERCASE | Charset::HYPHEN)
                .validate_first()
                .is_err()
        );
    }

    /// Two single charsets in a row, lowercase then digit, each fail
    /// `abc-123` on their own. Chaining them is not a union.
    #[test]
    fn chaining_multiple_charsets_applies_both_independently() {
        let errors = Validator::new("x", "abc-123")
            .charset_single(Charset::LOWERCASE)
            .charset_single(Charset::DIGIT)
            .validate();

        assert_eq!(errors.len(), 2);
    }

    /// A chain with no checks returns no errors from `validate`.
    #[test]
    fn validate_on_empty_chain_passes() {
        assert!(Validator::new("x", "anything").validate().is_empty());
    }

    /// A chain with no checks returns `Ok` from `validate_first`.
    #[test]
    fn validate_first_on_empty_chain_passes() {
        assert!(Validator::new("x", "anything").validate_first().is_ok());
    }

    /// Every error from a five-check chain on `my_field` names `my_field`.
    #[test]
    fn field_name_propagates_through_all_rules() {
        let errors = Validator::new("my_field", "-")
            .not_empty()
            .length(2..=10)
            .ascii_only()
            .charset(Charset::LOWERCASE | Charset::DIGIT)
            .boundaries(Boundary::Alphanumeric)
            .validate();

        for err in &errors {
            assert_eq!(err.field(), Some("my_field"));
        }
    }

    fn domain_errors(value: &str) -> Vec<ValidationError> {
        Validator::new("domain", value).domain_labels().validate()
    }

    /// `auth.acme.com` and `acme.com` pass the domain label check.
    #[test]
    fn a_hostname_with_ordinary_labels_passes() {
        assert!(domain_errors("auth.acme.com").is_empty());
        assert!(domain_errors("acme.com").is_empty());
    }

    /// A first label of 63 characters passes and one of 64 is refused. DNS
    /// allows 63, so a name a registrar accepted is accepted here too.
    #[test]
    fn a_label_of_sixty_three_characters_is_allowed_and_sixty_four_is_not() {
        let longest = "a".repeat(63);
        assert!(domain_errors(&format!("{longest}.com")).is_empty());

        let too_long = "a".repeat(64);
        assert!(!domain_errors(&format!("{too_long}.com")).is_empty());
    }

    /// `localhost` has no dot, so the domain label check refuses it.
    #[test]
    fn a_hostname_without_a_dot_is_refused() {
        assert!(!domain_errors("localhost").is_empty());
    }

    /// A leading dot, two dots in a row and a trailing dot each leave an
    /// empty label, and each is refused.
    #[test]
    fn an_empty_label_is_refused() {
        for value in [".acme.com", "acme..com", "acme.com."] {
            assert!(!domain_errors(value).is_empty(), "{value}");
        }
    }

    /// A label that starts or ends with a hyphen, first or later in the
    /// name, is refused.
    #[test]
    fn a_label_bounded_by_a_hyphen_is_refused() {
        for value in ["-acme.com", "acme-.com", "auth.-acme.com"] {
            assert!(!domain_errors(value).is_empty(), "{value}");
        }
    }

    /// `a\b` is refused by `no_backslash`, and `a/b` passes it.
    #[test]
    fn a_backslash_is_refused() {
        assert!(
            Validator::new("v", "a\\b")
                .no_backslash()
                .validate_first()
                .is_err()
        );
        assert!(
            Validator::new("v", "a/b")
                .no_backslash()
                .validate_first()
                .is_ok()
        );
    }

    fn domain(value: &str) -> Result<(), ValidationError> {
        Validator::new("domain", value)
            .domain_labels()
            .validate_first()
    }

    /// Ambiguous numeric IP spellings fail domain validation, while ordinary
    /// IPv4 and a hostname containing a digit remain valid.
    #[test]
    fn a_name_ending_in_a_number_must_be_an_ordinary_address() {
        assert!(domain("192.0.2.1").is_ok());
        assert!(domain("v2.acme.com").is_ok());
        for value in [
            "127.1",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "1.2.3.4.5",
            "acme.0x10",
        ] {
            assert!(domain(value).is_err(), "{value} was accepted");
        }
    }

    /// A count error with no upper bound says "at least 1 entry". One with
    /// both bounds says "between 1 and 20 entries". Each says how many were
    /// listed.
    #[test]
    fn a_count_error_says_how_many_entries_are_allowed() {
        let unbounded = ValidationError::Count {
            field: "hosts",
            min: 1,
            max: usize::MAX,
            actual: 0,
        };
        let bounded = ValidationError::Count {
            field: "hosts",
            min: 1,
            max: 20,
            actual: 21,
        };

        assert_eq!(
            unbounded.to_string(),
            "hosts must list at least 1 entry. You listed 0."
        );
        assert_eq!(
            bounded.to_string(),
            "hosts must list between 1 and 20 entries. You listed 21."
        );
    }

    fn host(value: &str) -> bool {
        Validator::new("host", value)
            .host_name()
            .validate_first()
            .is_ok()
    }

    /// A single-label name, a dotted name, an IPv4 address, an IPv6 address
    /// and a link-local IPv6 address with a zone are all valid hosts.
    #[test]
    fn a_name_or_an_ordinary_address_is_a_host() {
        for value in [
            "redis",
            "db.internal",
            "10.0.0.5",
            "fd00::1",
            "fe80::1%eth0",
        ] {
            assert!(host(value), "{value} was refused");
        }
    }

    /// Host validation rejects control characters in zones, short IPv4 forms,
    /// whitespace, slashes, brackets, and zones on non-link-local addresses.
    #[test]
    fn a_host_written_so_readers_disagree_is_refused() {
        for value in [
            "",
            "127.1",
            "0x7f.0.0.1",
            "db internal",
            "-db",
            "db..internal",
            "db/x",
            "[::1]",
            "fe80::1%x\r\nfoo",
            "fe80::1%eth0/admin",
            "fe80::1%",
            "fd00::1%eth0",
            "2001:db8::1%1",
        ] {
            assert!(!host(value), "{value:?} was accepted");
        }
    }
}
