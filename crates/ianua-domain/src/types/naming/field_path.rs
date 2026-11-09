//! A checked field path with dots, for data classification.
//!
//! It names one field in an API response to classify and redact, such as
//! `"user.ssn"` or `"billing.card_number"`.

use std::fmt;

use crate::message;
use crate::shared::validation::{ValidationError, Validator};

/// The most segments a field path may have.
const MAX_DEPTH: usize = 10;

/// The longest a field path may be, in bytes.
const MAX_LENGTH: usize = 256;

/// A checked field path, with segments joined by dots.
///
/// The rules:
/// - Not empty.
/// - ASCII only.
/// - At most 256 characters.
/// - At most 10 segments.
/// - No empty segments, so `"user..email"` is refused.
/// - Each segment matches `[a-zA-Z_][a-zA-Z0-9_]*`.
/// - No dot at the start or end.
///
/// # Examples
///
/// ```
/// # use ianua_domain::types::FieldPath;
/// let path = FieldPath::new("user.email").unwrap();
/// assert_eq!(path.as_str(), "user.email");
/// assert_eq!(path.segments().count(), 2);
///
/// assert!(FieldPath::new("").is_err());
/// assert!(FieldPath::new("user..email").is_err());
/// assert!(FieldPath::new(".leading").is_err());
/// assert!(FieldPath::new("trailing.").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct FieldPath(String);

impl TryFrom<String> for FieldPath {
    type Error = ValidationError;

    /// Reading JSON goes through [`FieldPath::new`], so a value that arrives
    /// as JSON is held to the same rules as one built in code.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl FieldPath {
    /// A checked field path.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for an empty, non-ASCII or over-256-character path,
    /// more than 10 segments, or any empty or non-identifier segment.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        Validator::new("field_path", &value)
            .not_empty()
            .ascii_only()
            .length(1..=MAX_LENGTH)
            .validate_first()?;
        ensure_segments_valid(&value)?;
        Ok(Self(value))
    }

    /// The checked path as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The segments between the dots, in order.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }

    /// How many segments the path has.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.0.split('.').count()
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// No more than [`MAX_DEPTH`] segments, none empty, each an identifier.
fn ensure_segments_valid(path: &str) -> Result<(), ValidationError> {
    let depth = path.split('.').count();
    if depth > MAX_DEPTH {
        return Err(ValidationError::Custom {
            field: "field_path",
            code: "too_deep".to_owned(),
            message: message!(
                "values-field-path-has-segments-maximum-is",
                format!("field path has {depth} segments, maximum is {MAX_DEPTH}")
            ),
        });
    }
    path.split('.').try_for_each(ensure_segment_valid)
}

fn ensure_segment_valid(segment: &str) -> Result<(), ValidationError> {
    if segment.is_empty() {
        return Err(ValidationError::Custom {
            field: "field_path",
            code: "empty_segment".to_owned(),
            message: message!(
                "values-field-path-must-not-start-or",
                "field path must not start or end with a dot, or contain empty segments"
            ),
        });
    }
    if !is_valid_segment(segment) {
        return Err(ValidationError::Custom {
            field: "field_path",
            code: "invalid_segment".to_owned(),
            message: message!(
                "values-segment-must-match-a-za-z",
                format!("segment \"{segment}\" must match [a-zA-Z_][a-zA-Z0-9_]*")
            ),
        });
    }
    Ok(())
}

/// Whether one segment is an identifier. It starts with a letter or an
/// underscore, and the rest are letters, digits or underscores.
fn is_valid_segment(segment: &str) -> bool {
    let mut chars = segment.chars();

    let Some(first) = chars.next() else {
        return false;
    };

    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `email` is accepted as a path one segment deep.
    #[test]
    fn valid_single_segment() {
        let path = FieldPath::new("email").unwrap();
        assert_eq!(path.as_str(), "email");
        assert_eq!(path.depth(), 1);
    }

    /// `user.profile.address.city` is four segments deep, read back in
    /// order.
    #[test]
    fn valid_multi_segment() {
        let path = FieldPath::new("user.profile.address.city").unwrap();
        assert_eq!(path.depth(), 4);
        let segments: Vec<&str> = path.segments().collect();
        assert_eq!(segments, ["user", "profile", "address", "city"]);
    }

    /// Segments may start with or hold underscores, as in `_private` and
    /// `card_number`.
    #[test]
    fn field_paths_may_contain_underscores() {
        assert!(FieldPath::new("_private").is_ok());
        assert!(FieldPath::new("user._internal_id").is_ok());
        assert!(FieldPath::new("card_number").is_ok());
    }

    /// Empty text is refused where classification requires a field selector.
    #[test]
    fn an_empty_field_path_is_refused() {
        assert!(FieldPath::new("").is_err());
    }

    /// `.user.email` starts with a dot and is refused.
    #[test]
    fn rejects_leading_dot() {
        assert!(FieldPath::new(".user.email").is_err());
    }

    /// `user.email.` ends with a dot and is refused.
    #[test]
    fn rejects_trailing_dot() {
        assert!(FieldPath::new("user.email.").is_err());
    }

    /// `user..email` has an empty segment and is refused.
    #[test]
    fn rejects_empty_segment() {
        assert!(FieldPath::new("user..email").is_err());
    }

    /// `user.0invalid` has a segment starting with a digit and is refused.
    #[test]
    fn rejects_segment_starting_with_digit() {
        assert!(FieldPath::new("user.0invalid").is_err());
    }

    /// `user.first-name` has a hyphen in a segment and is refused.
    #[test]
    fn rejects_segment_with_hyphen() {
        assert!(FieldPath::new("user.first-name").is_err());
    }

    /// `user.first name` has a space in a segment and is refused.
    #[test]
    fn rejects_segment_with_space() {
        assert!(FieldPath::new("user.first name").is_err());
    }

    /// A segment in Japanese is refused as not ASCII.
    #[test]
    fn rejects_non_ascii() {
        assert!(FieldPath::new("user.名前").is_err());
    }

    /// A path of 11 segments is refused as too deep.
    #[test]
    fn rejects_too_deep() {
        let deep = (0..11)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join(".");
        assert!(FieldPath::new(deep).is_err());
    }

    /// A path of exactly 10 segments is accepted.
    #[test]
    fn accepts_max_depth() {
        let path = (0..10)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join(".");
        assert!(FieldPath::new(path).is_ok());
    }

    /// A 257-character path is refused.
    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(257);
        assert!(FieldPath::new(long).is_err());
    }

    /// A 256-character path is accepted.
    #[test]
    fn accepts_max_length() {
        let path = "a".repeat(256);
        assert!(FieldPath::new(path).is_ok());
    }

    /// `user.ssn` prints as `user.ssn`.
    #[test]
    fn display_matches_as_str() {
        let path = FieldPath::new("user.ssn").unwrap();
        assert_eq!(path.to_string(), "user.ssn");
    }

    /// `billing.card_number` written to JSON reads back as the same path.
    #[cfg(feature = "serde")]
    #[test]
    fn a_field_path_reads_back_from_json() {
        let path = FieldPath::new("billing.card_number").unwrap();
        let json = serde_json::to_string(&path).unwrap();
        let restored: FieldPath = serde_json::from_str(&json).unwrap();
        assert_eq!(path, restored);
    }
}
