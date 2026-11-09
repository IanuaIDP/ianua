use std::fmt;

use crate::shared::validation::{ValidationError, Validator};

/// The longest a label may be by default, in characters.
const DEFAULT_MAX_LENGTH: usize = 100;

/// A checked short label, such as a passkey, role, device, connection or API
/// key name, or an email subject.
///
/// It is used wherever a user writes a short descriptive string. It is
/// checked when built, and reading JSON goes through the same checks with
/// the default limit.
///
/// It follows the shared free-text rules:
/// - Not blank.
/// - At most 100 characters, or what `with_max_length` sets.
/// - No ASCII control characters, such as NUL, tab, escape or line breaks.
/// - No invisible characters, such as bidirectional overrides, zero-width
///   or tag characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct Label(String);

impl TryFrom<String> for Label {
    type Error = ValidationError;

    /// Reading JSON goes through [`Label::new`] with the default limit.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new("label", value)
    }
}

impl Label {
    /// A checked label of at most 100 characters. `field` names the field in
    /// an error.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the value is blank.
    /// - [`ValidationError`] if it is over 100 characters.
    /// - [`ValidationError`] if it holds a control or invisible character.
    pub fn new(field: &'static str, value: impl Into<String>) -> Result<Self, ValidationError> {
        Self::with_max_length(field, value, DEFAULT_MAX_LENGTH)
    }

    /// A checked label of at most `max_length` characters.
    ///
    /// Use it for fields that need more than 100 characters, such as email
    /// subjects at 200 or descriptions at 300.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the value is blank.
    /// - [`ValidationError`] if it is over `max_length` characters.
    /// - [`ValidationError`] if it holds a control or invisible character.
    pub fn with_max_length(
        field: &'static str,
        value: impl Into<String>,
        max_length: usize,
    ) -> Result<Self, ValidationError> {
        let value = value.into();

        Validator::new(field, &value)
            .free_text(max_length)
            .validate_first()?;

        Ok(Self(value))
    }

    /// The checked text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A passkey named `YubiKey 5` is accepted as written.
    #[test]
    fn accepts_simple_name() {
        let name = Label::new("name", "YubiKey 5").unwrap();
        assert_eq!(name.as_str(), "YubiKey 5");
    }

    /// `MacBook de José` with an accented letter is accepted.
    #[test]
    fn labels_accept_non_ascii_letters() {
        assert!(Label::new("name", "MacBook de José").is_ok());
    }

    /// A name that starts with a key emoji is accepted, since emoji are
    /// visible characters.
    #[test]
    fn labels_accept_visible_emoji() {
        assert!(Label::new("name", "🔑 My Key").is_ok());
    }

    /// A 100-character label, the default maximum, is accepted.
    #[test]
    fn accepts_at_100_chars() {
        assert!(Label::new("name", "a".repeat(100)).is_ok());
    }

    /// Empty text cannot supply a resource's required display name.
    #[test]
    fn an_empty_label_is_refused() {
        assert!(Label::new("name", "").is_err());
    }

    /// A 101-character label is refused.
    #[test]
    fn rejects_over_100_chars() {
        assert!(Label::new("name", "a".repeat(101)).is_err());
    }

    /// A label with a NUL byte inside it is refused.
    #[test]
    fn rejects_null_byte() {
        assert!(Label::new("name", "Key\x00Name").is_err());
    }

    /// A label with a tab inside it is refused.
    #[test]
    fn labels_with_tabs_are_refused() {
        assert!(Label::new("name", "Key\tName").is_err());
    }

    /// A label with a line break inside it is refused.
    #[test]
    fn labels_with_newlines_are_refused() {
        assert!(Label::new("name", "Key\nName").is_err());
    }

    /// The label `My Key` prints as `My Key`.
    #[test]
    fn display_returns_value() {
        let name = Label::new("name", "My Key").unwrap();
        assert_eq!(name.to_string(), "My Key");
    }

    /// An empty passkey name is refused with an error that names
    /// `passkey_name`, so the form can mark the right field.
    #[test]
    fn carries_field_name_in_error() {
        let err = Label::new("passkey_name", "").unwrap_err();
        assert_eq!(err.field(), Some("passkey_name"));
    }

    /// An email subject of 200 characters passes a limit of 200.
    #[test]
    fn with_max_length_accepts_within_limit() {
        assert!(Label::with_max_length("subject", "a".repeat(200), 200).is_ok());
    }

    /// An email subject of 201 characters fails a limit of 200.
    #[test]
    fn with_max_length_rejects_over_limit() {
        assert!(Label::with_max_length("subject", "a".repeat(201), 200).is_err());
    }

    /// A longer limit does not let an empty subject through.
    #[test]
    fn with_max_length_still_rejects_empty() {
        assert!(Label::with_max_length("subject", "", 200).is_err());
    }

    /// A longer limit does not let a subject with a NUL byte through.
    #[test]
    fn with_max_length_still_rejects_control_chars() {
        assert!(Label::with_max_length("subject", "hello\x00", 200).is_err());
    }

    /// `Office laptop` reads from JSON. An empty label or one holding a NUL
    /// byte in JSON is refused, as in code.
    #[cfg(feature = "serde")]
    #[test]
    fn a_label_read_from_json_is_validated() {
        assert!(serde_json::from_str::<Label>("\"Office laptop\"").is_ok());
        assert!(serde_json::from_str::<Label>("\"\"").is_err());
        assert!(serde_json::from_str::<Label>("\"bad\\u0000name\"").is_err());
    }
}
