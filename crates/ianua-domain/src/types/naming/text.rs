use std::fmt;

use crate::shared::validation::{ValidationError, Validator};

/// A checked free-form text field, such as a reason, a description or a
/// message.
///
/// It is used wherever a user writes longer text, such as break-glass
/// reasons, impersonation justifications, invitation messages and webhook
/// descriptions.
///
/// It follows the shared free-text rules:
/// - Not blank.
/// - At most 500 characters, counted as Unicode characters.
/// - No ASCII control characters, such as NUL, tab, escape or line breaks.
/// - No invisible characters, such as bidirectional overrides, zero-width
///   or tag characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct Text(String);

impl TryFrom<String> for Text {
    type Error = ValidationError;

    /// Reading JSON goes through [`Text::new`], so text that arrives as JSON
    /// is held to the same rules as text built in code.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new("text", value)
    }
}

impl Text {
    /// A checked text field. `field` names the field in an error.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the value is blank.
    /// - [`ValidationError`] if it is over 500 characters.
    /// - [`ValidationError`] if it holds a control or invisible character.
    pub fn new(field: &'static str, value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();

        Validator::new(field, &value)
            .free_text(500)
            .validate_first()?;

        Ok(Self(value))
    }

    /// The checked text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A break-glass reason, `Production incident INC-1234`, is accepted as
    /// written.
    #[test]
    fn accepts_normal_sentence() {
        let t = Text::new("reason", "Production incident INC-1234").unwrap();
        assert_eq!(t.as_str(), "Production incident INC-1234");
    }

    /// A German reason with non-English letters is accepted.
    #[test]
    fn a_german_reason_is_accepted() {
        assert!(Text::new("reason", "Ursache: Datenmigration fehlgeschlagen").is_ok());
    }

    /// Text of exactly 500 characters, the most allowed, is accepted.
    #[test]
    fn accepts_at_500_chars() {
        assert!(Text::new("reason", "a".repeat(500)).is_ok());
    }

    /// An empty explanation is refused when a reason is required.
    #[test]
    fn an_empty_reason_is_refused() {
        assert!(Text::new("reason", "").is_err());
    }

    /// Text of 501 characters is refused.
    #[test]
    fn rejects_over_500_chars() {
        assert!(Text::new("reason", "a".repeat(501)).is_err());
    }

    /// A reason with a NUL byte inside it is refused.
    #[test]
    fn rejects_null_byte() {
        assert!(Text::new("reason", "reason\x00here").is_err());
    }

    /// A reason with a tab inside it is refused.
    #[test]
    fn reasons_with_tabs_are_refused() {
        assert!(Text::new("reason", "reason\there").is_err());
    }

    /// The text `hello` prints as `hello`.
    #[test]
    fn display_returns_value() {
        let t = Text::new("reason", "hello").unwrap();
        assert_eq!(t.to_string(), "hello");
    }

    /// An empty impersonation reason is refused with an error that names
    /// `impersonation_reason`, so the form can mark the right field.
    #[test]
    fn carries_field_name_in_error() {
        let err = Text::new("impersonation_reason", "").unwrap_err();
        assert_eq!(err.field(), Some("impersonation_reason"));
    }

    /// `"Production incident"` reads from JSON and writes back the same. An
    /// empty or 501-character value in JSON is refused, as in code.
    #[cfg(feature = "serde")]
    #[test]
    fn text_read_from_json_is_validated() {
        let t: Text = serde_json::from_str("\"Production incident\"").unwrap();

        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            "\"Production incident\""
        );
        assert!(serde_json::from_str::<Text>("\"\"").is_err());
        assert!(serde_json::from_str::<Text>(&format!("\"{}\"", "a".repeat(501))).is_err());
    }
}
