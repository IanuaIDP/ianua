use std::fmt;

use crate::shared::config::DisplayNameLimits;
use crate::shared::validation::{ValidationError, Validator};

/// A tenant name shown in admin UIs and branding.
///
/// It may hold any Unicode letters, so `"Café München GmbH"` is fine. It is
/// checked when built. A `DisplayName` is never blank, stays within the
/// configured length limits, and holds no control or invisible characters.
///
/// # Examples
///
/// ```
/// # use ianua_domain::types::DisplayName;
/// # use ianua_domain::shared::config::DisplayNameLimits;
/// let limits = DisplayNameLimits::default();
/// let name = DisplayName::new("Acme Corporation", &limits).unwrap();
/// assert_eq!(name.as_str(), "Acme Corporation");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct DisplayName(String);

impl TryFrom<String> for DisplayName {
    type Error = ValidationError;

    /// Reading JSON goes through [`DisplayName::new`] with the default
    /// limits.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value, &DisplayNameLimits::default())
    }
}

impl DisplayName {
    /// A display name checked against `limits`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the value is blank.
    /// - [`ValidationError`] if its length is outside the configured minimum
    ///   and maximum, counted in Unicode characters, not bytes.
    /// - [`ValidationError`] if it holds a control or invisible character.
    pub fn new(
        value: impl Into<String>,
        limits: &DisplayNameLimits,
    ) -> Result<Self, ValidationError> {
        let value = value.into();

        Validator::new("display_name", &value)
            .not_blank()
            .char_length(limits.min_length..=limits.max_length)
            .no_control_chars()
            .no_invisible_chars()
            .validate_first()?;

        Ok(Self(value))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> DisplayNameLimits {
        DisplayNameLimits::default()
    }

    /// `Acme Corp` is accepted and kept as written.
    #[test]
    fn accepts_simple_name() {
        let name = DisplayName::new("Acme Corp", &limits()).unwrap();
        assert_eq!(name.as_str(), "Acme Corp");
    }

    /// `Café München GmbH` and a name in Japanese are both accepted.
    #[test]
    fn display_names_accept_non_ascii_letters() {
        assert!(DisplayName::new("Café München GmbH", &limits()).is_ok());
        assert!(DisplayName::new("日本語テナント", &limits()).is_ok());
    }

    /// A one-letter name, `A`, is accepted under the default limits.
    #[test]
    fn accepts_single_character() {
        assert!(DisplayName::new("A", &limits()).is_ok());
    }

    /// A 255-character name, the default maximum, is accepted.
    #[test]
    fn accepts_at_max_length() {
        let name = "a".repeat(255);
        assert!(DisplayName::new(name, &limits()).is_ok());
    }

    /// An empty name is refused with the `required` code.
    #[test]
    fn empty_display_names_report_required() {
        let err = DisplayName::new("", &limits()).unwrap_err();
        assert_eq!(err.code(), "required");
    }

    /// A 256-character name is refused with the `invalid_length` code.
    #[test]
    fn rejects_over_max_length() {
        let long = "a".repeat(256);
        let err = DisplayName::new(long, &limits()).unwrap_err();
        assert_eq!(err.code(), "invalid_length");
    }

    /// A name of 255 "é" takes 510 bytes but has 255 characters, so it is
    /// accepted.
    #[test]
    fn counts_unicode_chars_not_bytes() {
        let value = "é".repeat(255);
        assert!(DisplayName::new(value, &limits()).is_ok());
    }

    /// With limits of 3 to 10 characters, `ab` and an 11-character name are
    /// refused, while 3 and 10 characters pass.
    #[test]
    fn respects_custom_limits() {
        let l = DisplayNameLimits {
            min_length: 3,
            max_length: 10,
        };
        assert!(DisplayName::new("ab", &l).is_err());
        assert!(DisplayName::new("abc", &l).is_ok());
        assert!(DisplayName::new("a".repeat(10), &l).is_ok());
        assert!(DisplayName::new("a".repeat(11), &l).is_err());
    }

    /// The name `Acme` prints as `Acme`.
    #[test]
    fn display_returns_inner_value() {
        let name = DisplayName::new("Acme", &limits()).unwrap();
        assert_eq!(name.to_string(), "Acme");
    }

    /// `Café München GmbH` reads from JSON and writes back the same. An empty
    /// or 256-character name in JSON is refused, as in code.
    #[cfg(feature = "serde")]
    #[test]
    fn a_display_name_read_from_json_is_validated() {
        let name: DisplayName = serde_json::from_str("\"Café München GmbH\"").unwrap();

        assert_eq!(
            serde_json::to_string(&name).unwrap(),
            "\"Café München GmbH\""
        );
        assert!(serde_json::from_str::<DisplayName>("\"\"").is_err());
        assert!(serde_json::from_str::<DisplayName>(&format!("\"{}\"", "a".repeat(256))).is_err());
    }
}
