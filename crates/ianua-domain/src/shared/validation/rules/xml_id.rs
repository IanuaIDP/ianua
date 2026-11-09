//! XML `ID` attributes, such as SAML request and assertion IDs.

use crate::message;
use crate::shared::validation::charset::Charset;
use crate::shared::validation::error::ValidationError;
use crate::shared::validation::rule::Rule;
use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Checks an XML `ID` attribute, such as a SAML request or assertion ID.
    ///
    /// It accepts the ASCII part of the XML Schema `xs:ID` type. The rules:
    /// - 1 to 256 characters
    /// - letters, digits, `-`, `.` and `_` only
    /// - starts with a letter or `_`
    #[must_use]
    pub fn xml_id(self) -> Self {
        self.not_empty()
            .length(1..=256)
            .charset(
                Charset::LOWERCASE
                    | Charset::UPPERCASE
                    | Charset::DIGIT
                    | Charset::HYPHEN
                    | Charset::DOT
                    | Charset::UNDERSCORE,
            )
            .rule(&StartsLikeXmlName)
    }
}

/// Requires the first character to be a letter or `_`, as an XML name must.
struct StartsLikeXmlName;

impl Rule for StartsLikeXmlName {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let first = value.bytes().next()?;
        if first.is_ascii_alphabetic() || first == b'_' {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_xml_id_start".to_owned(),
            message: message!(
                "values-must-start-with-a-letter-or",
                format!("{field} must start with a letter or an underscore.")
            ),
        })
    }
}
