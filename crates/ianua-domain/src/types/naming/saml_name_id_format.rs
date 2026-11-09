use crate::message;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

text_value! {
    /// The format of a SAML `NameID`, a URN such as
    /// `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`.
    pub struct SamlNameIdFormat;
}

impl SamlNameIdFormat {
    /// The format whose `NameID` a provider never gives to anyone else and
    /// never changes for the same person.
    pub const PERSISTENT: &'static str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

    /// Whether a `NameID` in this format names one person for good, so an
    /// account may be linked to it.
    ///
    /// Only the persistent format does. An email address is handed on when
    /// its owner leaves, and a transient `NameID` changes at every sign-in.
    #[must_use]
    pub fn names_one_person_for_good(&self) -> bool {
        self.as_str() == Self::PERSISTENT
    }
}

impl TextValue for SamlNameIdFormat {
    const FIELD: &'static str = "name_id_format";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=256).rule(&IsUrn)
    }
}

/// A URN, which is how SAML names every `NameID` format.
struct IsUrn;

impl Rule for IsUrn {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if value.starts_with("urn:") {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "not_a_urn".to_owned(),
            message: message!(
                "values-must-be-a-urn-such-as",
                format!(
                    "{field} must be a URN, such as urn:oasis:names:tc:SAML:2.0:nameid-format:persistent."
                )
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The email-address and persistent format URNs are both accepted.
    #[test]
    fn a_well_formed_saml_name_id_format_is_accepted() {
        for value in [
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        ] {
            assert!(
                SamlNameIdFormat::new(value).is_ok(),
                "{value:?} was refused"
            );
        }
    }

    /// An empty format, a bare `emailAddress` that is not a URN, and a URN
    /// with a space are all refused.
    #[test]
    fn a_malformed_saml_name_id_format_is_refused() {
        for value in ["", "emailAddress", "urn:a b"] {
            assert!(
                SamlNameIdFormat::new(value).is_err(),
                "{value:?} was accepted"
            );
        }
    }
}
