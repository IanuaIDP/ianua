use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// The `ID` of a SAML `AuthnRequest`, which its answer names again in
    /// `InResponseTo` and the identity provider carries back as `RelayState`.
    pub struct SamlRequestId;
}

impl TextValue for SamlRequestId {
    const FIELD: &'static str = "request_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.xml_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `_a1b2-c3.d4` starts with an underscore and is accepted as written.
    #[test]
    fn accepts_an_id_starting_with_an_underscore() {
        assert_eq!(
            SamlRequestId::new("_a1b2-c3.d4").unwrap().as_str(),
            "_a1b2-c3.d4"
        );
    }

    /// `id12345` starts with a letter and is accepted.
    #[test]
    fn accepts_an_id_starting_with_a_letter() {
        assert!(SamlRequestId::new("id12345").is_ok());
    }

    /// `1abc` starts with a digit, which an XML `ID` may not. It is refused.
    #[test]
    fn rejects_an_id_starting_with_a_digit() {
        assert!(SamlRequestId::new("1abc").is_err());
    }

    /// Ids with a space, a colon or a quote are refused.
    #[test]
    fn rejects_characters_an_xml_id_cannot_hold() {
        assert!(SamlRequestId::new("_a b").is_err());
        assert!(SamlRequestId::new("_a:b").is_err());
        assert!(SamlRequestId::new("_a\"b").is_err());
    }

    /// An empty id and a 257-character id are both refused.
    #[test]
    fn rejects_empty_and_overlong_ids() {
        assert!(SamlRequestId::new("").is_err());
        assert!(SamlRequestId::new(format!("_{}", "a".repeat(256))).is_err());
    }
}
