use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// The `ID` of a SAML response this platform sends.
    pub struct SamlResponseId;
}

impl TextValue for SamlResponseId {
    const FIELD: &'static str = "response_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.xml_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `_a1b2c3` and `id-42` are valid XML ids and are accepted.
    #[test]
    fn a_well_formed_saml_response_id_is_accepted() {
        for value in ["_a1b2c3", "id-42"] {
            assert!(SamlResponseId::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// An empty id, one starting with a digit and one with a space are all
    /// refused.
    #[test]
    fn a_malformed_saml_response_id_is_refused() {
        for value in ["", "1abc", "a b"] {
            assert!(
                SamlResponseId::new(value).is_err(),
                "{value:?} was accepted"
            );
        }
    }
}
