use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// The `ID` of a SAML assertion, by which a replay is spotted.
    pub struct SamlAssertionId;
}

impl TextValue for SamlAssertionId {
    const FIELD: &'static str = "assertion_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.xml_id()
    }
}

impl SamlAssertionId {
    /// A new, unique id for an assertion this platform issues.
    ///
    /// It is `_a` and then a UUID's hex digits, which is always a valid XML
    /// `ID`.
    #[must_use]
    pub fn fresh() -> Self {
        Self(format!("_a{}", uuid::Uuid::now_v7().simple()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `_a1b2-c3.d4` starts with an underscore and is accepted as written.
    #[test]
    fn accepts_an_id_starting_with_an_underscore() {
        assert_eq!(
            SamlAssertionId::new("_a1b2-c3.d4").unwrap().as_str(),
            "_a1b2-c3.d4"
        );
    }

    /// `id12345` starts with a letter and is accepted.
    #[test]
    fn accepts_an_id_starting_with_a_letter() {
        assert!(SamlAssertionId::new("id12345").is_ok());
    }

    /// `1abc` starts with a digit, which an XML `ID` may not. It is refused.
    #[test]
    fn rejects_an_id_starting_with_a_digit() {
        assert!(SamlAssertionId::new("1abc").is_err());
    }

    /// Ids with a space, a colon or a quote are refused.
    #[test]
    fn rejects_characters_an_xml_id_cannot_hold() {
        assert!(SamlAssertionId::new("_a b").is_err());
        assert!(SamlAssertionId::new("_a:b").is_err());
        assert!(SamlAssertionId::new("_a\"b").is_err());
    }

    /// A fresh assertion id passes the same check as a received one, and two
    /// fresh ids differ.
    #[test]
    fn a_fresh_id_is_valid_and_unique() {
        let (a, b) = (SamlAssertionId::fresh(), SamlAssertionId::fresh());

        assert!(SamlAssertionId::new(a.as_str()).is_ok());
        assert_ne!(a, b);
    }

    /// An empty id and a 257-character id are both refused.
    #[test]
    fn rejects_empty_and_overlong_ids() {
        assert!(SamlAssertionId::new("").is_err());
        assert!(SamlAssertionId::new(format!("_{}", "a".repeat(256))).is_err());
    }
}
