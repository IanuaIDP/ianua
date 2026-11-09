use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// The `SessionIndex` a SAML assertion carries, which a later logout
    /// request names.
    pub struct SessionIndex;
}

impl TextValue for SessionIndex {
    const FIELD: &'static str = "session_index";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session index in the usual hex form an identity provider sends is
    /// accepted.
    #[test]
    fn a_well_formed_session_index_is_accepted() {
        assert!(SessionIndex::new("_be9967abd904ddcae3c0eb4189adbe3f71e327cf93").is_ok());
    }

    /// An empty index, one with a space and one with a line break are all
    /// refused.
    #[test]
    fn a_malformed_session_index_is_refused() {
        for value in ["", "a b", "a\nb"] {
            assert!(SessionIndex::new(value).is_err(), "{value:?} was accepted");
        }
    }
}
