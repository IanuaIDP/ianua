use crate::shared::validation::{Charset, TextValue, Validator, text_value};

text_value! {
    /// The visible start of an API key, which identifies it in a list without
    /// revealing it.
    pub struct KeyPrefix;
}

impl TextValue for KeyPrefix {
    const FIELD: &'static str = "key_prefix";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=64,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::UNDERSCORE
                | Charset::HYPHEN,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prefixes such as `ik_live_ab12` and `oak_x` are accepted.
    #[test]
    fn a_well_formed_key_prefix_is_accepted() {
        for value in ["ik_live_ab12", "oak_x"] {
            assert!(KeyPrefix::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// An empty prefix, one with a space and one with a dot are all refused.
    #[test]
    fn a_malformed_key_prefix_is_refused() {
        for value in ["", "ik live", "ik.live"] {
            assert!(KeyPrefix::new(value).is_err(), "{value:?} was accepted");
        }
    }
}
