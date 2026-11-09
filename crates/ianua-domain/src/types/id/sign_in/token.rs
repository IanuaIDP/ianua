use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// A token's `jti`, by which a replay is spotted.
    pub struct TokenId;
}

impl TextValue for TokenId {
    const FIELD: &'static str = "jti";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `jti` written as a UUID is accepted.
    #[test]
    fn accepts_a_uuid() {
        assert!(TokenId::new("019f0000-0000-7000-8000-0000000000a6").is_ok());
    }

    /// An empty `jti`, a 257-character one and one holding a bell character
    /// are all refused.
    #[test]
    fn rejects_empty_overlong_and_control_characters() {
        assert!(TokenId::new("").is_err());
        assert!(TokenId::new("a".repeat(257)).is_err());
        assert!(TokenId::new("a\u{7}b").is_err());
    }
}
