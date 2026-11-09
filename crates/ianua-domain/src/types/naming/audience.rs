use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// Who a token is meant for, its `aud` claim.
    ///
    /// A service pins its audience, and a token must name it to be accepted
    /// there.
    pub struct Audience;
}

impl TextValue for Audience {
    const FIELD: &'static str = "audience";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain name, `billing-app`, and a URI, `https://api.acme.com`, are
    /// both accepted.
    #[test]
    fn accepts_a_name_or_a_uri() {
        assert!(Audience::new("billing-app").is_ok());
        assert!(Audience::new("https://api.acme.com").is_ok());
    }

    /// An empty audience, `billing app` with a space, and a 257-character
    /// audience are all refused.
    #[test]
    fn rejects_empty_spaced_and_overlong_audiences() {
        assert!(Audience::new("").is_err());
        assert!(Audience::new("billing app").is_err());
        assert!(Audience::new("a".repeat(257)).is_err());
    }

    /// An audience with a line break inside it is refused.
    #[test]
    fn rejects_control_characters() {
        assert!(Audience::new("billing\napp").is_err());
    }

    /// `"billing app"` read from JSON is refused, as it would be in code.
    #[cfg(feature = "serde")]
    #[test]
    fn deserializing_checks_the_value_too() {
        assert!(serde_json::from_str::<Audience>("\"billing app\"").is_err());
    }
}
