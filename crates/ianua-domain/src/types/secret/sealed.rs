use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    redacted
    /// A secret encrypted at rest, such as an API key, a client secret or a
    /// TOTP seed.
    ///
    /// The crypto adapter seals it. The domain cannot read it, and it never
    /// prints.
    pub struct SealedSecret;
}

impl TextValue for SealedSecret {
    const FIELD: &'static str = "sealed_secret";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=16_384)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sealed value such as `v1.AAECAwQF` is accepted.
    #[test]
    fn a_well_formed_sealed_secret_is_accepted() {
        assert!(SealedSecret::new("v1.AAECAwQF").is_ok());
    }

    /// An empty value, and values with a space or a line break inside, are
    /// refused.
    #[test]
    fn a_malformed_sealed_secret_is_refused() {
        for value in ["", "v1 AAEC", "v1\nAAEC"] {
            assert!(SealedSecret::new(value).is_err(), "{value:?} was accepted");
        }
    }
}
