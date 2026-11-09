//! Random DNS labels independent of a tenant's name and identifier.

use crate::shared::errors::DomainError;
use crate::shared::random::RandomSource;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};

text_value! {
    /// A permanent random platform label with no name or creation timestamp.
    pub struct PlatformLabel;
}

impl TextValue for PlatformLabel {
    const FIELD: &'static str = "platform_label";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .max_bytes(16)
            .length(6..=16)
            .ascii_only()
            .charset(Charset::LOWERCASE | Charset::DIGIT)
    }
}

impl PlatformLabel {
    /// Draws sixteen hexadecimal characters independently of tenant identifiers.
    /// Storage enforces uniqueness; the caller supplies secure randomness.
    ///
    /// # Errors
    ///
    /// Returns an infrastructure error if the random source exceeds its bound.
    pub fn generate(random: &mut impl RandomSource) -> Result<Self, DomainError> {
        let alphabet = b"0123456789abcdef";
        let mut label = String::with_capacity(16);
        for _ in 0..16 {
            let character = alphabet
                .get(random.index_below(alphabet.len()))
                .ok_or_else(|| {
                    DomainError::infra_msg("the random source exceeded the platform label alphabet")
                })?;
            label.push(char::from(*character));
        }
        Ok(Self(label))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fakes::SequenceRandom;

    /// Independently generated labels pass the same checks as stored labels.
    #[test]
    fn generated_labels_are_valid_and_independent() {
        let first = PlatformLabel::generate(&mut SequenceRandom::new(1)).unwrap();
        assert_ne!(
            first,
            PlatformLabel::generate(&mut SequenceRandom::new(2)).unwrap()
        );
        assert_eq!(PlatformLabel::new(first.as_str()).unwrap(), first);
    }

    struct BrokenRandom;

    impl RandomSource for BrokenRandom {
        /// Violates the source's bound to exercise refusal without a panic.
        fn index_below(&mut self, upper: usize) -> usize {
            upper
        }
    }

    /// An out-of-range random choice returns an infrastructure error
    /// instead of constructing a platform label.
    #[test]
    fn an_out_of_range_random_choice_is_refused() {
        assert!(matches!(
            PlatformLabel::generate(&mut BrokenRandom),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Empty or short labels, DNS separators, wildcards, uppercase letters
    /// and hyphens are rejected as platform labels.
    #[test]
    fn a_label_cannot_contain_dns_structure() {
        for value in ["", "api", "*.acme", "abc.def", "ABCDEF", "abc-def"] {
            assert!(PlatformLabel::new(value).is_err(), "{value}");
        }
    }
}
