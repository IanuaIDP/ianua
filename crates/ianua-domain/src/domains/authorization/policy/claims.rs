//! The attributes and token claims a policy rule can compare.
//!
//! A rule such as "deny unless `department` is `finance`" names an
//! attribute of the person, or a claim their sign-in carried, and the value
//! it must hold. The gateway reads them from the person's attributes and the
//! token it checked, and hands them in as [`Claim`]s.

use crate::shared::validation::{Charset, TextValue, Validator, text_value};

/// The longest claim name, in characters.
const MAX_NAME: usize = 128;

/// The longest claim value a rule compares, in characters.
const MAX_VALUE: usize = 256;

text_value! {
    /// The name of an attribute or a claim, such as `department`,
    /// `email_verified` or `https://acme.test/claims/tier`.
    ///
    /// Letters, digits and `_ - . : /` only, so a name never holds a space
    /// or a quote an editor could misread as its end.
    pub struct ClaimName;
}

impl TextValue for ClaimName {
    const FIELD: &'static str = "claim_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=MAX_NAME,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::UNDERSCORE
                | Charset::HYPHEN
                | Charset::DOT
                | Charset::COLON
                | Charset::SLASH,
        )
    }
}

text_value! {
    /// The value a rule wants an attribute or a claim to hold, compared
    /// exactly, such as `finance`.
    pub struct ClaimValue;
}

impl TextValue for ClaimValue {
    const FIELD: &'static str = "claim_value";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(MAX_VALUE)
    }
}

/// One attribute or claim a request's caller carries: its name and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    name: ClaimName,
    value: ClaimValue,
}

impl Claim {
    /// The caller carries `name` with `value`.
    #[must_use]
    pub fn new(name: ClaimName, value: ClaimValue) -> Self {
        Self { name, value }
    }

    /// The key used by policy conditions to select this caller assertion.
    #[must_use]
    pub fn name(&self) -> &ClaimName {
        &self.name
    }

    /// The asserted content compared with policy conditions.
    #[must_use]
    pub fn value(&self) -> &ClaimValue {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain name, a dotted one and a URL-shaped one are all claim names.
    #[test]
    fn claim_names_take_the_shapes_tokens_use() {
        for name in [
            "department",
            "email_verified",
            "https://acme.test/claims/tier",
        ] {
            assert!(ClaimName::new(name).is_ok(), "{name}");
        }
    }

    /// Claim names containing a space or a quote are rejected.
    #[test]
    fn a_claim_name_holds_no_space_or_quote() {
        assert!(ClaimName::new("department name").is_err());
        assert!(ClaimName::new("dept\"").is_err());
    }

    /// An empty value is refused, so "equals nothing" is never a rule that
    /// matches every caller without the claim.
    #[test]
    fn an_empty_claim_value_is_refused() {
        assert!(ClaimValue::new("").is_err());
        assert!(ClaimValue::new("finance").is_ok());
    }
}
