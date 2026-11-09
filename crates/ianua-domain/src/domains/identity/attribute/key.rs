//! The internal name of a custom user attribute.

use crate::message;
use crate::shared::validation::{
    Boundary, Charset, Rule, TextValue, ValidationError, Validator, text_value,
};

/// Maximum characters in an attribute key.
const MAX_LENGTH: usize = 64;

/// Prefix kept for attributes the platform may define itself, so a tenant
/// cannot take a name a later release needs.
const RESERVED_PREFIX: &str = "idp_";

text_value! {
    /// The fixed internal name of a custom user attribute, such as
    /// `annual_income`, `department` or `shirt_size`.
    ///
    /// It is not the display name, which an administrator may change at any
    /// time. The key is stored beside every value and named in every filter,
    /// so it never changes once declared.
    ///
    /// It allows fewer characters than a display name. The database only sees
    /// a key as a bound parameter, so quotes and spaces would be safe there.
    /// But a key also appears in query strings, exports and JSON object keys.
    /// A name that needs no escaping in any of them is worth more than spaces.
    ///
    /// Validation rules:
    /// - Lowercase letters, digits and underscores only
    /// - Starts and ends with a lowercase letter or digit
    /// - No doubled underscores
    /// - 1 to 64 characters
    /// - Does not begin with `idp_`
    #[derive(PartialOrd, Ord)]
    pub struct AttributeKey;
}

impl TextValue for AttributeKey {
    const FIELD: &'static str = "attribute_key";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .identifier(
                1..=MAX_LENGTH,
                Charset::LOWERCASE | Charset::DIGIT | Charset::UNDERSCORE,
            )
            .boundaries(Boundary::LowercaseAlphanumeric)
            .no_consecutive(b'_')
            .rule(&NotReserved)
    }
}

impl AttributeKey {
    /// Derives a key from a display name. An administrator who typed "Annual
    /// income" is offered `annual_income` and does not have to invent one.
    ///
    /// ASCII letters are lowercased and digits kept. Every other run of
    /// characters becomes one underscore, and runs at either end are dropped.
    /// The result is checked like any other key. So a name that reduces to
    /// nothing, or to the reserved prefix, is an error for the caller to
    /// handle.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when the derived key is not a valid key.
    pub fn derive_from(display_name: &str) -> Result<Self, ValidationError> {
        let mut derived = String::with_capacity(display_name.len());
        let mut pending_separator = false;

        for ch in display_name.chars() {
            if !ch.is_ascii_alphanumeric() {
                pending_separator = true;
                continue;
            }
            if pending_separator && !derived.is_empty() {
                derived.push('_');
            }
            pending_separator = false;
            derived.push(ch.to_ascii_lowercase());
        }

        Self::new(derived)
    }
}

impl AsRef<str> for AttributeKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Not under the prefix the platform keeps for its own attributes.
struct NotReserved;

impl Rule for NotReserved {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if !value.starts_with(RESERVED_PREFIX) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "reserved_prefix".to_owned(),
            message: message!(
                "identity-must-not-start-with-the-reserved",
                format!("must not start with the reserved prefix '{RESERVED_PREFIX}'")
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `annual_income` and `tier2` are accepted and keep their exact text.
    #[test]
    fn an_ordinary_key_is_accepted() {
        assert_eq!(
            AttributeKey::new("annual_income").unwrap().as_str(),
            "annual_income"
        );
        assert_eq!(AttributeKey::new("tier2").unwrap().as_str(), "tier2");
    }

    /// An empty string is not a key.
    #[test]
    fn an_empty_key_is_refused() {
        assert!(AttributeKey::new("").is_err());
    }

    /// A key of exactly 64 characters is accepted. One of 65 is refused.
    #[test]
    fn a_key_longer_than_the_limit_is_refused() {
        assert!(AttributeKey::new("a".repeat(MAX_LENGTH)).is_ok());
        assert!(AttributeKey::new("a".repeat(MAX_LENGTH + 1)).is_err());
    }

    /// Keys containing SQL fragments, quotes, punctuation, spaces or
    /// control characters are rejected by identifier validation.
    #[test]
    fn a_key_carrying_sql_or_markup_is_refused() {
        for hostile in [
            "value_text; DROP TABLE users--",
            "a' OR '1'='1",
            "name\"quoted",
            "back`tick",
            "semi;colon",
            "paren(s)",
            "star*",
            "percent%",
            "under_score-hyphen",
            "dot.separated",
            "space separated",
            "new\nline",
            "tab\there",
            "null\0byte",
        ] {
            assert!(
                AttributeKey::new(hostile).is_err(),
                "{hostile:?} must be refused"
            );
        }
    }

    /// `AnnualIncome` and `Annual_income` are refused. Only lowercase is
    /// allowed, so `annual_income` cannot also exist under another case.
    #[test]
    fn uppercase_is_refused_so_one_attribute_has_one_spelling() {
        assert!(AttributeKey::new("AnnualIncome").is_err());
        assert!(AttributeKey::new("Annual_income").is_err());
    }

    /// `_leading` and `trailing_` are both refused.
    #[test]
    fn a_key_cannot_start_or_end_with_an_underscore() {
        assert!(AttributeKey::new("_leading").is_err());
        assert!(AttributeKey::new("trailing_").is_err());
    }

    /// `a__b` is refused while `a_b_c` is accepted. Single underscores
    /// between words are fine.
    #[test]
    fn doubled_underscores_are_refused() {
        assert!(AttributeKey::new("a__b").is_err());
        assert!(AttributeKey::new("a_b_c").is_ok());
    }

    /// A tenant declares `idp_tier`. It is refused, since the platform may
    /// need that name later. `idpx_tier` is fine, as only the exact prefix is
    /// kept.
    #[test]
    fn the_platform_prefix_is_reserved() {
        assert!(AttributeKey::new("idp_tier").is_err());
        assert!(
            AttributeKey::new("idpx_tier").is_ok(),
            "only the exact prefix is reserved"
        );
    }

    /// "Shirt size (EU)" becomes `shirt_size_eu` and "Département" becomes
    /// `d_partement`. Extra spaces, symbols and non-ASCII letters each fold
    /// into one underscore.
    #[test]
    fn a_key_is_derived_from_what_the_administrator_typed() {
        for (typed, expected) in [
            ("Annual income", "annual_income"),
            ("Annual  income", "annual_income"),
            ("  Annual income  ", "annual_income"),
            ("Shirt size (EU)", "shirt_size_eu"),
            ("Tier 2", "tier_2"),
            ("Département", "d_partement"),
            ("ALL CAPS", "all_caps"),
            ("hyphen-separated", "hyphen_separated"),
        ] {
            assert_eq!(
                AttributeKey::derive_from(typed).unwrap().as_str(),
                expected,
                "deriving from {typed:?}"
            );
        }
    }

    /// An administrator types "!!!" or "idp_tier" as a display name. No key
    /// is derived. They get an error to fix instead of a key made up for
    /// them.
    #[test]
    fn a_name_that_derives_to_nothing_usable_is_an_error() {
        assert!(AttributeKey::derive_from("").is_err());
        assert!(AttributeKey::derive_from("!!!").is_err());
        assert!(AttributeKey::derive_from("___").is_err());
        assert!(AttributeKey::derive_from("idp_tier").is_err());
    }

    /// A key derived from "Annual income (gross)" passes the same check as a
    /// typed key and reads back equal.
    #[test]
    fn a_derived_key_is_a_valid_key() {
        let derived = AttributeKey::derive_from("Annual income (gross)").unwrap();
        assert_eq!(
            AttributeKey::new(derived.as_str()).unwrap(),
            derived,
            "deriving must not produce something new() would refuse"
        );
    }

    /// `department` prints as its text and equals another `department`, but
    /// not `departments`.
    #[test]
    fn keys_compare_and_render_by_their_text() {
        let key = AttributeKey::new("department").unwrap();

        assert_eq!(key.to_string(), "department");
        assert_eq!(key.as_ref(), "department");
        assert_eq!(key, AttributeKey::new("department").unwrap());
        assert_ne!(key, AttributeKey::new("departments").unwrap());
    }

    /// JSON deserialization refuses a reserved name, mixed-case words and
    /// an empty key instead of bypassing identifier validation.
    #[cfg(feature = "serde")]
    #[test]
    fn a_key_breaking_the_rules_is_refused_on_deserialize() {
        for bad in [r#""idp_tier""#, r#""Annual Income""#, r#""""#] {
            assert!(
                serde_json::from_str::<AttributeKey>(bad).is_err(),
                "{bad} must be refused"
            );
        }
    }

    /// `annual_income` turns into the JSON string `"annual_income"` and reads
    /// back as the same key.
    #[cfg(feature = "serde")]
    #[test]
    fn a_valid_key_round_trips_through_json() {
        let key = AttributeKey::new("annual_income").unwrap();

        let json = serde_json::to_string(&key).unwrap();

        assert_eq!(json, r#""annual_income""#);
        assert_eq!(serde_json::from_str::<AttributeKey>(&json).unwrap(), key);
    }
}
