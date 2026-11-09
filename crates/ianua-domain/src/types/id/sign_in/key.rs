use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// The `kid` in JWT headers and JWKS endpoints that names which signing
    /// key was used.
    ///
    /// It is a string, not a UUID, because RFC 7517 lets `kid` be any string
    /// and outside identity providers use other formats. It must be
    /// non-empty ASCII of at most 128 characters.
    pub struct KeyId;
}

impl TextValue for KeyId {
    const FIELD: &'static str = "kid";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `key-2024-01-abc123` is accepted and kept as written.
    #[test]
    fn accepts_valid_key_id() {
        let kid = KeyId::new("key-2024-01-abc123").unwrap();
        assert_eq!(kid.as_str(), "key-2024-01-abc123");
    }

    /// A `kid` written as a UUID is accepted too.
    #[test]
    fn accepts_uuid_format() {
        assert!(KeyId::new("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    /// An empty `kid` is refused.
    #[test]
    fn an_empty_key_id_is_refused() {
        assert!(KeyId::new("").is_err());
    }

    /// `kéy-1` holds a non-ASCII letter and is refused.
    #[test]
    fn non_ascii_key_ids_are_refused() {
        assert!(KeyId::new("kéy-1").is_err());
    }

    /// A 129-character `kid` is refused.
    #[test]
    fn rejects_over_max_length() {
        let long = "a".repeat(129);
        assert!(KeyId::new(long).is_err());
    }

    /// The `kid` `test-key` prints as `test-key`.
    #[test]
    fn display_returns_value() {
        let kid = KeyId::new("test-key").unwrap();
        assert_eq!(kid.to_string(), "test-key");
    }
}
