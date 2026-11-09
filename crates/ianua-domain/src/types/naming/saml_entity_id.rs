//! The SAML entity id that names an identity provider or a service provider.

use crate::shared::validation::{TextValue, Validator, text_value};

/// The longest entity id the SAML 2.0 specification allows.
const MAX_ENTITY_ID_LENGTH: usize = 1024;

text_value! {
    /// A SAML entity id, the `entityID` attribute in SAML metadata.
    ///
    /// It is a URL or a URN. The SAML 2.0 metadata specification makes
    /// entity ids URIs of at most 1024 characters.
    ///
    /// # Validation
    ///
    /// - Not empty.
    /// - At most 1024 characters.
    /// - No control characters or whitespace.
    pub struct SamlEntityId;
}

impl TextValue for SamlEntityId {
    const FIELD: &'static str = "entity_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .char_length(1..=MAX_ENTITY_ID_LENGTH)
            .no_control_chars()
            .no_whitespace()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `https://auth.acme.com` is accepted and kept as written.
    #[test]
    fn accepts_url_entity_id() {
        let id = SamlEntityId::new("https://auth.acme.com").unwrap();
        assert_eq!(id.as_str(), "https://auth.acme.com");
    }

    /// A URN entity id is accepted and kept as written.
    #[test]
    fn accepts_urn_entity_id() {
        let id = SamlEntityId::new("urn:oasis:names:tc:SAML:2.0:example").unwrap();
        assert_eq!(id.as_str(), "urn:oasis:names:tc:SAML:2.0:example");
    }

    /// Empty text cannot identify a peer in SAML metadata.
    #[test]
    fn an_empty_entity_id_is_refused() {
        assert!(SamlEntityId::new("").is_err());
    }

    /// A 1025-character entity id, one past the SAML limit, is refused.
    #[test]
    fn rejects_too_long() {
        assert!(SamlEntityId::new("a".repeat(1025)).is_err());
    }

    /// An entity id with a NUL byte inside it is refused.
    #[test]
    fn rejects_control_chars() {
        assert!(SamlEntityId::new("entity\x00id").is_err());
    }

    /// `https://sp.example.com` prints as itself.
    #[test]
    fn display_returns_value() {
        let id = SamlEntityId::new("https://sp.example.com").unwrap();
        assert_eq!(id.to_string(), "https://sp.example.com");
    }
}
