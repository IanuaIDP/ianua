use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// Who a person is at an outside identity provider, such as OIDC's `sub`
    /// or the SAML `NameID`.
    ///
    /// It is stable for that person at one provider and means nothing outside
    /// it, so it is only compared together with the connection it arrived on.
    /// A local account is linked to it, not to the email address, because the
    /// provider never hands a subject to somebody else.
    pub struct FederatedSubject;
}

impl TextValue for FederatedSubject {
    const FIELD: &'static str = "subject";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .max_bytes(MAX_SUBJECT_BYTES)
            .no_control_chars()
            .no_invisible_chars()
    }
}

/// The longest subject accepted. OIDC caps `sub` at 255 ASCII characters,
/// and SAML persistent identifiers stay well inside this too.
const MAX_SUBJECT_BYTES: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;

    /// The subject `google-oauth2|1234567890` is kept byte for byte, so it
    /// matches the provider's next sign-in.
    #[test]
    fn keeps_the_subject_exactly_as_the_provider_sent_it() {
        assert_eq!(
            FederatedSubject::new("google-oauth2|1234567890")
                .unwrap()
                .as_str(),
            "google-oauth2|1234567890"
        );
    }

    /// A provider sends an empty subject. It is refused, since it names
    /// nobody to link.
    #[test]
    fn rejects_an_empty_subject() {
        assert!(FederatedSubject::new("").is_err());
    }

    /// A 513-byte subject is refused.
    #[test]
    fn rejects_an_overlong_subject() {
        assert!(FederatedSubject::new("a".repeat(513)).is_err());
    }

    /// A subject with a line break inside it is refused.
    #[test]
    fn rejects_control_characters() {
        assert!(FederatedSubject::new("user\n1").is_err());
    }
}
