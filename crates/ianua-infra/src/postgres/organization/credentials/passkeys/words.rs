//! The words a passkey's choices are stored as.

use ianua_domain::domains::authentication::credentials::passkey::{
    AuthenticatorType, KeyAttestation,
};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    AuthenticatorType as "authenticator kind" {
        Platform => "platform",
        CrossPlatform => "cross_platform",
    }
}

stored_words! {
    KeyAttestation as "key attestation" {
        Unattested => "unattested",
        HardwareKey => "hardware_key",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// An authenticator's kind is stored as the name its records carry.
    #[test]
    fn every_authenticator_kind_is_stored_as_its_stable_name() {
        for kind in [
            AuthenticatorType::Platform,
            AuthenticatorType::CrossPlatform,
        ] {
            assert_eq!(kind.word(), kind.as_str());
            assert_eq!(AuthenticatorType::from_word(kind.word()), Some(kind));
        }
    }
}
