//! The words a signing key's choices are stored as.

use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    SigningAlgorithm as "signing algorithm" {
        Rs256 => "RS256",
        Es256 => "ES256",
        EdDsa => "EdDSA",
    }
}

stored_words! {
    KeyStatus as "key status" {
        Active => "active",
        Rotated => "rotated",
        Revoked => "revoked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every algorithm reads back from the word it is written as, and that
    /// word is the name a JWT header carries.
    #[test]
    fn every_algorithm_reads_back_from_its_word() {
        for algorithm in [
            SigningAlgorithm::Rs256,
            SigningAlgorithm::Es256,
            SigningAlgorithm::EdDsa,
        ] {
            assert_eq!(
                SigningAlgorithm::from_word(algorithm.word()),
                Some(algorithm)
            );
            assert_eq!(algorithm.word(), algorithm.to_string());
        }
    }

    /// Every status reads back from its word, so a revoked key is never
    /// read as one that signs.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [KeyStatus::Active, KeyStatus::Rotated, KeyStatus::Revoked] {
            assert_eq!(KeyStatus::from_word(status.word()), Some(status));
        }
    }
}
