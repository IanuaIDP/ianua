//! The words an organization API key's choices are stored as.

use ianua_domain::domains::organization::access::api_key::OrgApiKeyStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    OrgApiKeyStatus as "API key status" {
        Active => "active",
        Revoked => "revoked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every status reads back from the word it is written as, so a revoked
    /// key is never read as a working one.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [OrgApiKeyStatus::Active, OrgApiKeyStatus::Revoked] {
            assert_eq!(OrgApiKeyStatus::from_word(status.word()), Some(status));
        }
    }
}
