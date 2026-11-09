//! The words a directory service account's choices are stored as.

use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
use ianua_domain::domains::authentication::directory_service::scope::DirectoryAccess;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ServiceAccountStatus as "service account status" {
        Active => "active",
        Disabled => "disabled",
    }
}

stored_words! {
    DirectoryAccess as "directory access" {
        ReadOnly => "read_only",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every status reads back from its word, the one the domain names it
    /// by, so a disabled account is never read as one that binds.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [ServiceAccountStatus::Active, ServiceAccountStatus::Disabled] {
            assert_eq!(ServiceAccountStatus::from_word(status.word()), Some(status));
            assert_eq!(status.word(), status.as_str());
        }
    }

    /// The one access reads back from its word, and a word from before
    /// reads as nothing rather than as an access.
    #[test]
    fn the_access_reads_back_from_its_word() {
        let access = DirectoryAccess::ReadOnly;

        assert_eq!(DirectoryAccess::from_word(access.word()), Some(access));
        assert_eq!(access.word(), access.as_str());
        assert_eq!(DirectoryAccess::from_word("read_write"), None);
    }
}
