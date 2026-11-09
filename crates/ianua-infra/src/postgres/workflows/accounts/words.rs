//! The words an integration account's choices are stored as.

use ianua_domain::domains::workflows::account::{AccountSharing, AccountStatus};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    AccountSharing as "account sharing" {
        OwnerOnly => "owner_only",
        Tenant => "tenant",
    }
}

stored_words! {
    AccountStatus as "account status" {
        Active => "active",
        Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every sharing and status reads back from the word it is written as,
    /// so an account kept to its owner is never read as shared, nor a
    /// disabled one as active.
    #[test]
    fn every_choice_reads_back_from_its_word() {
        for sharing in [AccountSharing::OwnerOnly, AccountSharing::Tenant] {
            assert_eq!(AccountSharing::from_word(sharing.word()), Some(sharing));
        }
        for status in [AccountStatus::Active, AccountStatus::Disabled] {
            assert_eq!(AccountStatus::from_word(status.word()), Some(status));
        }
    }
}
