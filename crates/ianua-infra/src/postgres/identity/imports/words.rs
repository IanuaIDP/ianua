//! The words an import's choices are stored as.

use ianua_domain::domains::identity::account::import::refusal::RecordRefusal;
use ianua_domain::domains::identity::account::import::state::ImportStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ImportStatus as "import status" {
        Pending => "pending",
        Running => "running",
        Finished => "finished",
        Failed => "failed",
    }
}

stored_words! {
    RecordRefusal as "refusal reason" {
        AddressTaken => "address_taken",
        OwnManager => "own_manager",
        UserLimitReached => "user_limit_reached",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Each word is the name the domain gives the choice, so a row reads
    /// the same to every reader of it.
    #[test]
    fn every_word_is_the_domains_own_name() {
        for status in [
            ImportStatus::Pending,
            ImportStatus::Running,
            ImportStatus::Finished,
            ImportStatus::Failed,
        ] {
            assert_eq!(status.word(), status.as_str());
        }
        for reason in [
            RecordRefusal::AddressTaken,
            RecordRefusal::OwnManager,
            RecordRefusal::UserLimitReached,
        ] {
            assert_eq!(reason.word(), reason.as_str());
        }
    }
}
