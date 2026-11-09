//! The words a password reset's choices are stored as.

use ianua_domain::domains::authentication::recovery::reset::{ResetInitiator, ResetStatus};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ResetInitiator as "reset initiator" {
        User => "user",
        Admin => "admin",
        System => "system",
    }
}

stored_words! {
    ResetStatus as "reset status" {
        Pending => "pending",
        Completed => "completed",
        Expired => "expired",
        Cancelled => "cancelled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Who asked for a reset is stored as the name its records carry.
    #[test]
    fn every_initiator_is_stored_as_its_stable_name() {
        for initiator in [
            ResetInitiator::User,
            ResetInitiator::Admin,
            ResetInitiator::System,
        ] {
            assert_eq!(initiator.word(), initiator.as_str());
            assert_eq!(ResetInitiator::from_word(initiator.word()), Some(initiator));
        }
    }

    /// Completing a reset writes `completed` only over a stored `pending`,
    /// so those are the words the two statuses are kept as.
    #[test]
    fn the_completing_statement_reads_the_stored_words() {
        assert_eq!(ResetStatus::Pending.word(), "pending");
        assert_eq!(ResetStatus::Completed.word(), "completed");
    }
}
