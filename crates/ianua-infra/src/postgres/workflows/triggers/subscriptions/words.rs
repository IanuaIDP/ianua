//! The words a registration's status is stored as: the domain's own
//! cases, each with nothing of its own.

use ianua_domain::domains::workflows::triggers::subscription::SubscriptionStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    SubscriptionStatus as "subscription status" {
        Registering => "registering",
        Live => "live",
        Lapsed => "lapsed",
        Removed => "removed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every status reads back from the word it is written as.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [
            SubscriptionStatus::Registering,
            SubscriptionStatus::Live,
            SubscriptionStatus::Lapsed,
            SubscriptionStatus::Removed,
        ] {
            assert_eq!(SubscriptionStatus::from_word(status.word()), Some(status));
        }
    }
}
