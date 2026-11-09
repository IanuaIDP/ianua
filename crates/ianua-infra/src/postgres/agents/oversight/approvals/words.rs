//! The words an approval request's choices are stored as.

use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ApprovalStatus as "approval status" {
        Pending => "pending",
        Approved => "approved",
        Consumed => "consumed",
        Denied => "denied",
        Expired => "expired",
        Withdrawn => "withdrawn",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every status reads back from its word, so a denied or spent request
    /// is never read as one that lets an action through.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [
            ApprovalStatus::Pending,
            ApprovalStatus::Approved,
            ApprovalStatus::Consumed,
            ApprovalStatus::Denied,
            ApprovalStatus::Expired,
            ApprovalStatus::Withdrawn,
        ] {
            assert_eq!(ApprovalStatus::from_word(status.word()), Some(status));
        }
    }
}
