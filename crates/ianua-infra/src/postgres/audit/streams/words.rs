//! The words an audit stream's choices are stored as.

use ianua_domain::domains::tenant::audit_streams::PauseReason;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    PauseReason as "stream pause reason" {
        ByAdministrator => "by_administrator",
        AfterFailures => "after_failures",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every reason reads back from the word it is written as, and it is
    /// the word the domain names it by.
    #[test]
    fn every_pause_reason_reads_back_from_its_word() {
        for reason in [PauseReason::ByAdministrator, PauseReason::AfterFailures] {
            assert_eq!(PauseReason::from_word(reason.word()), Some(reason));
            assert_eq!(reason.word(), reason.as_str());
        }
    }
}
