//! The words a run's choices are stored as. Whether every call waits for a
//! person is stored with the words of the delegation's rule, kept with the
//! task templates.

use ianua_domain::domains::agents::execution::run::RunStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    RunStatus as "run status" {
        Running => "running",
        Completed => "completed",
        Failed => "failed",
        Cancelled => "cancelled",
        Halted => "halted",
        AwaitingApproval => "awaiting_approval",
        Paused => "paused",
        OverBudget => "over_budget",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every status reads back from its word, so an ended run is never
    /// read as one still going.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [
            RunStatus::Running,
            RunStatus::Completed,
            RunStatus::Failed,
            RunStatus::Cancelled,
            RunStatus::Halted,
            RunStatus::AwaitingApproval,
            RunStatus::Paused,
            RunStatus::OverBudget,
        ] {
            assert_eq!(RunStatus::from_word(status.word()), Some(status));
            assert_eq!(status.word(), status.as_str());
        }
    }
}
