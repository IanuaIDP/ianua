//! The words a task template's choices are stored as.

use ianua_domain::domains::agents::authority::capability::ActionApproval;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ActionApproval as "action approval" {
        NotRequired => "not_required",
        PerAction => "per_action",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every approval rule reads back from its word, so a template that
    /// holds every action for a person is never read as one that does not.
    #[test]
    fn every_approval_rule_reads_back_from_its_word() {
        for approval in [ActionApproval::NotRequired, ActionApproval::PerAction] {
            assert_eq!(ActionApproval::from_word(approval.word()), Some(approval));
        }
    }
}
