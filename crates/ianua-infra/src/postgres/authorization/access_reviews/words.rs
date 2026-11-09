//! The words an access review's choices are stored as.

use ianua_domain::domains::authorization::access_review::{
    AccessReviewStatus, ReviewChoice, Unanswered,
};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    AccessReviewStatus as "review status" {
        Open => "open",
        Completed => "completed",
        Cancelled => "cancelled",
    }
}

stored_words! {
    Unanswered as "unanswered rule" {
        KeepAccess => "keep_access",
        RemoveAccess => "remove_access",
    }
}

stored_words! {
    ReviewChoice as "review choice" {
        Keep => "keep",
        Remove => "remove",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// A reviewer's choice is stored as the name the domain's records
    /// carry, so the table and the audit trail say the same.
    #[test]
    fn every_choice_is_stored_as_its_own_name() {
        for choice in [ReviewChoice::Keep, ReviewChoice::Remove] {
            assert_eq!(choice.word(), choice.as_str());
            assert_eq!(ReviewChoice::from_word(choice.word()), Some(choice));
        }
    }
}
