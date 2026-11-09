//! The words a policy version's choices are stored as.

use ianua_domain::domains::authorization::policy::status::PolicyStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    PolicyStatus as "policy status" {
        Draft => "draft",
        Review => "review",
        Active => "active",
        Archived => "archived",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Enforcement finds the live version by the word `active`, which the
    /// query names, so that word must stay the live status's.
    #[test]
    fn the_live_status_is_stored_as_the_word_enforcement_reads() {
        assert_eq!(PolicyStatus::Active.word(), "active");
        assert_eq!(
            PolicyStatus::from_word("active"),
            Some(PolicyStatus::Active)
        );
    }
}
