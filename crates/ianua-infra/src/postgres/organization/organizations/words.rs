//! The words an organization's choices are stored as.

use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
use ianua_domain::domains::organization::status::{OrgSuspensionReason, OrganizationStatus};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    OrganizationPlan as "plan" {
        Free => "free",
        Starter => "starter",
        Business => "business",
        Custom => "custom",
        SelfHosted => "self_hosted",
    }
}

stored_words! {
    OrganizationStatus as "status" {
        Active => "active",
        Suspended => "suspended",
        Closed => "closed",
    }
}

stored_words! {
    OrgSuspensionReason as "suspension reason" {
        NonPayment => "non_payment",
        Operator => "operator",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [
            OrganizationStatus::Active,
            OrganizationStatus::Suspended,
            OrganizationStatus::Closed,
        ] {
            assert_eq!(status.word(), status.as_str());
            assert_eq!(OrganizationStatus::from_word(status.word()), Some(status));
        }
    }
}
