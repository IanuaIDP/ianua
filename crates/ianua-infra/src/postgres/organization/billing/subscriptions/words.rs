//! The words a subscription's choices are stored as.

use ianua_domain::domains::organization::billing::payment::{BillingCycle, TrialUse};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    BillingCycle as "billing cycle" {
        Monthly => "monthly",
        Annual => "annual",
    }
}

stored_words! {
    TrialUse as "trial use" {
        Unused => "unused",
        Used => "used",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// A billing cycle is stored as the name the domain gives it, so the
    /// column and the records it feeds read the same.
    #[test]
    fn every_cycle_is_stored_as_its_own_name() {
        for cycle in [BillingCycle::Monthly, BillingCycle::Annual] {
            assert_eq!(cycle.word(), cycle.as_str());
            assert_eq!(BillingCycle::from_word(cycle.word()), Some(cycle));
        }
    }
}
