//! The words an impersonation's choices are stored as.

use ianua_domain::domains::identity::impersonation::state::{
    ImpersonationConsent, ImpersonationStatus,
};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ImpersonationStatus as "impersonation status" {
        AwaitingConsent => "awaiting_consent",
        Active => "active",
        Declined => "declined",
        Ended => "ended",
    }
}

stored_words! {
    ImpersonationConsent as "impersonation consent" {
        AdminDecides => "admin_decides",
        HolderApproves => "holder_approves",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Each word is the name the domain gives the choice, so a row reads
    /// the same to every reader of it.
    #[test]
    fn every_word_is_the_domains_own_name() {
        for status in [
            ImpersonationStatus::AwaitingConsent,
            ImpersonationStatus::Active,
            ImpersonationStatus::Declined,
            ImpersonationStatus::Ended,
        ] {
            assert_eq!(status.word(), status.as_str());
        }
        for consent in [
            ImpersonationConsent::AdminDecides,
            ImpersonationConsent::HolderApproves,
        ] {
            assert_eq!(consent.word(), consent.as_str());
        }
    }
}
