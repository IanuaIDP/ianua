//! The words a member's choices are stored as.

use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    OrgUserStatus as "member status" {
        Invited => "invited",
        PendingVerification => "pending_verification",
        Active => "active",
        Locked => "locked",
        Deactivated => "deactivated",
        Closing => "closing",
    }
}

stored_words! {
    OrgRole as "organization role" {
        Viewer => "viewer",
        Billing => "billing",
        Member => "member",
        Admin => "admin",
        Owner => "owner",
    }
}

stored_words! {
    AddressStanding as "address standing" {
        Unverified => "unverified",
        Verified => "verified",
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
            OrgUserStatus::Invited,
            OrgUserStatus::PendingVerification,
            OrgUserStatus::Active,
            OrgUserStatus::Locked,
            OrgUserStatus::Deactivated,
            OrgUserStatus::Closing,
        ] {
            assert_eq!(status.word(), status.as_str());
            assert_eq!(OrgUserStatus::from_word(status.word()), Some(status));
        }
    }

    /// Every role reads back from the word it is stored as.
    #[test]
    fn every_role_reads_back_from_its_word() {
        for role in OrgRole::ALL {
            assert_eq!(OrgRole::from_word(role.word()), Some(role));
        }
    }
}
