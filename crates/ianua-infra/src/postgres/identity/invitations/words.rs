//! The words an invitation's status is stored as.

use ianua_domain::domains::identity::invitations::status::InvitationStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    InvitationStatus as "invitation status" {
        Pending => "pending",
        Accepted => "accepted",
        Declined => "declined",
        Expired => "expired",
        Revoked => "revoked",
    }
}
