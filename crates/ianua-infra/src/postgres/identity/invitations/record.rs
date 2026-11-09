//! An invitation as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::identity::invitations::invitation::{Invitation, InvitationRow};
use ianua_domain::domains::identity::invitations::offer::OfferState;
use ianua_domain::domains::identity::invitations::status::InvitationStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, InvitationId, RoleId, Text, TokenHash, UserId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const INVITATION: Stored = Stored("invitation");

const INVITED_BY: Kept = Kept {
    entity: INVITATION.0,
    column: "invited_by",
    shape: 1,
};

/// An invitation as it is read. The store's checked queries fill it.
pub(super) struct InvitationRecord {
    pub(super) id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) email: String,
    pub(super) invited_by: Value,
    pub(super) role_id: Uuid,
    pub(super) token_hash: String,
    pub(super) status: String,
    pub(super) accepted_at: Option<OffsetDateTime>,
    pub(super) message: Option<String>,
    pub(super) expires_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
}

impl InvitationRecord {
    /// The invitation the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the
    /// invitation keeps.
    pub(super) fn into_invitation(self) -> Result<Invitation<ResolvedTenant>, DomainError> {
        let status: InvitationStatus = INVITATION.choice(&self.status)?;
        Invitation::reconstitute(InvitationRow {
            id: InvitationId::from_uuid(self.id),
            user_id: UserId::from_uuid(self.user_id),
            email: INVITATION.value("email", Email::new(self.email))?,
            invited_by: INVITED_BY.open(self.invited_by)?,
            role_id: RoleId::from_uuid(self.role_id),
            token_hash: TokenHash::from_stored(self.token_hash),
            state: OfferState::from_stored(status, self.accepted_at)?,
            message: self
                .message
                .map(|message| INVITATION.value("message", Text::new("message", message)))
                .transpose()?,
            expires_at: self.expires_at,
            created_at: self.created_at,
        })
    }
}

/// An invitation's columns, as they are written.
pub(super) struct InvitationColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) email: &'a str,
    pub(super) invited_by: Value,
    pub(super) role_id: &'a Uuid,
    pub(super) token_hash: &'a str,
    pub(super) status: &'static str,
    pub(super) accepted_at: Option<OffsetDateTime>,
    pub(super) message: Option<&'a str>,
    pub(super) expires_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> InvitationColumns<'a> {
    /// The columns `invitation` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who sent it cannot be
    /// written out as JSON.
    pub(super) fn of(invitation: &'a Invitation<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: invitation.id().as_uuid(),
            user_id: invitation.user_id().as_uuid(),
            email: invitation.email().as_str(),
            invited_by: INVITED_BY.seal(invitation.invited_by())?,
            role_id: invitation.role_id().as_uuid(),
            token_hash: invitation.token_hash().as_str(),
            status: invitation.status().word(),
            accepted_at: invitation.accepted_at(),
            message: invitation.message().map(Text::as_str),
            expires_at: invitation.expires_at(),
            created_at: invitation.created_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::types::{ActorRef, OrgUserId};
    use serde_json::json;

    use super::*;

    /// Who sent an invitation, a tenant user or an organization member, is
    /// written in the shape pinned here, and a row in that shape reads back
    /// the same.
    #[test]
    fn who_sent_an_invitation_is_stored_in_its_pinned_shape() {
        let ann = UserId::from_uuid(Uuid::from_u128(7));
        let member = OrgUserId::from_uuid(Uuid::from_u128(8));
        let by_user = json!({"v": 1, "value": {"User": "00000000-0000-0000-0000-000000000007"}});
        let by_member =
            json!({"v": 1, "value": {"OrgUser": "00000000-0000-0000-0000-000000000008"}});

        assert_eq!(INVITED_BY.seal(&ActorRef::User(ann)).unwrap(), by_user);
        assert_eq!(
            INVITED_BY.seal(&ActorRef::OrgUser(member)).unwrap(),
            by_member
        );
        let read: ActorRef = INVITED_BY.open(by_member.clone()).unwrap();
        assert_eq!(INVITED_BY.seal(&read).unwrap(), by_member);
    }
}
