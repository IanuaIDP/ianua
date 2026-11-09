//! An invitation as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::identity::invitations::offer::OfferState;
use ianua_domain::domains::organization::members::invitation::{OrgInvitation, OrgInvitationRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OrgInvitationId, OrgUserId, OrganizationId, Text, TokenHash};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const INVITATION: Stored = Stored("organization invitation");

/// An invitation as it is read. The store's checked queries fill it.
pub(super) struct InvitationRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) org_user_id: Uuid,
    pub(super) email: String,
    pub(super) invited_by: Uuid,
    pub(super) token_hash: String,
    pub(super) status: String,
    pub(super) accepted_at: Option<OffsetDateTime>,
    pub(super) message: Option<String>,
    pub(super) expires_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
}

impl InvitationRecord {
    /// The invitation the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, the status is unknown or contradicts the acceptance time,
    /// or the row breaks a rule the invitation keeps.
    pub(super) fn into_invitation(self) -> Result<OrgInvitation, DomainError> {
        let message = self
            .message
            .map(|message| INVITATION.value("message", Text::new("message", message)))
            .transpose()?;
        OrgInvitation::reconstitute(OrgInvitationRow {
            id: OrgInvitationId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            org_user_id: OrgUserId::from_uuid(self.org_user_id),
            email: INVITATION.value("email", Email::new(self.email))?,
            invited_by: OrgUserId::from_uuid(self.invited_by),
            token_hash: TokenHash::from_stored(self.token_hash),
            state: OfferState::from_stored(INVITATION.choice(&self.status)?, self.accepted_at)?,
            message,
            expires_at: self.expires_at,
            created_at: self.created_at,
        })
    }
}

/// An invitation's columns, as they are written.
pub(super) struct InvitationColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) organization_id: &'a Uuid,
    pub(super) org_user_id: &'a Uuid,
    pub(super) email: &'a str,
    pub(super) invited_by: &'a Uuid,
    pub(super) token_hash: &'a str,
    pub(super) status: &'static str,
    pub(super) accepted_at: Option<OffsetDateTime>,
    pub(super) message: Option<&'a str>,
    pub(super) expires_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> InvitationColumns<'a> {
    /// The columns `invitation` is written to.
    pub(super) fn of(invitation: &'a OrgInvitation) -> Self {
        Self {
            id: invitation.id().as_uuid(),
            organization_id: invitation.organization_id().as_uuid(),
            org_user_id: invitation.org_user_id().as_uuid(),
            email: invitation.email().as_str(),
            invited_by: invitation.invited_by().as_uuid(),
            token_hash: invitation.token_hash().as_str(),
            status: invitation.status().word(),
            accepted_at: invitation.accepted_at(),
            message: invitation.message().map(Text::as_str),
            expires_at: invitation.expires_at(),
            created_at: invitation.created_at(),
        }
    }
}
