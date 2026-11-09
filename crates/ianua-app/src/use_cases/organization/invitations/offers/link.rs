//! Finding the invitation an emailed link belongs to, the first step of
//! every page behind that link: reading it, accepting it and turning it
//! down.

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::members::invitation::OrgInvitation;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{OrganizationId, TokenStatus};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::OrgInvitationStore;

/// Where an invitation link is looked up, and how its token is hashed.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::invitations) struct InvitationLinks<'a> {
    /// The organization's invitations.
    pub(in crate::use_cases::organization::invitations) invitations: &'a dyn OrgInvitationStore,
    /// Hashes the token the link carries.
    pub(in crate::use_cases::organization::invitations) token_generator:
        &'a dyn RefreshTokenGenerator,
}

impl InvitationLinks<'_> {
    /// The invitation of `organization_id` the link `raw_token` belongs to,
    /// whatever it is worth, or nothing for a link it never sent.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::Internal` on lookup failure.
    pub(in crate::use_cases::organization::invitations) async fn followed(
        &self,
        organization_id: &OrganizationId,
        raw_token: &str,
    ) -> Result<Option<OrgInvitation>, AppError> {
        crate::input::validate_token("token", raw_token)?;
        let token_hash = self.token_generator.hash_raw(raw_token);
        self.invitations
            .find_by_token_hash(organization_id, &token_hash)
            .await
            .or_internal()
    }

    /// The still open invitation the link `raw_token` belongs to.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is unknown, or the invitation was
    ///   accepted, declined or revoked.
    /// - `AppError::LinkExpired` if it ran out unused: an owner can send it
    ///   again.
    /// - `AppError::Internal` on lookup failure.
    pub(in crate::use_cases::organization::invitations) async fn open(
        &self,
        organization_id: &OrganizationId,
        raw_token: &str,
    ) -> Result<OrgInvitation, AppError> {
        let invitation = self
            .followed(organization_id, raw_token)
            .await?
            .or_not_found(message!(
                "identity-invalid-invitation-token",
                "invalid invitation token"
            ))?;
        ensure_still_open(&invitation)?;
        Ok(invitation)
    }
}

/// Refuses an invitation whose link ran out or was closed, telling the two
/// apart.
fn ensure_still_open(invitation: &OrgInvitation) -> Result<(), AppError> {
    match TokenStatus::from(invitation.state(clock::now())) {
        TokenStatus::Valid => Ok(()),
        TokenStatus::Expired => Err(AppError::LinkExpired(message!(
            "identity-this-invitation-has-expired",
            "this invitation has expired"
        ))),
        TokenStatus::AlreadyUsed | TokenStatus::Invalid => Err(AppError::NotFound(message!(
            "identity-invitation-already-used",
            "invitation already used"
        ))),
    }
}
