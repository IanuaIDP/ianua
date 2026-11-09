//! Keeping an invited member and their invitation together, as inviting
//! and accepting both change the two.

use ianua_domain::domains::organization::members::invitation::OrgInvitation;
use ianua_domain::domains::organization::members::org_user::OrgUser;

use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgInvitationStore, OrgUserStore};

/// Where invited members and their invitations are kept.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::invitations) struct InvitationRecords<'a> {
    /// The organization's members.
    pub(in crate::use_cases::organization::invitations) members: &'a dyn OrgUserStore,
    /// Saves the offers together with the accounts waiting on them.
    pub(in crate::use_cases::organization::invitations) invitations: &'a dyn OrgInvitationStore,
}

impl InvitationRecords<'_> {
    /// Saves `invitee`, then `invitation`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when either cannot be saved.
    pub(in crate::use_cases::organization::invitations) async fn save(
        &self,
        invitee: &OrgUser,
        invitation: &OrgInvitation,
    ) -> Result<(), AppError> {
        self.members.save(invitee).await.or_internal()?;
        self.invitations.save(invitation).await.or_internal()
    }
}
