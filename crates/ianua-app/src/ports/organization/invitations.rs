//! Invitations to an organization.

use async_trait::async_trait;
use ianua_domain::domains::organization::members::invitation::OrgInvitation;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OrgUserId, OrganizationId, TokenHash};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};

define_sort_field! {
    /// The stable order used by the organization invitation expiry sweep.
    pub enum OrgInvitationSweepSortField {
        /// Process invitations in expiry order, with their id breaking ties.
        ExpiresAt => "expires_at",
    }
    default = ExpiresAt;
    default direction = Asc;
}

impl SortKeys<OrgInvitationSweepSortField> for OrgInvitation {
    fn sort_key(&self, field: OrgInvitationSweepSortField) -> SortKey {
        match field {
            OrgInvitationSweepSortField::ExpiresAt => self.expires_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving org invitations.
///
/// Org-keyed (not tenant-scoped): every method takes the owning
/// `organization_id`.
#[async_trait]
pub trait OrgInvitationStore: Send + Sync {
    /// Finds an invitation by its token hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_token_hash(
        &self,
        organization_id: &OrganizationId,
        hash: &TokenHash,
    ) -> Result<Option<OrgInvitation>, DomainError>;

    /// Finds a pending invitation for an email.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_pending_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<OrgInvitation>, DomainError>;

    /// Finds the pending invitation for a specific org user, if any.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_pending_by_org_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<OrgInvitation>, DomainError>;

    /// Lists pending invitations for the organization.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_pending(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<OrgInvitation>, DomainError>;

    /// Lists the invitations still stored as pending whose link ran out at
    /// or before `now`, across every organization, in one bounded page ordered
    /// by expiry and id. Keep `now` fixed while following the returned cursor.
    ///
    /// It crosses organizations on purpose: it backs the background sweep
    /// that marks them expired.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_lapsed(
        &self,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<OrgInvitation>, DomainError>;

    /// Saves a new or updated invitation.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, invitation: &OrgInvitation) -> Result<(), DomainError>;
}
