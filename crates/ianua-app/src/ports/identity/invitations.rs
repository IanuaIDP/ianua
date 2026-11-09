//! Invitations to join a tenant.

use async_trait::async_trait;
use ianua_domain::domains::identity::invitations::invitation::Invitation;
use ianua_domain::domains::identity::invitations::status::InvitationLifecycle;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, RoleId, TokenHash, UserId};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Which open invitations a listing should be narrowed to.
///
/// Derived at read time from the invitation's lifecycle rather than stored:
/// an invitation sits in the database as `Pending` until it is used, whether
/// or not its window has closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationState {
    /// Sent and still inside its expiry window.
    Pending,
    /// Sent but past its expiry, so the link no longer works.
    Expired,
}

impl InvitationState {
    /// How a listing shows an invitation the domain reads as `lifecycle`,
    /// or `None` for one already accepted, declined or revoked, which is
    /// open no longer.
    #[must_use]
    pub fn of(lifecycle: InvitationLifecycle) -> Option<Self> {
        match lifecycle {
            InvitationLifecycle::Pending => Some(Self::Pending),
            InvitationLifecycle::Expired => Some(Self::Expired),
            InvitationLifecycle::Closed => None,
        }
    }
}

/// An invitation state evaluated at one instant, shared by selection and
/// enrichment so an expiry boundary does not move between those reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvitationFilter {
    /// The state an open invitation must have.
    pub state: InvitationState,
    /// The instant its expiry is compared with.
    pub at: OffsetDateTime,
}

define_sort_field! {
    /// The stable order used by the tenant invitation expiry sweep.
    pub enum InvitationSweepSortField {
        /// Process invitations in creation order, with their id breaking ties.
        CreatedAt => "created_at",
    }
    default = CreatedAt;
    default direction = Asc;
}

impl SortKeys<InvitationSweepSortField> for Invitation<ResolvedTenant> {
    fn sort_key(&self, field: InvitationSweepSortField) -> SortKey {
        match field {
            InvitationSweepSortField::CreatedAt => self.created_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving invitations.
#[async_trait]
pub trait InvitationStore: Send + Sync + TenantScoped {
    /// Finds an invitation by its token hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<Invitation<ResolvedTenant>>, DomainError>;

    /// Finds a pending invitation for an email.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_pending_by_email(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<Invitation<ResolvedTenant>>, DomainError>;

    /// Finds a pending invitation for a user by their stable id.
    ///
    /// Preferred over the email lookup for actions on a known user, since a
    /// user's email can change after the invitation is sent.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_pending_by_user_id(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<Invitation<ResolvedTenant>>, DomainError>;

    /// Every invitation kept for the invited account `user_id`, whatever
    /// its status, newest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_by_user_id(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError>;

    /// The latest stored-pending invitation for each requested user, including
    /// expired links. Missing users are omitted; ordering is unspecified.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn latest_pending_for_users(
        &self,
        tenant_id: &ScopedTenant,
        users: &[UserId],
    ) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError>;

    /// Lists pending invitations for the tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_pending(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError>;

    /// The tenant's invitations still stored as pending whose link ran out
    /// by `now`, oldest first, in one bounded page. Keep `now` fixed while
    /// following the returned cursor, including past invitations that failed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<Invitation<ResolvedTenant>>, DomainError>;

    /// How many of the tenant's invitations still pending give `role_id`
    /// once accepted, their link run out or not: each is someone waiting to
    /// get that role, so the role cannot be deleted under them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn count_pending_for_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError>;

    /// Saves a new or updated invitation.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        invitation: &Invitation<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}
