//! Organization sessions and the devices members trust.

use async_trait::async_trait;
use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId, SessionId, TokenHash, TrustedDeviceId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};

define_sort_field! {
    /// Field an active-session listing can be ordered by.
    pub enum OrgSessionSortField {
        /// Order by session creation time.
        CreatedAt => "created_at",
        /// Order by last activity time.
        LastActiveAt => "last_active_at",
        /// Order by absolute expiry time.
        ExpiresAt => "expires_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<OrgSessionSortField> for OrgSession {
    fn sort_key(&self, field: OrgSessionSortField) -> SortKey {
        match field {
            OrgSessionSortField::CreatedAt => self.created_at().into(),
            OrgSessionSortField::LastActiveAt => self.last_active_at().into(),
            OrgSessionSortField::ExpiresAt => self.expires_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving org sessions.
#[async_trait]
pub trait OrgSessionStore: Send + Sync {
    /// Finds an org session by its unique ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(&self, id: &SessionId) -> Result<Option<OrgSession>, DomainError>;

    /// Finds an org session by its refresh token hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_refresh_token_hash(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<OrgSession>, DomainError>;

    /// Saves a new or updated org session.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, session: &OrgSession) -> Result<(), DomainError>;

    /// Lists active (non-expired, non-revoked) sessions for an organization
    /// with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_active(
        &self,
        organization_id: &OrganizationId,
        sort: &SortOrder<OrgSessionSortField>,
        page: &PageRequest,
    ) -> Result<Page<OrgSession>, DomainError>;

    /// Lists the sessions of `org_user_id` still in force, neither ended
    /// nor expired, newest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_active_by_member(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgSession>, DomainError>;

    /// Revokes a single session by ID, unless it already was, suspended
    /// ones included. Answers whether one was revoked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke_by_id(&self, session_id: &SessionId) -> Result<bool, DomainError>;

    /// Revokes every session of an org user not revoked yet. Returns how
    /// many went.
    ///
    /// A suspended session is revoked too: it returns to active once its
    /// second factor is proved, so signing someone out everywhere must
    /// reach it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke_all_by_user(&self, org_user_id: &OrgUserId) -> Result<u64, DomainError>;

    /// Revokes every session of an entire organization not revoked yet,
    /// suspended ones included. Returns how many went.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke_all_by_org(&self, organization_id: &OrganizationId)
    -> Result<u64, DomainError>;

    /// Deletes expired and revoked sessions older than the given retention period.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn purge_expired(&self, retention_days: u32) -> Result<u64, DomainError>;
}

/// Dyn-safe port for org user trusted devices.
///
/// Stores devices in `org_trusted_devices` (control plane DB). Scoped by
/// `org_user_id` rather than by organization: a device is trusted by the
/// person sitting at it, and an admin of the same organization has no business
/// seeing or revoking someone else's laptop.
#[async_trait]
pub trait OrgTrustedDeviceStore: Send + Sync {
    /// Lists every device an org user has trusted, revoked ones included.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<TrustedDevice<ResolvedOrganization>>, DomainError>;

    /// Finds one of an org user's devices by its id.
    ///
    /// Takes the owner as well as the id so a device belonging to someone else
    /// reads as absent rather than as something to act on.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(
        &self,
        org_user_id: &OrgUserId,
        id: &TrustedDeviceId,
    ) -> Result<Option<TrustedDevice<ResolvedOrganization>>, DomainError>;

    /// Saves a new or updated device of `org_user_id`. A device's owner
    /// never changes once it is kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the device was trusted by
    /// someone other than `org_user_id`, `DomainError::Conflict` when its id
    /// is already kept for another member, and
    /// `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        org_user_id: &OrgUserId,
        device: &TrustedDevice<ResolvedOrganization>,
    ) -> Result<(), DomainError>;
}
