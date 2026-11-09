//! Organization members and the tenant identities linked to them.

use async_trait::async_trait;
use ianua_domain::domains::organization::members::linked_identity::LinkedIdentity;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OrgUserId, OrganizationId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};

/// Filter criteria for listing org users.
pub struct OrgUserFilter {
    /// Filter by status. `None` returns all statuses.
    pub status: Option<OrgUserStatus>,
    /// Filter by email substring (case-insensitive search).
    pub email_contains: Option<String>,
    /// Restrict to these org users. `None` places no restriction; `Some(&[])`
    /// matches nobody.
    ///
    /// Used to narrow a page to a set computed elsewhere, invitation state is
    /// the expiry on the invitation row compared against now, which no column
    /// on `org_users` records.
    pub ids: Option<Vec<OrgUserId>>,
}

impl OrgUserFilter {
    /// No filter, returns org users of every status.
    #[must_use]
    pub fn all() -> Self {
        Self {
            status: None,
            email_contains: None,
            ids: None,
        }
    }
}

/// Dyn-safe port for persisting and retrieving linked identities.
#[async_trait]
pub trait LinkedIdentityStore: Send + Sync {
    /// Finds a linked identity by email within an organization.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<LinkedIdentity>, DomainError>;

    /// Saves a new or updated linked identity, with exactly its links.
    ///
    /// An organization keeps one group per address. A new group under an
    /// address another group already holds is refused, never written over
    /// it: two first links racing would otherwise lose one of them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when another group of the
    /// organization holds the address, and `DomainError::Infrastructure` on
    /// persistence failure.
    async fn save(&self, identity: &LinkedIdentity) -> Result<(), DomainError>;

    /// Deletes a linked identity (when all links are removed).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for the read a tenant switch needs: the caller's linked
/// identity, found by email within their organization.
#[async_trait]
pub trait LinkedIdentityLookup: Send + Sync {
    /// Finds a linked identity by email within an organization.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<LinkedIdentity>, DomainError>;
}

define_sort_field! {
    /// Field an org-user listing can be ordered by.
    pub enum OrgUserSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by email address.
        Email => "email",
        /// Order by display name.
        DisplayName => "display_name",
        /// Order by account status.
        Status => "status",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<OrgUserSortField> for OrgUser {
    fn sort_key(&self, field: OrgUserSortField) -> SortKey {
        match field {
            OrgUserSortField::CreatedAt => self.created_at().into(),
            OrgUserSortField::UpdatedAt => self.updated_at().into(),
            OrgUserSortField::Email => self.email().as_str().into(),
            OrgUserSortField::DisplayName => self.display_name().as_str().into(),
            OrgUserSortField::Status => self.status().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving org users.
#[async_trait]
pub trait OrgUserStore: Send + Sync {
    /// Finds an org user by their unique ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(&self, id: &OrgUserId) -> Result<Option<OrgUser>, DomainError>;

    /// Finds the requested members across organizations, once each, in no
    /// order. Missing ids are omitted. Used to name already authorized
    /// principals; organization administration uses scoped lookups instead.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_ids(&self, ids: &[OrgUserId]) -> Result<Vec<OrgUser>, DomainError>;

    /// Finds an org user by ID, confined to one organization.
    ///
    /// Every admin action that names a target user by ID resolves it this
    /// way. An org owner's authority is proven for their own organization
    /// only, so a bare global lookup would let them act on a user in
    /// someone else's organization; a foreign ID resolves to `None` here
    /// and the use case reports it as not found.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id_in_org(
        &self,
        organization_id: &OrganizationId,
        id: &OrgUserId,
    ) -> Result<Option<OrgUser>, DomainError>;

    /// Finds a member within their organization and holds the record until
    /// the caller's unit of work ends, so a competing mutation reads the
    /// committed role before deciding whether another handover is allowed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn hold_by_id_in_org(
        &self,
        organization_id: &OrganizationId,
        id: &OrgUserId,
    ) -> Result<Option<OrgUser>, DomainError>;

    /// Serializes ownership changes until the current unit of work ends.
    /// Acquire before reading members or owners and before member row locks,
    /// so competing demotions, removals and transfers see committed standing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on locking failure.
    async fn hold_ownership(&self, organization_id: &OrganizationId) -> Result<(), DomainError>;

    /// The organization's owners, of every status, as they stand now.
    ///
    /// Read before a member is demoted, locked, deactivated or removed, so
    /// the domain can refuse taking away the last active owner. Ownership
    /// changes call `hold_ownership` before this read in the same unit of work.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_owners(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<OrgUser>, DomainError>;

    /// Finds an org user by email within an organization.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<OrgUser>, DomainError>;

    /// Every organization's account on this address, one per organization
    /// holding it.
    ///
    /// An address is unique within an organization, not across the
    /// platform: the same person may be a member of several. Sign-in pages
    /// that carry no organization read every account here, and settle which
    /// one only once a password or a mailed link proves it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_all_by_email(&self, email: &Email) -> Result<Vec<OrgUser>, DomainError>;

    /// Whether any organization has an account on this address.
    ///
    /// For the public sign-up form, which tells the holder of such an
    /// address to sign in instead of founding by mail. A new account in one
    /// organization is checked against that organization alone, through
    /// [`find_by_email`](Self::find_by_email); the unique index is on the
    /// organization and the address together.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn email_exists(&self, email: &Email) -> Result<bool, DomainError>;

    /// Lists org users in an organization with optional filtering, ordering,
    /// and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_by_org(
        &self,
        organization_id: &OrganizationId,
        filter: &OrgUserFilter,
        sort: &SortOrder<OrgUserSortField>,
        page: &PageRequest,
    ) -> Result<Page<OrgUser>, DomainError>;

    /// Saves a new or updated org user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, user: &OrgUser) -> Result<(), DomainError>;

    /// Permanently deletes an org user and all associated data.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, id: &OrgUserId) -> Result<(), DomainError>;
}
