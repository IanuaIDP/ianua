//! Groups and their members.

use async_trait::async_trait;
use ianua_domain::domains::authorization::group::{Group, GroupMembership};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, Label, PrincipalRef, RoleId};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authorization::{HoldingBatch, MembershipPosition};
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a group listing can be ordered by.
    pub enum GroupSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by name.
        Name => "name",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<GroupSortField> for Group<ResolvedTenant> {
    fn sort_key(&self, field: GroupSortField) -> SortKey {
        match field {
            GroupSortField::CreatedAt => self.created_at().into(),
            GroupSortField::UpdatedAt => self.updated_at().into(),
            GroupSortField::Name => self.name().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

define_sort_field! {
    /// The one order a group's members are listed in: oldest membership
    /// first.
    pub enum GroupMemberSortField {
        /// Order by when the member joined.
        JoinedAt => "joined_at",
    }
    default = JoinedAt;
}

impl SortKeys<GroupMemberSortField> for GroupMembership<ResolvedTenant> {
    fn sort_key(&self, field: GroupMemberSortField) -> SortKey {
        match field {
            GroupMemberSortField::JoinedAt => self.joined_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.principal().id().into()
    }
}

/// Dyn-safe port for persisting and retrieving groups.
#[async_trait]
pub trait GroupStore: Send + Sync + TenantScoped {
    /// Finds a group by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &GroupId,
    ) -> Result<Option<Group<ResolvedTenant>>, DomainError>;

    /// Finds the requested groups in one read, in no guaranteed order.
    /// Missing groups and groups of another tenant are omitted.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[GroupId],
    ) -> Result<Vec<Group<ResolvedTenant>>, DomainError>;

    /// Finds a group by its name (unique within tenant).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &Label,
    ) -> Result<Option<Group<ResolvedTenant>>, DomainError>;

    /// One page of the tenant's groups, in `sort`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<GroupSortField>,
        page: &PageRequest,
    ) -> Result<Page<Group<ResolvedTenant>>, DomainError>;

    /// Lists child groups of a parent.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn list_children(
        &self,
        tenant_id: &ScopedTenant,
        parent_id: &GroupId,
    ) -> Result<Vec<Group<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated group.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the group cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        group: &Group<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a group by ID.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the group cannot be deleted.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &GroupId) -> Result<(), DomainError>;

    /// Counts the tenant's groups carrying `role_id` among their roles, in
    /// one query.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn count_carrying_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError>;
}

/// Dyn-safe port for persisting and retrieving group memberships.
#[async_trait]
pub trait GroupMembershipStore: Send + Sync + TenantScoped {
    /// Lists all memberships for a principal.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError>;

    /// Lists all members of a group.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError>;

    /// Every member of each of `group_ids`, read in one query. Callers pass
    /// one page of groups, so the read stays bounded.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_groups(
        &self,
        tenant_id: &ScopedTenant,
        group_ids: &[GroupId],
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError>;

    /// One page of a group's members, oldest membership first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn list_by_group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
        page: &PageRequest,
    ) -> Result<Page<GroupMembership<ResolvedTenant>>, DomainError>;

    /// Checks whether a principal is a member of a group still in force
    /// now. A place whose end has come counts for nothing, whether or not
    /// the sweep has cleared it yet.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn exists(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        group_id: &GroupId,
    ) -> Result<bool, DomainError>;

    /// At most 500 expired memberships after the complete key in `batch`,
    /// ordered by expiry, group, principal kind and principal id. A sweep keeps
    /// the cutoff fixed and advances past failures as well as successful removals.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        batch: &HoldingBatch<MembershipPosition>,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError>;

    /// Saves a new membership. A place the principal holds still in force
    /// is left as it is; one whose end had come by the time they joined,
    /// not yet cleared by the sweep, is replaced by it.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the membership cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        membership: &GroupMembership<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Clears `membership` away for the sweep, only while its end has still
    /// come by `now`, and answers whether it did. A place given again since
    /// the sweep read it is in force once more, and is left.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the membership cannot be deleted.
    async fn remove_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        membership: &GroupMembership<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Saves each of `memberships` in one statement. A membership the
    /// principal holds still in force is left as it is, and one whose end
    /// had come is replaced.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the memberships cannot be written.
    async fn save_all(
        &self,
        tenant_id: &ScopedTenant,
        memberships: &[GroupMembership<ResolvedTenant>],
    ) -> Result<(), DomainError>;

    /// Removes a membership.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the membership cannot be deleted.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        group_id: &GroupId,
    ) -> Result<(), DomainError>;

    /// Removes the membership in `group_id` of each of `principals`, in one
    /// statement. A principal who is not a member is passed over.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the memberships cannot be deleted.
    async fn delete_all(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
        principals: &[PrincipalRef],
    ) -> Result<(), DomainError>;
}
