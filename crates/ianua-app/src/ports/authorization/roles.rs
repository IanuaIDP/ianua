//! Roles, who holds them, and deleting one with its holders moved.

use std::collections::HashMap;

use async_trait::async_trait;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, GroupId, Label, PrincipalRef, RoleId};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authorization::{AssignmentPosition, HoldingBatch};
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a role listing can be ordered by.
    pub enum RoleSortField {
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

impl SortKeys<RoleSortField> for Role<ResolvedTenant> {
    fn sort_key(&self, field: RoleSortField) -> SortKey {
        match field {
            RoleSortField::CreatedAt => self.created_at().into(),
            RoleSortField::UpdatedAt => self.updated_at().into(),
            RoleSortField::Name => self.name().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving roles.
#[async_trait]
pub trait RoleStore: Send + Sync + TenantScoped {
    /// Finds a role by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &RoleId,
    ) -> Result<Option<Role<ResolvedTenant>>, DomainError>;

    /// Finds several roles by ID in one query.
    ///
    /// Unknown IDs are absent from the result. A grant pointing at a
    /// deleted role contributes no permissions rather than failing the whole
    /// authorization check.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[RoleId],
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError>;

    /// Finds a role by its name (unique within tenant).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &Label,
    ) -> Result<Option<Role<ResolvedTenant>>, DomainError>;

    /// Finds requested role names together, omitting missing names and returning
    /// each matching role once in no guaranteed order.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_names(
        &self,
        tenant_id: &ScopedTenant,
        names: &[Label],
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError>;

    /// One page of the tenant's roles, in `sort`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read, or a validation
    /// error when the page's cursor was made for another sort.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<RoleSortField>,
        page: &PageRequest,
    ) -> Result<Page<Role<ResolvedTenant>>, DomainError>;

    /// Finds the default role(s) auto-assigned to new users.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_defaults(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated role.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the role cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        role: &Role<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a role by ID.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the role cannot be deleted.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &RoleId) -> Result<(), DomainError>;

    /// Loads the roles assigned to a principal *directly* (single query).
    ///
    /// Group-inherited roles are deliberately excluded: this is the set a
    /// caller can revoke. Use [`RoleStore::find_effective_by_principal`] to
    /// answer "what may this principal do".
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError>;

    /// Loads direct roles for a batch of principals in one read, ordered for
    /// each principal by creation time and id. Group roles are excluded.
    /// Principals with no roles may be absent from the map.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_principals(
        &self,
        tenant_id: &ScopedTenant,
        principals: &[PrincipalRef],
    ) -> Result<HashMap<PrincipalRef, Vec<Role<ResolvedTenant>>>, DomainError>;

    /// Loads every role a principal holds in this tenant (single query).
    ///
    /// For a tenant user the result is the union of directly assigned roles and
    /// roles granted through each group they belong to, including those groups'
    /// ancestors. A member of "Backend" (child of "Engineering") holds both
    /// groups' roles. Roles reachable by several paths appear once.
    ///
    /// Groups confer roles on people only, so for any other principal kind this
    /// is the direct set.
    ///
    /// This is the set the authorizer resolves permissions from.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_effective_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port for persisting and retrieving role assignments.
#[async_trait]
pub trait RoleAssignmentStore: Send + Sync + TenantScoped {
    /// Lists all assignments for a principal.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<RoleAssignment<ResolvedTenant>>, DomainError>;

    /// Checks whether a principal holds a specific role still in force now.
    /// One whose end has come counts for nothing, whether or not the sweep
    /// has cleared it yet.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn exists(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        role_id: &RoleId,
    ) -> Result<bool, DomainError>;

    /// Saves a new assignment. One the principal holds still in force is
    /// left as it is; one whose end had come by the time this one was
    /// given, not yet cleared by the sweep, is replaced by it.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the assignment cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        assignment: &RoleAssignment<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Clears `assignment` away for the sweep, only while its end has still
    /// come by `now`, and answers whether it did. One given again since the
    /// sweep read it is in force once more, and is left.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the assignment cannot be deleted.
    async fn remove_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        assignment: &RoleAssignment<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Removes an assignment.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the assignment cannot be deleted.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        role_id: &RoleId,
    ) -> Result<(), DomainError>;

    /// Removes one role from a bounded batch of principals in one statement.
    /// Other roles and tenants remain unchanged; missing assignments are ignored.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the batch cannot be deleted.
    async fn delete_for_principals(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
        principals: &[PrincipalRef],
    ) -> Result<(), DomainError>;

    /// At most 500 expired assignments after the complete key in `batch`,
    /// ordered by expiry, role, principal kind and principal id. A sweep keeps
    /// the cutoff fixed and advances past failures as well as successful removals.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        batch: &HoldingBatch<AssignmentPosition>,
    ) -> Result<Vec<RoleAssignment<ResolvedTenant>>, DomainError>;

    /// Counts principals holding a specific role.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn count_by_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError>;

    /// Counts principals holding each of the given roles in a single query.
    ///
    /// Roles with no assignments are absent from the map; callers default
    /// them to zero.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn count_by_roles(
        &self,
        tenant_id: &ScopedTenant,
        role_ids: &[RoleId],
    ) -> Result<HashMap<RoleId, u64>, DomainError>;
}

/// Dyn-safe unit of work for deleting a role and reassigning its holders.
///
/// The reassignment and the deletion span the `roles` and `role_assignments`
/// tables; this port commits them as a single transaction so a role is never
/// left half-deleted with orphaned or stranded holders.
#[async_trait]
pub trait RoleDeletionUnitOfWork: Send + Sync + TenantScoped {
    /// Moves every holder of `target` onto `replacement`, then deletes
    /// `target`, atomically.
    ///
    /// Holders (users, org users, agents or consumers) who already hold
    /// `replacement` keep their existing assignment; their `target`
    /// assignment is dropped. `reassigned_by` records the actor on the
    /// freshly created assignments. Returns the number of `target`
    /// assignments removed, which counts every holder of every kind. Either
    /// every write commits or none does.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the transaction cannot commit; nothing is
    /// written then.
    async fn reassign_and_delete(
        &self,
        tenant_id: &ScopedTenant,
        target: &RoleId,
        replacement: &RoleId,
        reassigned_by: ActorRef,
    ) -> Result<u64, DomainError>;
}

/// One holder of a role: someone given it straight, or a group carrying it
/// to its members and the members of the groups under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleHolder {
    /// A principal given the role straight.
    Direct(PrincipalRef),
    /// A group carrying the role.
    Group(GroupId),
}

define_sort_field! {
    /// The one order a role's holders are listed in: those given it
    /// straight first, then groups, each by id.
    pub enum RoleHolderSortField {
        /// Order by the kind of holder.
        Kind => "kind",
    }
    default = Kind;
}

impl SortKeys<RoleHolderSortField> for RoleHolder {
    fn sort_key(&self, field: RoleHolderSortField) -> SortKey {
        match (field, self) {
            (RoleHolderSortField::Kind, Self::Direct(_)) => SortKey::Integer(0),
            (RoleHolderSortField::Kind, Self::Group(_)) => SortKey::Integer(1),
        }
    }

    fn tiebreak(&self) -> SortKey {
        match self {
            Self::Direct(principal) => principal.id().into(),
            Self::Group(group_id) => group_id.as_uuid().into(),
        }
    }
}

/// Dyn-safe port reading who holds one role, a page at a time.
///
/// Read across the `role_assignments` and `groups` tables in one query, so
/// the holders of a role held by thousands are paged in storage rather than
/// loaded with every other record of the tenant.
#[async_trait]
pub trait RoleHolderQueries: Send + Sync + TenantScoped {
    /// One page of the holders of `role_id` at `now`, in
    /// [`RoleHolderSortField`]'s order: first each principal given it
    /// straight by an assignment still in force, once each; then each group
    /// carrying it. The order is fixed, so pages neither overlap nor skip.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read, or a validation
    /// error when the page's cursor was made for another list.
    async fn holders_of(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<RoleHolder>, DomainError>;
}
