//! The resource types a tenant declares.

use async_trait::async_trait;
use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::authorization::resource_type::ResourceType;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ResourceTypeId;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a resource type listing can be ordered by.
    pub enum ResourceTypeSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by the key used in `resource:action`.
        Key => "key",
    }
    default = Key;
    default direction = Asc;
}

impl SortKeys<ResourceTypeSortField> for ResourceType<ResolvedTenant> {
    fn sort_key(&self, field: ResourceTypeSortField) -> SortKey {
        match field {
            ResourceTypeSortField::CreatedAt => self.created_at().into(),
            ResourceTypeSortField::UpdatedAt => self.updated_at().into(),
            ResourceTypeSortField::Key => self.key().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for a tenant's permission catalogue.
///
/// The catalogue names what the tenant's own application protects. A role's
/// permissions are checked against it when somebody edits one, and the
/// gateway walks its ladders so a held action brings the ones it implies.
#[async_trait]
pub trait ResourceTypeStore: Send + Sync + TenantScoped {
    /// Finds a resource type by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ResourceTypeId,
    ) -> Result<Option<ResourceType<ResolvedTenant>>, DomainError>;

    /// Finds a resource type by the key it uses in `resource:action`.
    ///
    /// Keys are unique within a tenant.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_key(
        &self,
        tenant_id: &ScopedTenant,
        key: &PermissionSegment,
    ) -> Result<Option<ResourceType<ResolvedTenant>>, DomainError>;

    /// One page of the catalogue, in `sort`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ResourceTypeSortField>,
        page: &PageRequest,
    ) -> Result<Page<ResourceType<ResolvedTenant>>, DomainError>;

    /// Lists the whole catalogue, unpaginated.
    ///
    /// Used to check a set of permissions against every declaration at once,
    /// where paging would mean re-reading the catalogue per permission.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn list_every(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ResourceType<ResolvedTenant>>, DomainError>;

    /// Persists a new or updated resource type.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the resource type cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        resource_type: &ResourceType<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a resource type.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the resource type cannot be deleted.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &ResourceTypeId,
    ) -> Result<(), DomainError>;

    /// How many roles currently hold a permission naming `key`.
    ///
    /// Deleting a declaration that roles still refer to would leave permissions
    /// nothing defines, which is the free-text situation the catalogue exists
    /// to end.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn count_roles_using(
        &self,
        tenant_id: &ScopedTenant,
        key: &PermissionSegment,
    ) -> Result<u64, DomainError>;
}
