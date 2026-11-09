//! Organizations.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::status::OrganizationStatus;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantSlug};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};

define_sort_field! {
    /// Field an organization listing can be ordered by.
    pub enum OrganizationSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by organization name.
        Name => "name",
        /// Order by slug.
        Slug => "slug",
        /// Order by lifecycle status.
        Status => "status",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<OrganizationSortField> for Organization {
    fn sort_key(&self, field: OrganizationSortField) -> SortKey {
        match field {
            OrganizationSortField::CreatedAt => self.created_at().into(),
            OrganizationSortField::UpdatedAt => self.updated_at().into(),
            OrganizationSortField::Name => self.name().as_str().into(),
            OrganizationSortField::Slug => self.slug().as_str().into(),
            OrganizationSortField::Status => self.status().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving organizations.
#[async_trait]
pub trait OrganizationStore: Send + Sync {
    /// Finds an organization by its globally unique ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(&self, id: &OrganizationId) -> Result<Option<Organization>, DomainError>;

    /// Finds requested organizations together on the platform. Missing ids are
    /// omitted and each organization appears once, in no guaranteed order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup or reconstitution failure.
    async fn find_by_ids(&self, ids: &[OrganizationId]) -> Result<Vec<Organization>, DomainError>;

    /// Finds an organization by its slug.
    ///
    /// Returns an `Arc` because this is the per-request read-only resolution
    /// path (scope extractor, login).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_slug(
        &self,
        slug: &TenantSlug,
    ) -> Result<Option<Arc<Organization>>, DomainError>;

    /// Checks whether an organization slug is already taken.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn slug_exists(&self, slug: &TenantSlug) -> Result<bool, DomainError>;

    /// Lists organizations with optional status filter, ordering, and
    /// pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_all(
        &self,
        status: Option<OrganizationStatus>,
        sort: &SortOrder<OrganizationSortField>,
        page: &PageRequest,
    ) -> Result<Page<Organization>, DomainError>;

    /// Saves a new or updated organization.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, organization: &Organization) -> Result<(), DomainError>;

    /// Signals that a cached view of the given organization may be stale.
    ///
    /// Called when external changes (e.g. tenant provisioned/deleted) affect
    /// derived fields like `tenant_ids` without modifying the organization row.
    /// The default implementation is a no-op; cache decorators override this.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the cache cannot be reached.
    async fn invalidate(&self, _id: &OrganizationId) -> Result<(), DomainError> {
        Ok(())
    }
}
