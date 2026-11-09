//! HTTP routes.

use async_trait::async_trait;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PipelineId, RouteId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a route listing can be ordered by.
    pub enum RouteSortField {
        /// Order by dispatch priority (lowest first).
        Priority => "priority",
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by route name.
        Name => "name",
        /// Order by lifecycle status.
        Status => "status",
    }
    default = Priority;
}

impl SortKeys<RouteSortField> for Route<ResolvedTenant> {
    fn sort_key(&self, field: RouteSortField) -> SortKey {
        match field {
            RouteSortField::Priority => u32::from(self.priority()).into(),
            RouteSortField::CreatedAt => self.created_at().into(),
            RouteSortField::UpdatedAt => self.updated_at().into(),
            RouteSortField::Name => self.name().as_str().into(),
            RouteSortField::Status => route_status_word(self.status()).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word a route's status sorts by, as it is stored.
fn route_status_word(status: RouteStatus) -> &'static str {
    match status {
        RouteStatus::Active => "active",
        RouteStatus::Disabled => "disabled",
    }
}

/// Dyn-safe port for persisting and retrieving routes.
#[async_trait]
pub trait RouteStore: Send + Sync + TenantScoped {
    /// Finds a route by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the route cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &RouteId,
    ) -> Result<Option<Route<ResolvedTenant>>, DomainError>;

    /// Lists routes for the tenant with optional status filter, ordering, and
    /// pagination.
    ///
    /// Defaults to ascending priority order.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the routes cannot be read.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<RouteStatus>,
        sort: &SortOrder<RouteSortField>,
        page: &PageRequest,
    ) -> Result<Page<Route<ResolvedTenant>>, DomainError>;

    /// Every route of the tenant that runs `pipeline_id`, whatever its
    /// status, in priority order.
    ///
    /// Unpaged: the domain checks a pipeline against all of its routes, and
    /// a tenant's routes on one pipeline are bounded by its plan.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the routes cannot be read.
    async fn list_by_pipeline(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<Vec<Route<ResolvedTenant>>, DomainError>;

    /// Every active route of the tenant open to workflows, in priority
    /// order: the apps a Protected apps step may call.
    ///
    /// Unpaged: a tenant's routes are bounded by its plan.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the routes cannot be read.
    async fn list_open_to_workflows(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Route<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated route.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when another route of the tenant has the
    ///   name.
    /// - [`DomainError::Infrastructure`] if the route cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        route: &Route<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a route by ID.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the route cannot be deleted.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &RouteId) -> Result<(), DomainError>;
}
