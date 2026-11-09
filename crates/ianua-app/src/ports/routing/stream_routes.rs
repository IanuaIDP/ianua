//! Stream routes and finding them by listener.

use async_trait::async_trait;
use ianua_domain::domains::routing::stream::{StreamRoute, WorkflowLogin};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{StreamRouteId, TenantId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a stream route listing can be ordered by.
    pub enum StreamRouteSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by name.
        Name => "name",
        /// Order by the port listened on.
        ListenPort => "listen_port",
    }
    default = ListenPort;
}

impl SortKeys<StreamRouteSortField> for StreamRoute<ResolvedTenant> {
    fn sort_key(&self, field: StreamRouteSortField) -> SortKey {
        match field {
            StreamRouteSortField::CreatedAt => self.created_at().into(),
            StreamRouteSortField::UpdatedAt => self.updated_at().into(),
            StreamRouteSortField::Name => self.name().as_str().into(),
            StreamRouteSortField::ListenPort => u32::from(self.listen_port().get()).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving stream routes.
#[async_trait]
pub trait StreamRouteStore: Send + Sync + TenantScoped {
    /// Finds a stream route by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the stream route cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<Option<StreamRoute<ResolvedTenant>>, DomainError>;

    /// Lists a tenant's stream routes with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the stream routes cannot be read.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<StreamRouteSortField>,
        page: &PageRequest,
    ) -> Result<Page<StreamRoute<ResolvedTenant>>, DomainError>;

    /// Every active stream route of the tenant open to workflows, by name:
    /// the systems a Protected data step may reach.
    ///
    /// Unpaged: a tenant's stream routes are bounded by its plan.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the stream routes cannot be read.
    async fn list_open_to_workflows(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<StreamRoute<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated stream route.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the port is already claimed, by this
    ///   tenant or any other. A listening port belongs to the deployment, not
    ///   to a tenant, so the clash is reported here rather than discovered by
    ///   a listener that cannot bind.
    /// - [`DomainError::Conflict`] when another stream route of the tenant
    ///   has the name.
    /// - [`DomainError::Infrastructure`] if the stream route cannot be
    ///   written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        route: &StreamRoute<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a stream route by ID, releasing its port.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the stream route cannot be deleted.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &StreamRouteId)
    -> Result<(), DomainError>;
}

/// Dyn-safe port keeping the login each stream route open to workflows
/// signs in with, apart from the route itself.
///
/// The adapter keeps it where the gateway, which reads every route, cannot
/// read it: only the worker making a Protected data step's call needs it.
/// Its password is kept as sealed, and never opened here.
#[async_trait]
pub trait StreamRouteLogins: Send + Sync + TenantScoped {
    /// The login kept for stream route `id`, if one is.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if it cannot be read.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<Option<WorkflowLogin>, DomainError>;

    /// Keeps `login` for stream route `id`, in place of any kept before.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if it cannot be written.
    async fn keep(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
        login: &WorkflowLogin,
    ) -> Result<(), DomainError>;

    /// Forgets the login of stream route `id`; none kept is no error.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if it cannot be removed.
    async fn forget(&self, tenant_id: &ScopedTenant, id: &StreamRouteId)
    -> Result<(), DomainError>;
}

/// Dyn-safe port for reading every tenant's active stream routes at once.
///
/// Separate from [`StreamRouteStore`], and deliberately not tenant-scoped: the
/// data plane binds one socket per port for the whole deployment, so it has to
/// ask across tenants before it knows which tenant a connection belongs to.
/// That is the one question `TenantScoped` cannot express, and giving it its
/// own port keeps it from becoming a hole in the scoped one.
#[async_trait]
pub trait StreamRouteDirectory: Send + Sync {
    /// Every active stream route across the deployment, with its tenant.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the stream routes cannot be read.
    async fn active_routes(
        &self,
    ) -> Result<Vec<(TenantId, StreamRoute<ResolvedTenant>)>, DomainError>;
}
