//! Upstream services.

use async_trait::async_trait;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ServiceId;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a service listing can be ordered by.
    pub enum ServiceSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by service name.
        Name => "name",
    }
    default = Name;
}

impl SortKeys<ServiceSortField> for Service<ResolvedTenant> {
    fn sort_key(&self, field: ServiceSortField) -> SortKey {
        match field {
            ServiceSortField::CreatedAt => self.created_at().into(),
            ServiceSortField::UpdatedAt => self.updated_at().into(),
            ServiceSortField::Name => self.name().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving services.
#[async_trait]
pub trait ServiceStore: Send + Sync + TenantScoped {
    /// Finds a service by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the service cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceId,
    ) -> Result<Option<Service<ResolvedTenant>>, DomainError>;

    /// Finds several services by ID in one query.
    ///
    /// The proxy compiles a whole tenant's route table at once and needs every
    /// service those routes name; asking per route would be one round trip per
    /// route.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the services cannot be read.
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[ServiceId],
    ) -> Result<Vec<Service<ResolvedTenant>>, DomainError>;

    /// Lists services for the tenant with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the services cannot be read.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ServiceSortField>,
        page: &PageRequest,
    ) -> Result<Page<Service<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated service.
    ///
    /// A host the service's app sign-in answers on, or its own session
    /// cookie is set on, belongs to it alone in the tenant: two services
    /// answering sign-in on one host would each hand out sessions the other
    /// trusts.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when another service of the tenant has the
    ///   name, or already answers sign-in or sets its cookie on one of the
    ///   hosts.
    /// - [`DomainError::Infrastructure`] if the service cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        service: &Service<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a service by ID.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when a route still points at it, or another
    ///   service still accepts its app sign-in: the foreign key refuses the
    ///   delete rather than taking the others with it.
    /// - [`DomainError::Infrastructure`] if the service cannot be deleted.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &ServiceId) -> Result<(), DomainError>;

    /// How many routes point at this service.
    ///
    /// Answers "may this be deleted", and fills the route count a listing
    /// shows beside each service.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the routes cannot be counted.
    async fn route_count(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceId,
    ) -> Result<u64, DomainError>;
}
