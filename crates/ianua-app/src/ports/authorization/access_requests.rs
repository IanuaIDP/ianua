//! Just-in-time access requests: asked, answered, withdrawn or run out,
//! and the limit a tenant sets on how long one may ask for.

use async_trait::async_trait;
use ianua_domain::domains::authorization::access_request::AccessRequest;
use ianua_domain::domains::authorization::request_policy::AccessRequestPolicy;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AccessRequestId, PrincipalRef};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// The one order access requests are listed in: newest first.
    pub enum AccessRequestSortField {
        /// Order by when the request was made.
        RequestedAt => "requested_at",
    }
    default = RequestedAt;
    default direction = Desc;
}

impl SortKeys<AccessRequestSortField> for AccessRequest<ResolvedTenant> {
    fn sort_key(&self, field: AccessRequestSortField) -> SortKey {
        match field {
            AccessRequestSortField::RequestedAt => self.requested_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Which of a tenant's access requests a listing shows, newest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessRequestFilter {
    /// Every request.
    All,
    /// Only those still waiting for an answer.
    Pending,
    /// Only those asked through this account.
    AskedBy(PrincipalRef),
}

/// Dyn-safe port for persisting and retrieving access requests.
#[async_trait]
pub trait AccessRequestStore: Send + Sync + TenantScoped {
    /// Finds a request by its id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccessRequestId,
    ) -> Result<Option<AccessRequest<ResolvedTenant>>, DomainError>;

    /// The requests `filter` keeps, newest first, one page of them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: AccessRequestFilter,
        page: &PageRequest,
    ) -> Result<Page<AccessRequest<ResolvedTenant>>, DomainError>;

    /// One page of requests still pending whose answer window has closed by
    /// `now`, asked at least `ANSWER_WINDOW` before it, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<AccessRequest<ResolvedTenant>>, DomainError>;

    /// Saves a new or changed request.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the request cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &AccessRequest<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for the one limit each tenant sets on how long its people
/// may ask for access.
#[async_trait]
pub trait AccessRequestPolicyStore: Send + Sync + TenantScoped {
    /// The tenant's policy, or `None` when it never set one.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AccessRequestPolicy<ResolvedTenant>>, DomainError>;

    /// Saves the tenant's policy, replacing the one stored.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the policy cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        policy: &AccessRequestPolicy<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}
