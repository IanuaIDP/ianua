//! List services: the backends a tenant's routes can forward to.

use std::sync::Arc;

use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::routing::{ServiceSortField, ServiceStore};
use crate::use_case::Query;
use crate::use_cases::routing::lookup::ensure_may_view_routing;

/// In what order to list the services, and which page of them.
pub struct ListRequest {
    /// The fields and directions to order by.
    pub sort: SortOrder<ServiceSortField>,
    /// Which page of the ordered services to return.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's backends.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Page<Service<ResolvedTenant>>, AppError>;

    /// The page of services `request` asks for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<Service<ResolvedTenant>>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        let ListRequest { sort, page } = request;
        self.ports
            .service_store
            .list_all(&caller.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeServiceStore, service_named, unpinned_upstream};
    use crate::test_support::{block_on, test_ctx};

    fn list(authorities: FakeTenantAuthorities) -> Result<Page<Service<ResolvedTenant>>, AppError> {
        let services = Arc::new(FakeServiceStore::empty());
        for name in ["web", "api"] {
            let service = service_named(name, unpinned_upstream("https://backend:8080"));
            block_on(services.save(&test_ctx().tenant(), &service)).unwrap();
        }
        let use_case = ListUseCase::new(ListPorts {
            service_store: services,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(
            &test_ctx(),
            ListRequest {
                sort: SortOrder::default(),
                page: PageRequest::default(),
            },
        ))
    }

    /// Acme has two backends. Ann lists them by name.
    #[test]
    fn services_are_listed_by_name() {
        let page = list(FakeTenantAuthorities::holding_everything()).unwrap();

        let names: Vec<_> = page.items.iter().map(|s| s.name().as_str()).collect();
        assert_eq!(names, ["api", "web"]);
        assert_eq!(page.items.len(), 2);
    }

    /// Listing backend services requires the routing viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list backend services.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
