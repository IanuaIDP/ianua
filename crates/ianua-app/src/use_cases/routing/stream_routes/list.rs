//! List stream routes: the ports a tenant listens on below HTTP.

use std::sync::Arc;

use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::routing::{StreamRouteSortField, StreamRouteStore};
use crate::use_case::Query;
use crate::use_cases::routing::lookup::ensure_may_view_routing;

/// In what order to list the stream routes, and which page of them.
pub struct ListRequest {
    /// The fields and directions to order by.
    pub sort: SortOrder<StreamRouteSortField>,
    /// Which page of the ordered stream routes to return.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's stream routes.
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
    type Output = Result<Page<StreamRoute<ResolvedTenant>>, AppError>;

    /// The page of stream routes `request` asks for.
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
    ) -> Result<Page<StreamRoute<ResolvedTenant>>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        let ListRequest { sort, page } = request;
        self.ports
            .stream_route_store
            .list_all(&caller.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeStreamRouteStore, stream_route_on};
    use crate::test_support::{block_on, test_ctx};

    fn list(
        authorities: FakeTenantAuthorities,
    ) -> Result<Page<StreamRoute<ResolvedTenant>>, AppError> {
        let routes = Arc::new(FakeStreamRouteStore::empty());
        for port in [25432, 15432] {
            block_on(routes.save(&test_ctx().tenant(), &stream_route_on(port))).unwrap();
        }
        let use_case = ListUseCase::new(ListPorts {
            stream_route_store: routes,
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

    /// Acme listens on two ports. Ann lists them, lowest port first.
    #[test]
    fn stream_routes_are_listed_by_port() {
        let page = list(FakeTenantAuthorities::holding_everything()).unwrap();

        let ports: Vec<_> = page.items.iter().map(|r| r.listen_port().get()).collect();
        assert_eq!(ports, [15432, 25432]);
    }

    /// Listing stream routes requires the routing viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list stream routes.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
