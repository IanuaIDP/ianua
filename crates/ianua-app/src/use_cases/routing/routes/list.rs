//! List routes: the tenant's routes, filtered, ordered and paged.

use std::sync::Arc;

use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::routing::{RouteSortField, RouteStore};
use crate::use_case::Query;
use crate::use_cases::routing::lookup::ensure_may_view_routing;

/// Which routes to include.
pub enum RouteFilter {
    /// Every route, whatever its status.
    All,
    /// Only routes in this status.
    InStatus(RouteStatus),
}

impl RouteFilter {
    /// The status the store filters by, if any.
    fn status(&self) -> Option<RouteStatus> {
        match self {
            Self::All => None,
            Self::InStatus(status) => Some(*status),
        }
    }
}

/// Which routes to list, in what order, and which page of them.
pub struct ListRequest {
    /// Which routes to include.
    pub filter: RouteFilter,
    /// The fields and directions to order by.
    pub sort: SortOrder<RouteSortField>,
    /// Which page of the ordered routes to return.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's routes.
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
    type Output = Result<Page<Route<ResolvedTenant>>, AppError>;

    /// The page of routes `request` asks for.
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
    ) -> Result<Page<Route<ResolvedTenant>>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        let ListRequest { filter, sort, page } = request;
        self.ports
            .route_store
            .list_all(&caller.tenant(), filter.status(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::{Limit, Sort};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakeRouteStore, RouteShape, disabled, route_of, service_named, unpinned_upstream,
    };
    use crate::test_support::{block_on, test_ctx};

    fn store_with(count: usize) -> Arc<FakeRouteStore> {
        let service = service_named("api", unpinned_upstream("https://backend:8080"));
        let store = Arc::new(FakeRouteStore::empty());
        for i in 0..count {
            let (name, path) = (format!("Route {i}"), format!("/api/v{i}/*"));
            let route = route_of(RouteShape::public(&name, &path), &service, &test_pipeline());
            block_on(store.save(&test_ctx().tenant(), &route)).unwrap();
        }
        store
    }

    fn use_case(store: Arc<FakeRouteStore>, authorities: FakeTenantAuthorities) -> ListUseCase {
        ListUseCase::new(ListPorts {
            route_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn everything(page: PageRequest) -> ListRequest {
        ListRequest {
            filter: RouteFilter::All,
            sort: SortOrder::default(),
            page,
        }
    }

    fn list(store: Arc<FakeRouteStore>, request: ListRequest) -> Page<Route<ResolvedTenant>> {
        block_on(
            use_case(store, FakeTenantAuthorities::holding_everything())
                .execute(&test_ctx(), request),
        )
        .unwrap()
    }

    /// Acme has five routes and Ann asks for three a page. She gets three,
    /// told there are five and that another page follows.
    #[test]
    fn routes_are_paged() {
        let page = list(
            store_with(5),
            everything(PageRequest::first(Limit::new(3).unwrap())),
        );

        assert_eq!(page.items.len(), 3);
        assert!(page.has_next());
    }

    /// One of Acme's three routes is disabled. Ann asks for active routes
    /// and gets the other two.
    #[test]
    fn routes_are_filtered_by_status() {
        let store = store_with(2);
        let service = service_named("api", unpinned_upstream("https://backend:8080"));
        let off = disabled(route_of(
            RouteShape::public("Off", "/off/*"),
            &service,
            &test_pipeline(),
        ));
        block_on(store.save(&test_ctx().tenant(), &off)).unwrap();

        let page = list(
            store,
            ListRequest {
                filter: RouteFilter::InStatus(RouteStatus::Active),
                ..everything(PageRequest::default())
            },
        );

        assert_eq!(page.items.len(), 2);
    }

    /// Acme has no routes. Ann's list is empty.
    #[test]
    fn a_tenant_without_routes_lists_none() {
        let page = list(store_with(0), everything(PageRequest::default()));

        assert!(page.is_empty());
    }

    /// Ann orders the routes by name, last first. They come in that order.
    #[test]
    fn routes_are_ordered_by_name_descending() {
        let page = list(
            store_with(3),
            ListRequest {
                sort: SortOrder::single(Sort::descending(RouteSortField::Name)),
                ..everything(PageRequest::default())
            },
        );

        let names: Vec<_> = page.items.iter().map(|r| r.name().as_str()).collect();
        assert_eq!(names, ["Route 2", "Route 1", "Route 0"]);
    }

    /// Listing HTTP routes requires the routing viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = block_on(
            use_case(store_with(1), FakeTenantAuthorities::holding(&[]))
                .execute(&test_ctx(), everything(PageRequest::default())),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list HTTP routes.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = block_on(
            use_case(
                store_with(1),
                FakeTenantAuthorities::refusing(Refusal::SignedOut),
            )
            .execute(&test_ctx(), everything(PageRequest::default())),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
