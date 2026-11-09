//! List apps: the routes a Protected apps step may call, every active route
//! the tenant opened to workflows, for someone who may view workflows.
//!
//! Whoever builds the workflow sees which apps are open, not who may use
//! them: each call is still asked of the route's policy for the person the
//! run acts for.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::RouteStore;
use crate::use_case::Query;

/// The ports [`ListAppsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListAppsPorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the apps workflows may call.
pub struct ListAppsUseCase {
    ports: ListAppsPorts,
}

impl ListAppsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListAppsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListAppsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<Route<ResolvedTenant>>, AppError>;

    /// Every active route of the tenant open to workflows, in priority
    /// order.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when the routes cannot be read.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<Route<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .route_store
            .list_open_to_workflows(&ctx.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::routing::control::RoutingControl;
    use ianua_domain::test_support::authority::assumed_authority;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakeRouteStore, RouteShape, route_of, service_named, unpinned_upstream,
    };
    use crate::test_support::workflows::person;
    use crate::test_support::{block_on, test_ctx};

    /// The orders route, opened to workflows, and the billing route, left
    /// closed.
    fn routes() -> (Arc<FakeRouteStore>, Route<ResolvedTenant>) {
        let service = service_named("orders", unpinned_upstream("https://orders:8080"));
        let mut orders = route_of(
            RouteShape::public("Orders", "/orders/*"),
            &service,
            &test_pipeline(),
        );
        let billing = route_of(
            RouteShape::public("Billing", "/billing/*"),
            &service,
            &test_pipeline(),
        );
        let ann = person("ann@corp.test");
        let authority = assumed_authority(
            &ann,
            test_ctx().tenant_id(),
            &[SystemPermission::ManageRouting],
            &[],
        );
        orders
            .open_to_workflows(&RoutingControl::new(authority))
            .unwrap();
        let store = Arc::new(FakeRouteStore::empty());
        block_on(store.save(&test_ctx().tenant(), &orders)).unwrap();
        block_on(store.save(&test_ctx().tenant(), &billing)).unwrap();
        (store, orders)
    }

    fn list(
        store: Arc<FakeRouteStore>,
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<Route<ResolvedTenant>>, AppError> {
        let use_case = ListAppsUseCase::new(ListAppsPorts {
            route_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann builds a workflow and is offered the orders app, which Acme
    /// opened to workflows, and not billing, which it did not.
    #[test]
    fn only_the_routes_open_to_workflows_are_listed() {
        let (store, orders) = routes();
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let listed = list(store, viewer).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id(), orders.id());
    }

    /// A caller without workflow view rights cannot list the tenant's open apps.
    #[test]
    fn a_caller_who_may_not_view_workflows_is_refused() {
        let (store, _) = routes();

        let result = list(store, FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list the tenant's open apps.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, _) = routes();

        let result = list(store, FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
