//! Disable route: stop a route from taking traffic, keeping it for later.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::RouteId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::RouteStore;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::existing_route;

/// The ports [`DisableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DisablePorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Turns a route off.
pub struct DisableUseCase {
    ports: DisablePorts,
}

impl DisableUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DisablePorts) -> Self {
        Self { ports }
    }
}

impl Command for DisableUseCase {
    type Caller = CallerContext;
    type Input = RouteId;
    type Output = Result<(), AppError>;

    /// Disables the route, so requests it took go to the next route that
    /// fits or get 404, and records `routing.route_disabled`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the route doesn't exist.
    /// - `AppError::Domain` if the route is already disabled.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        route_id: RouteId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut route = existing_route(self.ports.route_store.as_ref(), &tenant, &route_id).await?;
        route.disable(&control).map_err(AppError::from_domain)?;
        self.ports
            .route_store
            .save(&tenant, &route)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), route.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakeRouteStore, RouteShape, route_of, service_named, unpinned_upstream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        routes: Arc<FakeRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        route_id: RouteId,
        use_case: DisableUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let service = service_named("api", unpinned_upstream("https://backend:8080"));
        let route = route_of(
            RouteShape::public("API", "/api/*"),
            &service,
            &test_pipeline(),
        );
        let routes = Arc::new(FakeRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        Fixture {
            use_case: DisableUseCase::new(DisablePorts {
                route_store: routes.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
        }
    }

    fn run(f: &Fixture, route_id: RouteId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), route_id),
        )
    }

    fn is_active(f: &Fixture) -> bool {
        block_on(f.routes.find_by_id(&test_ctx().tenant(), &f.route_id))
            .unwrap()
            .unwrap()
            .is_active()
    }

    /// Ann turns the route off. It stops taking traffic and the change is
    /// recorded.
    #[test]
    fn an_active_route_is_disabled_and_recorded() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, f.route_id).unwrap();

        assert!(!is_active(&f));
        assert_eq!(*f.audit.records.lock().unwrap(), ["routing.route_disabled"]);
    }

    /// Ann turns the route off twice. The second time is refused as a change
    /// that cannot be made.
    #[test]
    fn a_disabled_route_cannot_be_disabled_again() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        run(&f, f.route_id).unwrap();

        let result = run(&f, f.route_id);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann turns off a route that does not exist. She is told it was not
    /// found and nothing is recorded.
    #[test]
    fn an_unknown_route_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(&f, RouteId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Disabling an HTTP route without the update right is forbidden and
    /// leaves the route active.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, f.route_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(is_active(&f));
    }

    /// A caller without the update right receives a permission refusal even
    /// when the route to disable does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_route() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, RouteId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot disable an HTTP route, which remains active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, f.route_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(is_active(&f));
    }
}
