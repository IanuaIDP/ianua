//! Delete route: remove a disabled route for good.

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

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a route.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = RouteId;
    type Output = Result<(), AppError>;

    /// Deletes the route once the domain agrees it may go, and records
    /// `routing.route_deleted`. A route is disabled before it is deleted, so
    /// a live route is never removed in one slip.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not delete routing.
    /// - `AppError::NotFound` if the route doesn't exist.
    /// - `AppError::Domain` if the route is still active.
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
            .ensure_may(RoutingRight::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut route = existing_route(self.ports.route_store.as_ref(), &tenant, &route_id).await?;
        route.delete(&control).map_err(AppError::from_domain)?;
        self.ports
            .route_store
            .delete(&tenant, &route_id)
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
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakeRouteStore, RouteShape, disabled, route_of, service_named, unpinned_upstream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        routes: Arc<FakeRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        route_id: RouteId,
        use_case: DeleteUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities, route_is: RouteIs) -> Fixture {
        let service = service_named("api", unpinned_upstream("https://backend:8080"));
        let active = route_of(
            RouteShape::public("API", "/api/*"),
            &service,
            &test_pipeline(),
        );
        let route = match route_is {
            RouteIs::Active => active,
            RouteIs::Disabled => disabled(active),
        };
        let routes = Arc::new(FakeRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        Fixture {
            use_case: DeleteUseCase::new(DeletePorts {
                route_store: routes.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
        }
    }

    /// Whether the saved route still serves requests.
    #[derive(Clone, Copy)]
    enum RouteIs {
        Active,
        Disabled,
    }

    fn run(f: &Fixture, route_id: RouteId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), route_id),
        )
    }

    /// Ann deletes a route she disabled. It is gone and the deletion is
    /// recorded.
    #[test]
    fn a_disabled_route_is_deleted_and_recorded() {
        let f = fixture(
            FakeTenantAuthorities::holding_everything(),
            RouteIs::Disabled,
        );

        run(&f, f.route_id).unwrap();

        assert_eq!(f.routes.count(), 0);
        assert_eq!(*f.audit.records.lock().unwrap(), ["routing.route_deleted"]);
    }

    /// Ann deletes a route that still takes traffic. It is refused until she
    /// disables it, and the route stays.
    #[test]
    fn an_active_route_is_not_deleted() {
        let f = fixture(FakeTenantAuthorities::holding_everything(), RouteIs::Active);

        let result = run(&f, f.route_id);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::InvalidTransition(_)))
        ));
        assert_eq!(f.routes.count(), 1);
    }

    /// Ann deletes a route that does not exist. She is told it was not found
    /// and nothing is recorded.
    #[test]
    fn an_unknown_route_is_not_found() {
        let f = fixture(
            FakeTenantAuthorities::holding_everything(),
            RouteIs::Disabled,
        );

        let result = run(&f, RouteId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// The routing update right does not permit deleting a disabled HTTP
    /// route. The permission refusal leaves the route stored.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let f = fixture(
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::Update)]),
            RouteIs::Disabled,
        );

        let result = run(&f, f.route_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.routes.count(), 1);
    }

    /// A caller without the deletion right receives a permission refusal
    /// even when the requested HTTP route does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_route() {
        let f = fixture(FakeTenantAuthorities::holding(&[]), RouteIs::Disabled);

        let result = run(&f, RouteId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot delete the stored HTTP route.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            RouteIs::Disabled,
        );

        let result = run(&f, f.route_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.routes.count(), 1);
    }
}
