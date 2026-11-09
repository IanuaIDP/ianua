//! Open or close a port without deleting the route that describes it.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::StreamRouteId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::StreamRouteStore;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::existing_stream_route;

/// Which way to move a stream route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Start accepting connections on the port.
    Activate,
    /// Stop accepting. Established streams are left alone.
    Disable,
}

/// Which stream route to move, and which way.
pub struct SetStatusRequest {
    /// The stream route to move.
    pub stream_route_id: StreamRouteId,
    /// The state to move it to.
    pub transition: Transition,
}

/// The ports [`SetStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetStatusPorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Opens or closes a port.
pub struct SetStatusUseCase {
    ports: SetStatusPorts,
}

impl SetStatusUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SetStatusPorts) -> Self {
        Self { ports }
    }
}

impl Command for SetStatusUseCase {
    type Caller = CallerContext;
    type Input = SetStatusRequest;
    type Output = Result<(), AppError>;

    /// Moves the route the way `request` says and records
    /// `routing.stream_route_activated` or `routing.stream_route_disabled`.
    ///
    /// Disabling keeps the row, and with it the port. A tenant taking a port
    /// out of service for a while does not find another tenant has taken it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the route doesn't exist.
    /// - `AppError::Domain` if it is already in that state.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: SetStatusRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let SetStatusRequest {
            stream_route_id,
            transition,
        } = request;
        let mut route = existing_stream_route(
            self.ports.stream_route_store.as_ref(),
            &tenant,
            &stream_route_id,
        )
        .await?;
        set_status(&mut route, transition, &control).map_err(AppError::from_domain)?;
        self.ports
            .stream_route_store
            .save(&tenant, &route)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), route.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Moves `route` the way `transition` says, on behalf of `by`.
fn set_status(
    route: &mut StreamRoute<ResolvedTenant>,
    transition: Transition,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    match transition {
        Transition::Activate => route.activate(by),
        Transition::Disable => route.disable(by),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeStreamRouteStore, stream_route_on};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        routes: Arc<FakeStreamRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        route_id: StreamRouteId,
        use_case: SetStatusUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let route = stream_route_on(15432);
        let routes = Arc::new(FakeStreamRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        Fixture {
            use_case: SetStatusUseCase::new(SetStatusPorts {
                stream_route_store: routes.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
        }
    }

    fn admin_fixture() -> Fixture {
        fixture(FakeTenantAuthorities::holding_everything())
    }

    fn run(f: &Fixture, transition: Transition) -> Result<(), AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            SetStatusRequest {
                stream_route_id: f.route_id,
                transition,
            },
        ))
    }

    fn is_active(f: &Fixture) -> bool {
        block_on(f.routes.find_by_id(&test_ctx().tenant(), &f.route_id))
            .unwrap()
            .unwrap()
            .is_active()
    }

    /// Ann closes the port. It is recorded as disabled.
    #[test]
    fn disabling_is_recorded_as_disabled() {
        let f = admin_fixture();

        run(&f, Transition::Disable).unwrap();

        assert!(!is_active(&f));
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.stream_route_disabled"]
        );
    }

    /// Ann closes the port and opens it again. The reopening is recorded as
    /// activated.
    #[test]
    fn reactivating_is_recorded_as_activated() {
        let f = admin_fixture();

        run(&f, Transition::Disable).unwrap();
        run(&f, Transition::Activate).unwrap();

        assert!(is_active(&f));
        assert_eq!(
            f.audit.records.lock().unwrap()[1],
            "routing.stream_route_activated"
        );
    }

    /// Ann opens a port that is already open. It is refused and nothing is
    /// recorded.
    #[test]
    fn activating_an_open_port_is_refused() {
        let f = admin_fixture();

        let result = run(&f, Transition::Activate);

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann closes the port for a while. The route stays, and with it the
    /// port, so no other tenant can take it meanwhile.
    #[test]
    fn disabling_keeps_the_route_and_so_the_port() {
        let f = admin_fixture();

        run(&f, Transition::Disable).unwrap();

        assert_eq!(f.routes.count(), 1);
    }

    /// Disabling a stream route without the update right is forbidden and
    /// leaves the route active.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, Transition::Disable);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(is_active(&f));
    }

    /// A caller without the update right receives a permission refusal even
    /// when the stream route to disable does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_route() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            SetStatusRequest {
                stream_route_id: StreamRouteId::new(),
                transition: Transition::Disable,
            },
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot disable a stream route, which remains active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, Transition::Disable);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(is_active(&f));
    }
}
