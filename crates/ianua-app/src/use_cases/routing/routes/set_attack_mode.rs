//! Set attack mode: check a route harder for a while during an attack, or
//! end that early.
//!
//! While a route is in attack mode, the gateway refuses addresses any
//! tenant's decoys or recon scoring caught, and holds each address to a
//! fixed number of requests a minute, before the route's own pipeline. It
//! ends on its own.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::route::{AttackLength, AttackMode};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::RouteId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::RouteStore;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::existing_route;

/// What to do with a route's attack mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackChange {
    /// Check it harder for this long from now.
    Start(AttackLength),
    /// End attack mode now.
    End,
}

/// Which route, and what to do with its attack mode.
#[derive(Debug, Clone, Copy)]
pub struct SetAttackModeRequest {
    /// The matching rule whose temporary defensive mode will change.
    pub route_id: RouteId,
    /// Start it for a while, or end it.
    pub change: AttackChange,
}

/// The ports [`SetAttackModeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetAttackModePorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Starts or ends a route's attack mode.
pub struct SetAttackModeUseCase {
    ports: SetAttackModePorts,
}

impl SetAttackModeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SetAttackModePorts) -> Self {
        Self { ports }
    }
}

impl Command for SetAttackModeUseCase {
    type Caller = CallerContext;
    type Input = SetAttackModeRequest;
    type Output = Result<AttackMode, AppError>;

    /// Starts attack mode and records `routing.route_attack_mode_started`,
    /// or ends it and records `routing.route_attack_mode_ended`, and gives
    /// back where the route's attack mode stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the route doesn't exist.
    /// - `AppError::Domain` when ending attack mode on a route not in it.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: SetAttackModeRequest,
    ) -> Result<AttackMode, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut route =
            existing_route(self.ports.route_store.as_ref(), &tenant, &request.route_id).await?;
        let changed = match request.change {
            AttackChange::Start(length) => route.start_attack_mode(&control, length),
            AttackChange::End => route.end_attack_mode(&control),
        };
        changed.map_err(AppError::from_domain)?;
        self.ports
            .route_store
            .save(&tenant, &route)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), route.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(route.attack_mode())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakeRouteStore, RouteShape, route_of, service_named, unpinned_upstream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        routes: Arc<FakeRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        route_id: RouteId,
        use_case: SetAttackModeUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let service = service_named("orders", unpinned_upstream("https://orders:8080"));
        let route = route_of(
            RouteShape::public("Orders", "/orders/*"),
            &service,
            &test_pipeline(),
        );
        let routes = Arc::new(FakeRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        Fixture {
            use_case: SetAttackModeUseCase::new(SetAttackModePorts {
                route_store: routes.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
        }
    }

    fn set(f: &Fixture, change: AttackChange) -> Result<AttackMode, AppError> {
        let request = SetAttackModeRequest {
            route_id: f.route_id,
            change,
        };
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    fn kept(f: &Fixture) -> AttackMode {
        block_on(f.routes.find_by_id(&test_ctx().tenant(), &f.route_id))
            .unwrap()
            .unwrap()
            .attack_mode()
    }

    /// Ann puts the orders route in attack mode for an hour, then ends it.
    /// Each change is kept and recorded.
    #[test]
    fn attack_mode_is_started_and_ended() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        let hour = AttackLength::minutes(60).unwrap();

        let started = set(&f, AttackChange::Start(hour)).unwrap();
        let in_force = kept(&f).in_force_at(clock::now());
        set(&f, AttackChange::End).unwrap();

        assert!(started.in_force_at(clock::now()));
        assert!(in_force);
        assert_eq!(kept(&f), AttackMode::Off);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            [
                "routing.route_attack_mode_started",
                "routing.route_attack_mode_ended"
            ]
        );
    }

    /// A routing viewer cannot start attack mode. The refusal leaves it off
    /// and records no audit event.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[
            SystemPermission::Routing(RoutingAction::View),
        ]));

        let result = set(&f, AttackChange::Start(AttackLength::minutes(60).unwrap()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(kept(&f), AttackMode::Off);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }
}
