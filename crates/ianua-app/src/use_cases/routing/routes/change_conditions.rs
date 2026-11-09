//! Change route conditions: set the headers and cookies a request must carry
//! for a route to take it, such as a blue/green header or a canary cookie.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::matching::request_match::RouteConditions;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::RouteId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::RouteStore;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::existing_route;

/// The conditions a route is to match on from now on.
pub struct ChangeConditionsRequest {
    /// The route to change.
    pub route_id: RouteId,
    /// Every header and cookie condition, replacing the ones it has. None
    /// lets every request on the route's path through to it.
    pub conditions: RouteConditions,
}

/// The ports [`ChangeConditionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeConditionsPorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Replaces a route's header and cookie conditions.
pub struct ChangeConditionsUseCase {
    ports: ChangeConditionsPorts,
}

impl ChangeConditionsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeConditionsPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeConditionsUseCase {
    type Caller = CallerContext;
    type Input = ChangeConditionsRequest;
    type Output = Result<(), AppError>;

    /// Replaces the conditions and records `routing.route_updated`.
    ///
    /// A condition only narrows which requests the route takes. A request
    /// it turns away goes on to the next route that fits, under that route's
    /// own policy.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the route doesn't exist.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeConditionsRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut route =
            existing_route(self.ports.route_store.as_ref(), &tenant, &request.route_id).await?;
        route
            .change_conditions(request.conditions, &control)
            .map_err(AppError::from_domain)?;
        self.ports
            .route_store
            .save(&tenant, &route)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), route.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::matching::request_match::{
        MatchSubject, RequestCondition, ValueMatch,
    };
    use ianua_domain::types::{CookieName, HeaderName, HeaderValue};

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
        use_case: ChangeConditionsUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let service = service_named("shop", unpinned_upstream("https://green:8080"));
        let route = route_of(
            RouteShape::public("shop-green", "/*"),
            &service,
            &test_pipeline(),
        );
        let routes = Arc::new(FakeRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        Fixture {
            use_case: ChangeConditionsUseCase::new(ChangeConditionsPorts {
                route_store: routes.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
        }
    }

    fn green_deployment() -> RouteConditions {
        RouteConditions::new(vec![
            RequestCondition::new(
                MatchSubject::Header(HeaderName::new("x-deployment").unwrap()),
                ValueMatch::Exact(HeaderValue::new("green").unwrap()),
            ),
            RequestCondition::new(
                MatchSubject::Cookie(CookieName::new("canary").unwrap()),
                ValueMatch::Present,
            ),
        ])
        .unwrap()
    }

    fn run(f: &Fixture, route_id: RouteId, conditions: RouteConditions) -> Result<(), AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            ChangeConditionsRequest {
                route_id,
                conditions,
            },
        ))
    }

    fn saved_conditions(f: &Fixture) -> RouteConditions {
        block_on(f.routes.find_by_id(&test_ctx().tenant(), &f.route_id))
            .unwrap()
            .unwrap()
            .conditions()
            .clone()
    }

    /// Ann pins the green route to requests with the green header and the
    /// canary cookie. It is saved and the change recorded.
    #[test]
    fn conditions_are_saved_and_recorded() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, f.route_id, green_deployment()).unwrap();

        assert_eq!(saved_conditions(&f), green_deployment());
        assert_eq!(*f.audit.records.lock().unwrap(), ["routing.route_updated"]);
    }

    /// Ann clears the conditions once the rollout is done. The route takes
    /// every request on its path again.
    #[test]
    fn clearing_the_conditions_matches_every_request_again() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        run(&f, f.route_id, green_deployment()).unwrap();

        run(&f, f.route_id, RouteConditions::default()).unwrap();

        assert!(saved_conditions(&f).is_empty());
    }

    /// Ann changes the conditions of a route that does not exist. She is
    /// told it was not found and nothing is recorded.
    #[test]
    fn an_unknown_route_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(&f, RouteId::new(), green_deployment());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Changing route conditions without the update right is forbidden.
    /// Conditions remain empty and no update event is recorded.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, f.route_id, green_deployment());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(saved_conditions(&f).is_empty());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A caller without the update right receives a permission refusal even
    /// when the route whose conditions are requested does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_route() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, RouteId::new(), green_deployment());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot add route conditions, which remain empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, f.route_id, green_deployment());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(saved_conditions(&f).is_empty());
    }
}
