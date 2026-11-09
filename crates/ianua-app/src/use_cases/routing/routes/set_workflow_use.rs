//! Set workflow use: open a route to the tenant's workflows, so a Protected
//! apps step may call it as the person its run acts for, or close it again.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::route::{Route, WorkflowUse};
use ianua_domain::domains::workflows::triggers::before::GuardedChange;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::RouteId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::RouteStore;
use crate::ports::workflows::ChangeGuard;
use crate::services::guarded::ensure_rules_allow;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::existing_route;

/// Which route, and whether workflows may reach it.
#[derive(Debug, Clone, Copy)]
pub struct SetWorkflowUseRequest {
    /// The matching rule whose availability to workflow calls will change.
    pub route_id: RouteId,
    /// Open to workflows, or closed to them.
    pub workflow_use: WorkflowUse,
}

/// The ports [`SetWorkflowUseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetWorkflowUsePorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The company's "before" rules, asked before an app is opened to
    /// workflows.
    pub guard: Arc<dyn ChangeGuard>,
}

/// Opens a route to workflows, or closes it.
pub struct SetWorkflowUseUseCase {
    ports: SetWorkflowUsePorts,
}

impl SetWorkflowUseUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SetWorkflowUsePorts) -> Self {
        Self { ports }
    }

    /// Asks the company's "before app opened" rules about opening `route`;
    /// closing an app narrows what workflows reach, which is not theirs to
    /// decide.
    async fn ensure_rules_allow(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        workflow_use: WorkflowUse,
        route: &Route<ResolvedTenant>,
    ) -> Result<(), AppError> {
        if workflow_use == WorkflowUse::Closed {
            return Ok(());
        }
        let fields = [
            ("app", route.id().to_string()),
            ("app_name", route.name().as_str().to_owned()),
        ];
        let guard = self.ports.guard.as_ref();
        let change = GuardedChange::AppOpenedToWorkflows;
        ensure_rules_allow(guard, tenant, auditor, change, &fields).await
    }
}

impl Command for SetWorkflowUseUseCase {
    type Caller = CallerContext;
    type Input = SetWorkflowUseRequest;
    type Output = Result<(), AppError>;

    /// Opens the route to workflows and records
    /// `routing.route_opened_to_workflows`, or closes it and records
    /// `routing.route_closed_to_workflows`. A closed route refuses every
    /// run pass from the next request on.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the route doesn't exist.
    /// - `AppError::Domain` if the route is open or closed already.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: SetWorkflowUseRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut route =
            existing_route(self.ports.route_store.as_ref(), &tenant, &request.route_id).await?;
        let changed = match request.workflow_use {
            WorkflowUse::Open => route.open_to_workflows(&control),
            WorkflowUse::Closed => route.close_to_workflows(&control),
        };
        changed.map_err(AppError::from_domain)?;
        self.ensure_rules_allow(&tenant, auditor, request.workflow_use, &route)
            .await?;
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
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};

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
        use_case: SetWorkflowUseUseCase,
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
            use_case: SetWorkflowUseUseCase::new(SetWorkflowUsePorts {
                route_store: routes.clone(),
                tenant_authorities: Arc::new(authorities),
                guard: crate::test_support::Fake::fake(),
            }),
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
        }
    }

    fn set(f: &Fixture, workflow_use: WorkflowUse) -> Result<(), AppError> {
        let request = SetWorkflowUseRequest {
            route_id: f.route_id,
            workflow_use,
        };
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    fn workflow_use(f: &Fixture) -> WorkflowUse {
        block_on(f.routes.find_by_id(&test_ctx().tenant(), &f.route_id))
            .unwrap()
            .unwrap()
            .workflow_use()
    }

    /// Ann opens the orders route to workflows, then closes it again. Each
    /// change is kept and recorded.
    #[test]
    fn a_route_is_opened_and_closed_to_workflows() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        set(&f, WorkflowUse::Open).unwrap();
        let opened = workflow_use(&f);
        set(&f, WorkflowUse::Closed).unwrap();

        assert_eq!(opened, WorkflowUse::Open);
        assert_eq!(workflow_use(&f), WorkflowUse::Closed);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            [
                "routing.route_opened_to_workflows",
                "routing.route_closed_to_workflows"
            ]
        );
    }

    /// Ann closes a route no workflow could reach. She is told nothing
    /// changes, and nothing is recorded.
    #[test]
    fn a_closed_route_cannot_be_closed_again() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = set(&f, WorkflowUse::Closed);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A routing viewer cannot open an HTTP route to workflows. The refusal
    /// leaves workflow use closed.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[
            SystemPermission::Routing(RoutingAction::View),
        ]));

        let result = set(&f, WorkflowUse::Open);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(workflow_use(&f), WorkflowUse::Closed);
    }

    /// A signed-out session cannot open an HTTP route to workflows.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = set(&f, WorkflowUse::Open);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
