//! Update route: change how a route matches, where it forwards, and what a
//! caller must prove there.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::matching::parameter::{ParameterRule, RouteReach};
use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{
    DeclaredAction, HttpMethod, Label, PipelineId, RouteId, ServiceId, UrlPath,
};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::proxy::PipelineStore;
use crate::ports::routing::{RouteStore, ServiceStore};
use crate::services::hosts::PlatformAddresses;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::{
    ensure_hosts_belong_to_tenant, ensure_policy_permissions_declared, existing_route,
    existing_service, named_pipeline,
};
use crate::use_cases::routing::routes::retarget::{Retarget, RouteTargets, retarget};

/// What to change on a route. A field left `None` stays as it is.
pub struct UpdateRequest {
    /// The route to change.
    pub route_id: RouteId,
    /// A new name.
    pub name: Option<Label>,
    /// A new path pattern.
    pub path_pattern: Option<UrlPath>,
    /// New methods to match.
    pub methods: Option<Vec<HttpMethod>>,
    /// The service to point the route at.
    pub service_id: Option<ServiceId>,
    /// A new policy.
    pub policy: Option<RoutePolicy>,
    /// A new priority.
    pub priority: Option<u16>,
    /// What path the upstream sees.
    pub path_rewrite: Option<PathRewrite>,
    /// Which of the tenant's domains the route answers on.
    pub hosts: Option<RouteHosts>,
    /// The pipeline to move the route onto.
    ///
    /// This is how a pipeline is replaced without an outage: build the new
    /// one beside the live one, then move routes onto it one at a time.
    pub pipeline_id: Option<PipelineId>,
    /// The most sensitive data the route serves or accepts.
    pub data_class: Option<DataClassLevel>,
    /// What kind of action the route takes.
    pub action_class: Option<DeclaredAction>,
    /// Whether the service goes only where it was built to, or where it is
    /// told.
    pub reach: Option<RouteReach>,
    /// Which hosts the route's URL parameters may name.
    pub parameter_rules: Option<Vec<ParameterRule>>,
}

impl UpdateRequest {
    /// Whether this request changes nothing.
    fn is_empty(&self) -> bool {
        !self.changes_matching() && !self.changes_declarations() && !self.changes_targets()
    }

    fn changes_matching(&self) -> bool {
        self.name.is_some()
            || self.path_pattern.is_some()
            || self.path_rewrite.is_some()
            || self.methods.is_some()
            || self.priority.is_some()
            || self.hosts.is_some()
    }

    fn changes_declarations(&self) -> bool {
        self.data_class.is_some()
            || self.action_class.is_some()
            || self.reach.is_some()
            || self.parameter_rules.is_some()
    }

    fn changes_targets(&self) -> bool {
        self.service_id.is_some() || self.pipeline_id.is_some() || self.policy.is_some()
    }
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// The tenant's registered domains, which a host restriction must name.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// The tenant's pipelines, one of which the route runs.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// The tenant's services, one of which the route forwards to.
    pub service_store: Arc<dyn ServiceStore>,
    /// The tenant's permission catalogue, which a required custom permission
    /// must be declared in.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a route's settings.
pub struct UpdateUseCase {
    ports: UpdatePorts,
    platform: Option<Arc<PlatformAddresses>>,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        UpdateUseCase {
            ports,
            platform: None,
        }
    }

    /// Enables host restrictions on the current tenant's platform addresses.
    #[must_use]
    pub fn with_platform_addresses(mut self, platform: Arc<PlatformAddresses>) -> Self {
        self.platform = Some(platform);
        self
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Applies the changes `request` carries and records
    /// `routing.route_updated`. A request changing nothing records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without routing-update rights.
    /// - `AppError::NotFound` for a missing route/service; `Domain` for an unverified host or foreign pipeline.
    /// - `AppError::Domain` also covers undeclared permissions, inseparable sign-in, an incompatible rewrite or duplicate parameter rules.
    /// - `AppError::Conflict` for a taken route name; `Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut route =
            existing_route(self.ports.route_store.as_ref(), &tenant, &request.route_id).await?;
        if request.is_empty() {
            return Ok(());
        }
        ensure_references_known(&self.ports, &tenant, &request, self.platform.as_deref()).await?;
        let loaded = retargeting(&self.ports, &tenant, &route, &request).await?;
        apply_changes(&mut route, request, loaded, &control).map_err(AppError::from_domain)?;
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

/// Refuses a new host restriction or policy the tenant has not verified or
/// declared.
async fn ensure_references_known(
    ports: &UpdatePorts,
    tenant: &ScopedTenant,
    request: &UpdateRequest,
    platform: Option<&PlatformAddresses>,
) -> Result<(), AppError> {
    if let Some(hosts) = &request.hosts {
        ensure_hosts_belong_to_tenant(ports.domain_store.as_ref(), tenant, hosts, platform).await?;
    }
    let Some(policy) = &request.policy else {
        return Ok(());
    };
    ensure_policy_permissions_declared(ports.resource_type_store.as_ref(), tenant, policy).await
}

/// A service and the pipeline a route runs, as loaded.
struct Targets {
    service: Service<ResolvedTenant>,
    pipeline: Pipeline<ResolvedTenant>,
}

impl Targets {
    fn borrowed(&self) -> RouteTargets<'_> {
        RouteTargets {
            service: &self.service,
            pipeline: &self.pipeline,
        }
    }
}

/// Where a route forwards and runs now, and where it is to from now on, as
/// loaded.
struct Loaded {
    current: Targets,
    next: Targets,
}

impl Loaded {
    fn retarget(&self) -> Retarget<'_> {
        Retarget {
            current: self.current.borrowed(),
            next: self.next.borrowed(),
        }
    }
}

/// The route's targets before and after the change, when the request moves
/// it or changes its policy.
async fn retargeting(
    ports: &UpdatePorts,
    tenant: &ScopedTenant,
    route: &Route<ResolvedTenant>,
    request: &UpdateRequest,
) -> Result<Option<Loaded>, AppError> {
    if !request.changes_targets() {
        return Ok(None);
    }
    let current = targets(ports, tenant, route.service_id(), route.pipeline_id()).await?;
    let next = targets(
        ports,
        tenant,
        request.service_id.as_ref().unwrap_or(route.service_id()),
        request.pipeline_id.as_ref().unwrap_or(route.pipeline_id()),
    )
    .await?;
    Ok(Some(Loaded { current, next }))
}

/// The tenant's service `service_id` and pipeline `pipeline_id`.
async fn targets(
    ports: &UpdatePorts,
    tenant: &ScopedTenant,
    service_id: &ServiceId,
    pipeline_id: &PipelineId,
) -> Result<Targets, AppError> {
    let service = existing_service(ports.service_store.as_ref(), tenant, service_id).await?;
    let pipeline = named_pipeline(ports.pipeline_store.as_ref(), tenant, pipeline_id).await?;
    Ok(Targets { service, pipeline })
}

/// Applies every change `request` carries to `route`, on behalf of `by`.
fn apply_changes(
    route: &mut Route<ResolvedTenant>,
    request: UpdateRequest,
    loaded: Option<Loaded>,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    apply_declarations(route, &request, by)?;
    if let Some(loaded) = loaded {
        retarget(route, request.policy.clone(), loaded.retarget(), by)?;
    }
    apply_matching(route, request, by)
}

/// Changes which requests the route matches.
fn apply_matching(
    route: &mut Route<ResolvedTenant>,
    request: UpdateRequest,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if let Some(name) = request.name {
        route.rename(name, by)?;
    }
    if request.path_pattern.is_some() || request.path_rewrite.is_some() {
        let pattern = request
            .path_pattern
            .unwrap_or_else(|| route.path_pattern().clone());
        let rewrite = request
            .path_rewrite
            .unwrap_or_else(|| route.path_rewrite().clone());
        route.change_path(pattern, rewrite, by)?;
    }
    if let Some(methods) = request.methods {
        route.change_methods(methods, by)?;
    }
    if let Some(priority) = request.priority {
        route.change_priority(priority, by)?;
    }
    let Some(hosts) = request.hosts else {
        return Ok(());
    };
    route.change_hosts(hosts, by)
}

/// Changes what the route declares about the data and actions behind it.
fn apply_declarations(
    route: &mut Route<ResolvedTenant>,
    request: &UpdateRequest,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if let Some(data_class) = request.data_class {
        route.declare_data_class(data_class, by)?;
    }
    if let Some(action_class) = request.action_class {
        route.declare_action_class(action_class, by)?;
    }
    if let Some(reach) = request.reach {
        route.declare_reach(reach, by)?;
    }
    let Some(rules) = &request.parameter_rules else {
        return Ok(());
    };
    route.replace_parameter_rules(rules.clone(), by)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::backend::upstream::Upstream;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::proxy::{FakePipelineStore, test_pipeline};
    use crate::test_support::routing::{
        FakeRouteStore, FakeServiceStore, RouteShape, pinned_upstream, route_of, routing_admin,
        routing_label, service_named, unpinned_upstream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        routes: Arc<FakeRouteStore>,
        services: Arc<FakeServiceStore>,
        pipelines: Arc<FakePipelineStore>,
        audit: Arc<FakeEventDispatcher>,
        route_id: RouteId,
        service_id: ServiceId,
        use_case: UpdateUseCase,
    }

    fn tenant() -> ScopedTenant {
        test_ctx().tenant()
    }

    fn fixture_on(
        upstream: Upstream,
        shape: RouteShape<'_>,
        authorities: Arc<dyn TenantAuthorities>,
    ) -> Fixture {
        let service = service_named("api", upstream);
        let route = route_of(shape, &service, &test_pipeline());
        let (routes, services) = (
            Arc::new(FakeRouteStore::empty()),
            Arc::new(FakeServiceStore::empty()),
        );
        block_on(services.save(&tenant(), &service)).unwrap();
        block_on(routes.save(&tenant(), &route)).unwrap();
        let pipelines = Arc::new(FakePipelineStore::holding(
            test_ctx().tenant_id(),
            test_pipeline(),
        ));
        let use_case = UpdateUseCase::new(UpdatePorts {
            route_store: routes.clone(),
            service_store: services.clone(),
            pipeline_store: pipelines.clone(),
            resource_type_store: Arc::new(FakeResourceTypeStore::seeded(test_ctx().tenant_id())),
            tenant_authorities: authorities,
            ..UpdatePorts::fakes()
        });
        Fixture {
            routes,
            services,
            pipelines,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
            service_id: *service.id(),
            use_case,
        }
    }

    fn fixture_holding(authorities: FakeTenantAuthorities) -> Fixture {
        fixture_on(
            pinned_upstream("https://backend:8080", "api"),
            RouteShape::signed_in("API", "/api/*"),
            Arc::new(authorities),
        )
    }

    fn fixture() -> Fixture {
        fixture_holding(FakeTenantAuthorities::holding_everything())
    }

    fn change(route_id: RouteId) -> UpdateRequest {
        UpdateRequest {
            route_id,
            name: None,
            path_pattern: None,
            methods: None,
            service_id: None,
            policy: None,
            priority: None,
            path_rewrite: None,
            hosts: None,
            pipeline_id: None,
            data_class: None,
            action_class: None,
            reach: None,
            parameter_rules: None,
        }
    }

    fn run(f: &Fixture, request: UpdateRequest) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    fn saved(f: &Fixture) -> Route<ResolvedTenant> {
        block_on(f.routes.find_by_id(&tenant(), &f.route_id))
            .unwrap()
            .unwrap()
    }

    fn another_service(f: &Fixture, upstream: Upstream) -> ServiceId {
        let service = service_named("replacement", upstream);
        block_on(f.services.save(&tenant(), &service)).unwrap();
        *service.id()
    }

    /// Ann renames the route. It is saved and the change is recorded.
    #[test]
    fn a_renamed_route_is_saved_and_recorded() {
        let f = fixture();

        run(
            &f,
            UpdateRequest {
                name: Some(routing_label("Updated API")),
                ..change(f.route_id)
            },
        )
        .unwrap();

        assert_eq!(saved(&f).name().as_str(), "Updated API");
        assert_eq!(*f.audit.records.lock().unwrap(), ["routing.route_updated"]);
    }

    /// Ann has the upstream see the path without its prefix. The rewrite is
    /// saved.
    #[test]
    fn a_new_path_rewrite_is_saved() {
        let f = fixture();

        run(
            &f,
            UpdateRequest {
                path_rewrite: Some(PathRewrite::StripPrefix),
                ..change(f.route_id)
            },
        )
        .unwrap();

        assert_eq!(*saved(&f).path_rewrite(), PathRewrite::StripPrefix);
    }

    /// Ann sends an edit that changes nothing. Nothing is recorded.
    #[test]
    fn an_empty_change_records_nothing() {
        let f = fixture();

        run(&f, change(f.route_id)).unwrap();

        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann changes the methods, then the path, then the priority, one at a
    /// time. Each is applied on its own.
    #[test]
    fn a_single_changed_field_is_applied_on_its_own() {
        let f = fixture();

        run(
            &f,
            UpdateRequest {
                methods: Some(vec![HttpMethod::Post]),
                ..change(f.route_id)
            },
        )
        .unwrap();
        run(
            &f,
            UpdateRequest {
                path_pattern: Some(UrlPath::new("/v2/*").unwrap()),
                ..change(f.route_id)
            },
        )
        .unwrap();
        run(
            &f,
            UpdateRequest {
                priority: Some(10),
                ..change(f.route_id)
            },
        )
        .unwrap();

        let route = saved(&f);
        assert_eq!(route.methods(), [HttpMethod::Post]);
        assert_eq!(route.path_pattern().as_str(), "/v2/*");
        assert_eq!(route.priority(), 10);
        assert_eq!(f.audit.records.lock().unwrap().len(), 3);
    }

    /// Ann replaces the backend by pointing the route at a new service that
    /// pins an audience. The route forwards there.
    #[test]
    fn moving_a_route_to_another_service_is_saved() {
        let f = fixture();
        let replacement = another_service(&f, pinned_upstream("https://v2:8080", "api"));

        run(
            &f,
            UpdateRequest {
                service_id: Some(replacement),
                ..change(f.route_id)
            },
        )
        .unwrap();

        assert_eq!(saved(&f).service_id(), &replacement);
    }

    /// Ann points the route at a service Acme does not have. It is refused
    /// and the route keeps its service.
    #[test]
    fn moving_a_route_to_an_unknown_service_is_refused() {
        let f = fixture();

        let result = run(
            &f,
            UpdateRequest {
                service_id: Some(ServiceId::new()),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(saved(&f).service_id(), &f.service_id);
    }

    /// Requiring authentication on a service without a pinned audience is
    /// refused and records no route update.
    #[test]
    fn requiring_sign_in_on_an_unpinned_service_is_refused() {
        let f = fixture_on(
            unpinned_upstream("https://backend:8080"),
            RouteShape::public("API", "/api/*"),
            Arc::new(FakeTenantAuthorities::holding_everything()),
        );

        let result = run(
            &f,
            UpdateRequest {
                policy: Some(RoutePolicy::Authenticated),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann makes the signed-in route public and moves it to a service that
    /// pins no audience, in one edit. The policy goes first, so the move is
    /// allowed.
    #[test]
    fn going_public_and_moving_to_an_unpinned_service_is_one_edit() {
        let f = fixture();
        let unpinned = another_service(&f, unpinned_upstream("https://open:8080"));

        run(
            &f,
            UpdateRequest {
                policy: Some(RoutePolicy::Public),
                service_id: Some(unpinned),
                ..change(f.route_id)
            },
        )
        .unwrap();

        let route = saved(&f);
        assert_eq!(route.service_id(), &unpinned);
        assert!(route.policy().is_public());
    }

    /// Ann moves the route onto the edge pipeline she built beside the live
    /// one. The route runs it.
    #[test]
    fn moving_a_route_to_another_pipeline_is_saved() {
        let f = fixture();
        let edge = Pipeline::with_defaults(routing_label("edge"), &routing_admin()).unwrap();
        block_on(f.pipelines.save(&tenant(), &edge)).unwrap();

        run(
            &f,
            UpdateRequest {
                pipeline_id: Some(*edge.id()),
                ..change(f.route_id)
            },
        )
        .unwrap();

        assert_eq!(saved(&f).pipeline_id(), edge.id());
    }

    /// Ann moves the route onto a pipeline Acme does not have. It is refused
    /// and the route keeps its pipeline.
    #[test]
    fn moving_a_route_to_an_unknown_pipeline_is_refused() {
        let f = fixture();
        let before = *saved(&f).pipeline_id();

        let result = run(
            &f,
            UpdateRequest {
                pipeline_id: Some(PipelineId::new()),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(*saved(&f).pipeline_id(), before);
    }

    /// Ann renames a route that does not exist. She is told it was not found
    /// and nothing is recorded.
    #[test]
    fn an_unknown_route_is_not_found() {
        let f = fixture();

        let result = run(
            &f,
            UpdateRequest {
                name: Some(routing_label("Ghost")),
                ..change(RouteId::new())
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann sends an empty edit for a route that does not exist. She is still
    /// told it was not found, not that nothing changed.
    #[test]
    fn an_empty_change_to_an_unknown_route_is_not_found() {
        let f = fixture();

        let result = run(&f, change(RouteId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann changes only the priority. The route keeps the service it
    /// forwards to.
    #[test]
    fn an_unrelated_edit_leaves_the_service_alone() {
        let f = fixture();

        run(
            &f,
            UpdateRequest {
                priority: Some(5),
                ..change(f.route_id)
            },
        )
        .unwrap();

        assert_eq!(saved(&f).service_id(), &f.service_id);
    }

    /// Making an authenticated route public without the update right is
    /// forbidden and preserves its authentication requirement.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture_holding(FakeTenantAuthorities::holding(&[]));

        let result = run(
            &f,
            UpdateRequest {
                policy: Some(RoutePolicy::Public),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(saved(&f).policy().requires_auth());
    }

    /// A caller without the update right receives a permission refusal even
    /// when the requested route does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_route() {
        let f = fixture_holding(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, change(RouteId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot rename an HTTP route.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_holding(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(
            &f,
            UpdateRequest {
                name: Some(routing_label("Mine")),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
