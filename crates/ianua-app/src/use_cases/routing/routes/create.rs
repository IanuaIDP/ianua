//! Create route: define a new route within the tenant's proxy.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::matching::parameter::{ParameterRule, RouteReach};
use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
use ianua_domain::domains::routing::matching::request_match::RouteConditions;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::{CreateRouteParams, Route};
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
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
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::proxy::PipelineStore;
use crate::ports::routing::{RouteStore, ServiceStore};
use crate::services::hosts::PlatformAddresses;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::{
    ensure_hosts_belong_to_tenant, ensure_policy_permissions_declared, existing_service,
    named_pipeline,
};

/// What a new route is made of.
pub struct CreateRequest {
    /// Route name.
    pub name: Label,
    /// Path pattern, such as `/api/v1/projects/*`.
    pub path_pattern: UrlPath,
    /// HTTP methods to match. Empty means all.
    pub methods: Vec<HttpMethod>,
    /// The service whose upstream this route forwards to.
    pub service_id: ServiceId,
    /// What a caller must prove to be let through.
    pub policy: RoutePolicy,
    /// What path the upstream sees.
    pub path_rewrite: PathRewrite,
    /// Evaluation priority, lower first.
    pub priority: u16,
    /// Which of the tenant's domains this route answers on.
    pub hosts: RouteHosts,
    /// Which pipeline runs on this route. Named, never defaulted.
    pub pipeline_id: PipelineId,
    /// The most sensitive data the route serves or accepts.
    pub data_class: DataClassLevel,
    /// What kind of action the route takes, or undeclared to guess it from
    /// each request.
    pub action_class: DeclaredAction,
    /// Whether the service goes only where it was built to, or where it is
    /// told.
    pub reach: RouteReach,
    /// Which hosts the route's URL parameters may name.
    pub parameter_rules: Vec<ParameterRule>,
    /// The headers and cookies a request must carry for the route to take
    /// it. None lets every request on the path through.
    pub conditions: RouteConditions,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// The plan's ceiling on routes.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
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

/// Adds a route to the tenant's proxy.
pub struct CreateUseCase {
    ports: CreatePorts,
    platform: Option<Arc<PlatformAddresses>>,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        CreateUseCase {
            ports,
            platform: None,
        }
    }

    /// Enables host restrictions on addresses the deployment owns for this tenant.
    #[must_use]
    pub fn with_platform_addresses(mut self, platform: Arc<PlatformAddresses>) -> Self {
        self.platform = Some(platform);
        self
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<RouteId, AppError>;

    /// Creates the route `request` describes and records
    /// `routing.route_created`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without routing-creation rights or with a full plan.
    /// - `AppError::NotFound` for a service outside the tenant; `Domain` for an unverified host or foreign pipeline.
    /// - `AppError::Domain` also covers undeclared permissions, inseparable sign-in, an incompatible rewrite or duplicate parameter rules.
    /// - `AppError::Conflict` for a taken route name; `Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<RouteId, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Create)
            .map_err(AppError::from_domain)?;
        let targets =
            route_targets(&self.ports, caller, &request, self.platform.as_deref()).await?;
        let tenant = caller.tenant();
        let mut route = new_route(request, &targets, &control)?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(caller.plan_limits(), &tenant, ResourceKind::Routes)
            .await
            .map_err(AppError::from_domain)?;
        self.ports
            .route_store
            .save(&tenant, &route)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), route.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(*route.id())
    }
}

/// The service a new route forwards to and the pipeline it runs.
struct RouteTargets {
    service: Service<ResolvedTenant>,
    pipeline: Pipeline<ResolvedTenant>,
}

/// The service and pipeline `request` names, once its hosts and required
/// permissions are known to the tenant.
async fn route_targets(
    ports: &CreatePorts,
    caller: &CallerContext,
    request: &CreateRequest,
    platform: Option<&PlatformAddresses>,
) -> Result<RouteTargets, AppError> {
    let tenant = caller.tenant();
    ensure_hosts_belong_to_tenant(
        ports.domain_store.as_ref(),
        &tenant,
        &request.hosts,
        platform,
    )
    .await?;
    ensure_policy_permissions_declared(
        ports.resource_type_store.as_ref(),
        &tenant,
        &request.policy,
    )
    .await?;
    let service =
        existing_service(ports.service_store.as_ref(), &tenant, &request.service_id).await?;
    let pipeline =
        named_pipeline(ports.pipeline_store.as_ref(), &tenant, &request.pipeline_id).await?;
    Ok(RouteTargets { service, pipeline })
}

/// The route `request` describes, made by `by` and declared as it says.
fn new_route(
    request: CreateRequest,
    targets: &RouteTargets,
    by: &RoutingControl<'_>,
) -> Result<Route<ResolvedTenant>, AppError> {
    let mut route = Route::create(
        CreateRouteParams {
            name: request.name,
            path_pattern: request.path_pattern,
            methods: request.methods,
            policy: request.policy,
            hosts: request.hosts,
            path_rewrite: request.path_rewrite,
            priority: request.priority,
        },
        &targets.service,
        &targets.pipeline,
        by,
    )
    .map_err(AppError::from_domain)?;
    route
        .declare_data_class(request.data_class, by)
        .and_then(|()| route.declare_action_class(request.action_class, by))
        .and_then(|()| route.declare_reach(request.reach, by))
        .and_then(|()| route.replace_parameter_rules(request.parameter_rules, by))
        .and_then(|()| route.change_conditions(request.conditions, by))
        .map_err(AppError::from_domain)?;
    Ok(route)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::CustomPermission;
    use ianua_domain::domains::routing::backend::upstream::Upstream;
    use ianua_domain::domains::routing::matching::path_rewrite::PathTemplate;
    use ianua_domain::domains::routing::matching::request_match::{
        MatchSubject, RequestCondition, ValueMatch,
    };
    use ianua_domain::types::{DomainName, HeaderName, HeaderValue};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::domain::FakeDomainStore;
    use crate::test_support::proxy::{FakePipelineStore, test_pipeline, test_pipeline_id};
    use crate::test_support::routing::{
        FakeRouteStore, FakeServiceStore, pinned_upstream, service_named, unpinned_upstream,
        unproved_domain, verified_domains,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    struct Fixture {
        routes: Arc<FakeRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        service_id: ServiceId,
        use_case: CreateUseCase,
    }

    fn services_holding(upstream: Upstream) -> (Arc<FakeServiceStore>, ServiceId) {
        let service = service_named("projects-api", upstream);
        let id = *service.id();
        let store = Arc::new(FakeServiceStore::empty());
        block_on(store.save(&test_ctx().tenant(), &service)).unwrap();
        (store, id)
    }

    fn fixture_with(ports: impl FnOnce(CreatePorts) -> CreatePorts) -> Fixture {
        let routes = Arc::new(FakeRouteStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let (services, service_id) = services_holding(pinned_upstream(
            "https://projects.internal:8080",
            "projects",
        ));
        let use_case = CreateUseCase::new(ports(CreatePorts {
            route_store: routes.clone(),
            service_store: services,
            pipeline_store: Arc::new(FakePipelineStore::holding(
                test_ctx().tenant_id(),
                test_pipeline(),
            )),
            resource_type_store: Arc::new(FakeResourceTypeStore::seeded(test_ctx().tenant_id())),
            ..CreatePorts::fakes()
        }));
        Fixture {
            routes,
            audit,
            service_id,
            use_case,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(|ports| ports)
    }

    fn with_domains(domains: Arc<FakeDomainStore>) -> Fixture {
        fixture_with(|ports| CreatePorts {
            domain_store: domains,
            ..ports
        })
    }

    fn request(service_id: ServiceId) -> CreateRequest {
        CreateRequest {
            name: Label::new("name", "Projects API").unwrap(),
            path_pattern: UrlPath::new("/api/v1/projects/*").unwrap(),
            methods: vec![HttpMethod::Get, HttpMethod::Post],
            service_id,
            policy: RoutePolicy::Authenticated,
            path_rewrite: PathRewrite::StripPrefix,
            priority: 100,
            hosts: RouteHosts::Any,
            pipeline_id: test_pipeline_id(),
            data_class: DataClassLevel::Internal,
            action_class: DeclaredAction::Undeclared,
            reach: RouteReach::Fixed,
            parameter_rules: Vec::new(),
            conditions: RouteConditions::default(),
        }
    }

    fn scoped_to(service_id: ServiceId, host: &str) -> CreateRequest {
        CreateRequest {
            hosts: RouteHosts::only(vec![DomainName::new(host).unwrap()]).unwrap(),
            ..request(service_id)
        }
    }

    fn run(f: &Fixture, request: CreateRequest) -> Result<RouteId, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    /// Ann adds the projects route. It is saved, active and pointed at the
    /// projects service, and the change is recorded.
    #[test]
    fn a_route_is_saved_active_and_recorded() {
        let f = fixture();

        let id = run(&f, request(f.service_id)).unwrap();

        let saved = block_on(f.routes.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert!(saved.is_active());
        assert_eq!(saved.service_id(), &f.service_id);
        assert_eq!(*f.audit.records.lock().unwrap(), ["routing.route_created"]);
    }

    /// Ann adds the green route for requests carrying the green deployment
    /// header. It is saved with that condition, and created as one change.
    #[test]
    fn a_route_is_created_with_its_conditions() {
        let f = fixture();
        let green = RouteConditions::new(vec![RequestCondition::new(
            MatchSubject::Header(HeaderName::new("x-deployment").unwrap()),
            ValueMatch::Exact(HeaderValue::new("green").unwrap()),
        )])
        .unwrap();

        let id = run(
            &f,
            CreateRequest {
                conditions: green.clone(),
                ..request(f.service_id)
            },
        )
        .unwrap();

        let saved = block_on(f.routes.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert_eq!(saved.conditions(), &green);
        assert_eq!(*f.audit.records.lock().unwrap(), ["routing.route_created"]);
    }

    /// Ann restricts the route to `admin.acme.com`, which Acme registered and
    /// proved. It is saved.
    #[test]
    fn a_route_may_be_scoped_to_a_domain_the_tenant_has_verified() {
        let f = with_domains(verified_domains(&test_ctx().tenant(), &["admin.acme.com"]));

        let result = run(&f, scoped_to(f.service_id, "admin.acme.com"));

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(f.routes.count(), 1);
    }

    /// Ann restricts a route to `app.acme.com`, which Acme never registered.
    /// The proxy would never match it there, so it is refused at the write.
    #[test]
    fn a_route_scoped_to_an_unregistered_domain_is_refused() {
        let f = with_domains(verified_domains(&test_ctx().tenant(), &["admin.acme.com"]));

        let result = run(&f, scoped_to(f.service_id, "app.acme.com"));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(f.routes.count(), 0);
    }

    /// Acme proved `acme.com`. Ann restricts a route to `app.acme.com`, which
    /// is registered on its own or not at all. It is refused.
    #[test]
    fn a_subdomain_of_a_registered_domain_is_not_itself_registered() {
        let f = with_domains(verified_domains(&test_ctx().tenant(), &["acme.com"]));

        let result = run(&f, scoped_to(f.service_id, "app.acme.com"));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Acme registered `admin.acme.com` but never proved it. A route there
    /// would answer nobody, so it is refused.
    #[test]
    fn a_route_scoped_to_an_unverified_domain_is_refused() {
        let f = with_domains(unproved_domain(&test_ctx().tenant(), "admin.acme.com"));

        let result = run(&f, scoped_to(f.service_id, "admin.acme.com"));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann adds a route on every host. It needs no registered domain.
    #[test]
    fn an_unrestricted_route_needs_no_registered_domain() {
        let f = fixture();

        assert!(run(&f, request(f.service_id)).is_ok());
    }

    /// Ann points a route at a service Acme does not have. It is refused,
    /// since the route would fail every request it matched.
    #[test]
    fn a_route_naming_an_unknown_service_is_refused() {
        let f = fixture();

        let result = run(&f, request(ServiceId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(f.routes.count(), 0);
    }

    /// An authenticated route requires its service to pin an audience. A
    /// missing audience causes refusal and saves no route.
    #[test]
    fn a_signed_in_route_on_an_unpinned_service_is_refused() {
        let (services, service_id) =
            services_holding(unpinned_upstream("https://projects.internal:8080"));
        let f = fixture_with(|ports| CreatePorts {
            service_store: services,
            ..ports
        });

        let result = run(&f, request(service_id));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.routes.count(), 0);
    }

    /// Ann adds a public route on the same unpinned service. Nobody signs in
    /// there, so it is allowed.
    #[test]
    fn a_public_route_on_an_unpinned_service_is_allowed() {
        let (services, service_id) =
            services_holding(unpinned_upstream("https://projects.internal:8080"));
        let f = fixture_with(|ports| CreatePorts {
            service_store: services,
            ..ports
        });

        let result = run(
            &f,
            CreateRequest {
                policy: RoutePolicy::Public,
                ..request(service_id)
            },
        );

        assert!(result.is_ok(), "{result:?}");
    }

    /// Ann names a pipeline Acme does not have. The route would refuse every
    /// request, so it is refused.
    #[test]
    fn a_route_naming_an_unknown_pipeline_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            pipeline_store: Arc::new(FakePipelineStore::empty()),
            ..ports
        });

        let result = run(&f, request(f.service_id));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.routes.count(), 0);
    }

    /// Ann requires `project:write`, which Acme's catalogue declares. The
    /// route is saved.
    #[test]
    fn a_route_may_require_a_declared_permission() {
        let f = fixture();

        let result = run(
            &f,
            CreateRequest {
                policy: RoutePolicy::RequireCustomPermission(vec![
                    CustomPermission::new("project", "write").unwrap(),
                ]),
                ..request(f.service_id)
            },
        );

        assert!(result.is_ok(), "{result:?}");
    }

    /// Ann types `projects:write`, which no role can grant. The route would
    /// refuse everyone, so it is refused, naming the permission.
    #[test]
    fn a_route_requiring_an_undeclared_permission_is_refused() {
        let f = fixture();

        let error = run(
            &f,
            CreateRequest {
                policy: RoutePolicy::RequireCustomPermission(vec![
                    CustomPermission::new("projects", "write").unwrap(),
                ]),
                ..request(f.service_id)
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("projects:write"));
    }

    /// Ann's rewrite names `{id}`, which the pattern never captures. Every
    /// request would be forwarded with a literal brace, so it is refused.
    #[test]
    fn a_rewrite_naming_an_uncaptured_parameter_is_refused() {
        let f = fixture();

        let result = run(
            &f,
            CreateRequest {
                path_pattern: UrlPath::new("/v1/users/{user}").unwrap(),
                path_rewrite: PathRewrite::Template(
                    PathTemplate::new("/internal/user/{id}").unwrap(),
                ),
                ..request(f.service_id)
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.routes.count(), 0);
    }

    /// Ann's rewrite names `{id}`, which the pattern captures. It is saved.
    #[test]
    fn a_rewrite_naming_a_captured_parameter_is_accepted() {
        let f = fixture();

        let result = run(
            &f,
            CreateRequest {
                path_pattern: UrlPath::new("/v1/users/{id}").unwrap(),
                path_rewrite: PathRewrite::Template(
                    PathTemplate::new("/internal/user/{id}").unwrap(),
                ),
                ..request(f.service_id)
            },
        );

        assert!(result.is_ok(), "{result:?}");
    }

    /// Acme's plan holds no more routes. Ann's new route is refused and
    /// nothing is saved.
    #[test]
    fn a_route_past_the_plan_limit_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports
        });

        let result = run(&f, request(f.service_id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.routes.count(), 0);
    }

    /// Creating an HTTP route without tenant rights is forbidden, saving no
    /// route and recording no creation event.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports
        });

        let result = run(&f, request(f.service_id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.routes.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A caller without the create right receives a permission refusal even
    /// when the requested route names an unknown service.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_service() {
        let f = fixture_with(|ports| CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports
        });

        let result = run(&f, request(ServiceId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot create an HTTP route and leaves the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports
        });

        let result = run(&f, request(f.service_id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.routes.count(), 0);
    }
}
