//! A tenant's routes, in the order they are tried, and the route a request
//! takes.
//!
//! Every rule is the domain's: [`evaluation_order`] sorts the table,
//! [`resolve_route`] picks the route that takes a request (hosts, method,
//! header and cookie conditions, pattern), and the route's
//! `forwarding_path` says what the upstream is sent. The first route that
//! takes it wins; a route that refuses the method or the host leaves the
//! request to the next. None taking it is "not found", never a default
//! route.
//!
//! Which routes serve is the domain's answer too: a route that is not
//! active, or whose service is not, takes nothing and the request falls to
//! the next. A route that serves but cannot be run safely (its pipeline is
//! missing or not active, or it needs client certificates its tenant's
//! authorities cannot verify) still takes the request, and refuses it:
//! falling through would send the request to a route its operator did not
//! pick for it.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::routing::matching::path_rewrite::ForwardedPath;
use ianua_domain::domains::routing::matching::request_match::RequestValues;
use ianua_domain::domains::routing::route::{Route, RouteRequest, evaluation_order, resolve_route};
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{CanonicalPath, Fact, HttpMethod, PipelineId, RouteId, ServiceId};

use crate::request::RequestHost;

/// What a request is routed on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RouteQuery<'a, V> {
    /// The host it was sent to.
    pub host: &'a RequestHost,
    /// The HTTP verb used to select eligible forwarding rules.
    pub method: HttpMethod,
    /// Its canonical path.
    pub path: &'a CanonicalPath,
    /// Its headers and cookies, for route conditions.
    pub values: &'a V,
}

/// The route a request takes, and the service it forwards to.
#[derive(Debug, Clone)]
pub(crate) struct MatchedRoute {
    route: Arc<Route<ResolvedTenant>>,
    service: Arc<Service<ResolvedTenant>>,
    pipeline: Arc<Pipeline<ResolvedTenant>>,
    captured: Vec<(String, String)>,
    forwarding_path: ForwardedPath,
}

impl MatchedRoute {
    /// The pipeline it runs, shared with the table, for the pipeline's
    /// evaluation of this request.
    #[must_use]
    pub(crate) fn shared_pipeline(&self) -> Arc<Pipeline<ResolvedTenant>> {
        Arc::clone(&self.pipeline)
    }

    /// What the route's pattern captured from the path, by name, which the
    /// route's parameter rules read.
    #[must_use]
    pub(crate) fn captured(&self) -> &[(String, String)] {
        &self.captured
    }

    /// The selected forwarding definition that supplied the path captures.
    #[must_use]
    pub(crate) fn route(&self) -> &Route<ResolvedTenant> {
        &self.route
    }

    /// The route, shared with the table, for the request's
    /// [`RequestFacts`](crate::pipeline::facts::RequestFacts).
    #[must_use]
    pub(crate) fn shared_route(&self) -> Arc<Route<ResolvedTenant>> {
        Arc::clone(&self.route)
    }

    /// The service it forwards to.
    #[must_use]
    pub(crate) fn service(&self) -> &Service<ResolvedTenant> {
        &self.service
    }

    /// The pipeline it runs, active.
    #[must_use]
    pub(crate) fn pipeline(&self) -> &Pipeline<ResolvedTenant> {
        &self.pipeline
    }

    /// The route's id, for the request record.
    #[must_use]
    pub(crate) fn route_id(&self) -> &RouteId {
        self.route.id()
    }

    /// The service's id, for the request record and the backend pool.
    #[must_use]
    pub(crate) fn service_id(&self) -> &ServiceId {
        self.service.id()
    }

    /// The path the upstream is sent, after the route's rewrite, spelled
    /// for the wire and without a query.
    #[must_use]
    pub(crate) fn forwarding_path(&self) -> &ForwardedPath {
        &self.forwarding_path
    }
}

/// How routing a request ended.
#[derive(Debug, Clone)]
pub(crate) enum RouteLookup {
    /// This route takes it.
    Found(MatchedRoute),
    /// No route takes it.
    NotFound,
    /// This route takes it and refuses it.
    Refused {
        /// Why it cannot be served.
        why: RouteRefusal,
    },
}

/// Why a route that takes a request cannot serve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteRefusal {
    /// The pipeline it names is not among the tenant's.
    PipelineMissing,
    /// Its pipeline is a draft or turned off, and the domain denies traffic
    /// on its routes.
    PipelineInactive,
    /// It takes client certificates and the tenant's authorities cannot be
    /// used to verify them. It never falls back to no verification.
    CertificatesUnverifiable,
    /// Its rewrite names a parameter the pattern did not capture, or makes
    /// a path that is not canonical. Only a corrupt row does that; nothing
    /// is forwarded with a literal `{name}` in it.
    Unforwardable,
}

/// Whether a tenant's client certificates can be verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientCertificates {
    /// Its authorities were usable, or it names none.
    Verifiable,
    /// Its authorities could not be used.
    Unverifiable,
}

/// What a tenant's routes are compiled against.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RouteSetting<'a> {
    pub(crate) services: &'a HashMap<ServiceId, Arc<Service<ResolvedTenant>>>,
    pub(crate) pipelines: &'a HashMap<PipelineId, Arc<Pipeline<ResolvedTenant>>>,
    pub(crate) certificates: ClientCertificates,
}

/// One tenant's serving routes, in evaluation order.
#[derive(Debug, Default)]
pub(crate) struct RouteTable {
    entries: Vec<Entry>,
}

#[derive(Debug)]
struct Entry {
    route: Arc<Route<ResolvedTenant>>,
    service: Arc<Service<ResolvedTenant>>,
    runs: Result<Arc<Pipeline<ResolvedTenant>>, RouteRefusal>,
}

impl RouteTable {
    /// Compiles `routes` in `setting`.
    ///
    /// A disabled route is left out, and so is one whose service is missing
    /// or disabled: there is nothing to forward it to, and the request
    /// falls to the next route or finds none.
    pub(crate) fn build(mut routes: Vec<Route<ResolvedTenant>>, setting: RouteSetting<'_>) -> Self {
        routes.sort_by(evaluation_order);
        let entries = routes
            .into_iter()
            .filter(Route::is_active)
            .filter_map(|route| Entry::serving(route, setting))
            .collect();
        Self { entries }
    }

    /// The route `query` takes, as the domain's [`resolve_route`] picks it
    /// from the table: the first, in evaluation order, that takes it.
    #[must_use]
    pub(crate) fn find<V: RequestValues>(&self, query: &RouteQuery<'_, V>) -> RouteLookup {
        let request = RouteRequest {
            method: query.method,
            path: query.path,
            host: Fact::Known(query.host.as_str()),
            values: Fact::Known(query.values),
        };
        let Some(entry) = resolve_route(&self.entries, &request, |_| true) else {
            return RouteLookup::NotFound;
        };
        entry.lookup(query.path)
    }

    /// The route `route_id`, when it serves and takes `query`'s method,
    /// conditions and path, whatever host the request named: on the
    /// workflow listener a run pass names the route, and no host picks it.
    #[must_use]
    pub(crate) fn find_named<V: RequestValues>(
        &self,
        route_id: &RouteId,
        query: &RouteQuery<'_, V>,
    ) -> RouteLookup {
        let request = RouteRequest {
            method: query.method,
            path: query.path,
            host: Fact::Unknown,
            values: Fact::Known(query.values),
        };
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.route.id() == route_id && entry.route.takes_once_named(&request))
        else {
            return RouteLookup::NotFound;
        };
        entry.lookup(query.path)
    }

    /// Whether it holds none.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Entry {
    /// What a request for `path` this entry took comes to: the matched
    /// route, or why it cannot run.
    fn lookup(&self, path: &CanonicalPath) -> RouteLookup {
        let pipeline = match &self.runs {
            Ok(pipeline) => Arc::clone(pipeline),
            Err(why) => return RouteLookup::Refused { why: *why },
        };
        let Some(forwarding) = self.route.forwarding(path) else {
            let why = RouteRefusal::Unforwardable;
            return RouteLookup::Refused { why };
        };
        RouteLookup::Found(MatchedRoute {
            route: Arc::clone(&self.route),
            service: Arc::clone(&self.service),
            pipeline,
            captured: forwarding.captures().entries().to_vec(),
            forwarding_path: forwarding.path().clone(),
        })
    }

    /// `route` as it serves in `setting`, or `None` when its service does
    /// not serve.
    fn serving(route: Route<ResolvedTenant>, setting: RouteSetting<'_>) -> Option<Self> {
        let service = setting.services.get(route.service_id())?;
        if !service.is_active() {
            return None;
        }
        let runs = runs(&route, service, setting);
        Some(Self {
            route: Arc::new(route),
            service: Arc::clone(service),
            runs,
        })
    }
}

impl AsRef<Route<ResolvedTenant>> for Entry {
    fn as_ref(&self) -> &Route<ResolvedTenant> {
        &self.route
    }
}

/// The pipeline `route` runs, or why it cannot run one.
fn runs(
    route: &Route<ResolvedTenant>,
    service: &Service<ResolvedTenant>,
    setting: RouteSetting<'_>,
) -> Result<Arc<Pipeline<ResolvedTenant>>, RouteRefusal> {
    let unverifiable = setting.certificates == ClientCertificates::Unverifiable;
    if unverifiable && service.upstream().requires_client_certificate() {
        return Err(RouteRefusal::CertificatesUnverifiable);
    }
    let pipeline = setting
        .pipelines
        .get(route.pipeline_id())
        .ok_or(RouteRefusal::PipelineMissing)?;
    if !pipeline.status().is_active() {
        return Err(RouteRefusal::PipelineInactive);
    }
    Ok(Arc::clone(pipeline))
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_app::test_support::proxy::{test_pipeline_id, test_pipeline_in};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::routing::matching::host::RouteHosts;
    use ianua_domain::domains::routing::matching::parameter::RouteReach;
    use ianua_domain::domains::routing::matching::path_rewrite::{PathRewrite, PathTemplate};
    use ianua_domain::domains::routing::matching::request_match::{
        MatchSubject, RequestCondition, RouteConditions, ValueMatch,
    };
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::route::{AttackMode, RouteRow, WorkflowUse};
    use ianua_domain::domains::routing::route_status::RouteStatus;
    use ianua_domain::types::{
        DeclaredAction, DomainName, HeaderName, HeaderValue, Label, Setting, UrlPath,
    };

    use super::*;
    use crate::request::RequestHeaders;
    use crate::resolve::sign_in::tests::service_with;

    /// The parts of a stored route a test sets.
    pub(crate) struct RouteSpec {
        pub(crate) pattern: &'static str,
        pub(crate) priority: u16,
        pub(crate) methods: Vec<HttpMethod>,
        pub(crate) hosts: RouteHosts,
        pub(crate) rewrite: PathRewrite,
        pub(crate) conditions: RouteConditions,
        pub(crate) status: RouteStatus,
    }

    impl RouteSpec {
        pub(crate) fn on(pattern: &'static str) -> Self {
            Self {
                pattern,
                priority: 100,
                methods: Vec::new(),
                hosts: RouteHosts::Any,
                rewrite: PathRewrite::Keep,
                conditions: RouteConditions::default(),
                status: RouteStatus::Active,
            }
        }

        pub(crate) fn stored(self, service: &ServiceId) -> Route<ResolvedTenant> {
            let now = ianua_domain::shared::clock::now();
            Route::reconstitute(RouteRow {
                id: RouteId::new(),
                name: Label::new("name", "route").unwrap(),
                path_pattern: UrlPath::new(self.pattern).unwrap(),
                methods: self.methods,
                service_id: *service,
                policy: RoutePolicy::Public,
                hosts: self.hosts,
                conditions: self.conditions,
                pipeline_id: test_pipeline_id(),
                path_rewrite: self.rewrite,
                status: self.status,
                priority: self.priority,
                data_class: DataClassLevel::Internal,
                action_class: DeclaredAction::Undeclared,
                reach: RouteReach::Fixed,
                parameter_rules: Vec::new(),
                workflow_use: WorkflowUse::Closed,
                attack_mode: AttackMode::Off,
                created_at: now,
                updated_at: now,
            })
            .unwrap()
        }
    }

    pub(crate) fn active_service() -> Service<ResolvedTenant> {
        service_with(ServiceId::new(), "backend", Setting::Unset, Setting::Unset)
    }

    /// The tenant's one pipeline, in `status`, by its id.
    pub(crate) fn pipelines_in(
        status: PipelineStatus,
    ) -> HashMap<PipelineId, Arc<Pipeline<ResolvedTenant>>> {
        HashMap::from([(test_pipeline_id(), Arc::new(test_pipeline_in(status)))])
    }

    fn table_in(
        specs: Vec<RouteSpec>,
        service: Service<ResolvedTenant>,
        status: PipelineStatus,
        certificates: ClientCertificates,
    ) -> (RouteTable, Vec<RouteId>) {
        let service = Arc::new(service);
        let routes: Vec<Route<ResolvedTenant>> = specs
            .into_iter()
            .map(|spec| spec.stored(service.id()))
            .collect();
        let ids = routes.iter().map(|route| *route.id()).collect();
        let services = HashMap::from([(*service.id(), service)]);
        let pipelines = pipelines_in(status);
        let setting = RouteSetting {
            services: &services,
            pipelines: &pipelines,
            certificates,
        };
        (RouteTable::build(routes, setting), ids)
    }

    fn table_of(specs: Vec<RouteSpec>) -> (RouteTable, Vec<RouteId>) {
        table_in(
            specs,
            active_service(),
            PipelineStatus::Active,
            ClientCertificates::Verifiable,
        )
    }

    fn refusal(result: RouteLookup) -> RouteRefusal {
        match result {
            RouteLookup::Refused { why, .. } => why,
            other => panic!("the route refuses the request, got {other:?}"),
        }
    }

    /// Matching a route with a draft or disabled pipeline returns an inactive
    /// pipeline refusal instead of treating the route as absent.
    #[test]
    fn a_route_whose_pipeline_is_not_active_refuses_rather_than_falls_through() {
        for status in [PipelineStatus::Draft, PipelineStatus::Disabled] {
            let (table, _) = table_in(
                vec![RouteSpec::on("/api/*")],
                active_service(),
                status,
                ClientCertificates::Verifiable,
            );

            let result = lookup(&table, "a.acme.com", HttpMethod::Get, "/api/x");

            assert_eq!(
                refusal(result),
                RouteRefusal::PipelineInactive,
                "{status:?}"
            );
        }
    }

    #[test]
    fn a_route_whose_pipeline_is_missing_refuses() {
        let service = Arc::new(active_service());
        let route = RouteSpec::on("/api/*").stored(service.id());
        let services = HashMap::from([(*service.id(), service)]);
        let setting = RouteSetting {
            services: &services,
            pipelines: &HashMap::new(),
            certificates: ClientCertificates::Verifiable,
        };

        let table = RouteTable::build(vec![route], setting);

        let result = lookup(&table, "a.acme.com", HttpMethod::Get, "/api/x");
        assert_eq!(refusal(result), RouteRefusal::PipelineMissing);
    }

    /// A route requiring client certificates refuses matching requests when
    /// its tenant's authorities cannot verify those certificates.
    #[test]
    fn a_certificate_route_refuses_when_the_authorities_cannot_be_used() {
        let (table, _) = table_in(
            vec![RouteSpec::on("/api/*")],
            certificate_service(),
            PipelineStatus::Active,
            ClientCertificates::Unverifiable,
        );

        let result = lookup(&table, "a.acme.com", HttpMethod::Get, "/api/x");

        assert_eq!(refusal(result), RouteRefusal::CertificatesUnverifiable);
    }

    /// Unusable authorities refuse only the routes that take certificates.
    #[test]
    fn a_token_route_serves_when_the_authorities_cannot_be_used() {
        let (table, _) = table_in(
            vec![RouteSpec::on("/api/*")],
            active_service(),
            PipelineStatus::Active,
            ClientCertificates::Unverifiable,
        );

        let matched = found(lookup(&table, "a.acme.com", HttpMethod::Get, "/api/x"));

        assert!(matched.pipeline().status().is_active());
    }

    fn certificate_service() -> Service<ResolvedTenant> {
        use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
        use ianua_domain::domains::routing::backend::upstream::{
            HostHeader, Upstream, UpstreamTimeout,
        };
        use ianua_domain::domains::routing::service::ServiceRow;
        use ianua_domain::types::HttpUrl;

        let now = ianua_domain::shared::clock::now();
        let upstream = Upstream::new(
            HttpUrl::new("https://app.internal:8080").unwrap(),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_required_client_certificate();
        Service::reconstitute(ServiceRow {
            id: ServiceId::new(),
            name: Label::new("name", "mtls").unwrap(),
            upstream,
            health_check: HealthCheckPolicy::Disabled,
            app_sign_in: Setting::Unset,
            accepted_sign_in: Setting::Unset,
            status: RouteStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .unwrap()
    }

    fn host(name: &str) -> RequestHost {
        RequestHost::new(DomainName::new(name).unwrap()).unwrap()
    }

    fn lookup(table: &RouteTable, on: &str, method: HttpMethod, path: &str) -> RouteLookup {
        lookup_with(table, &Lookup { on, method, path }, &http::HeaderMap::new())
    }

    /// The request line whose route a fixture looks up.
    struct Lookup<'a> {
        on: &'a str,
        method: HttpMethod,
        path: &'a str,
    }

    /// Looks up the request line with its client-supplied headers.
    fn lookup_with(
        table: &RouteTable,
        request: &Lookup<'_>,
        headers: &http::HeaderMap,
    ) -> RouteLookup {
        let path = CanonicalPath::new(request.path).unwrap();
        let host = host(request.on);
        let values = RequestHeaders::new(headers);
        table.find(&RouteQuery {
            host: &host,
            method: request.method,
            path: &path,
            values: &values,
        })
    }

    fn found(result: RouteLookup) -> MatchedRoute {
        match result {
            RouteLookup::Found(matched) => matched,
            other => panic!("a route takes the request, got {other:?}"),
        }
    }

    fn only_on(pattern: &'static str, priority: u16, hosts: &[&str]) -> RouteSpec {
        let domains = hosts.iter().map(|h| DomainName::new(*h).unwrap()).collect();
        RouteSpec {
            priority,
            hosts: RouteHosts::only(domains).unwrap(),
            ..RouteSpec::on(pattern)
        }
    }

    /// What a request on the workflow listener for `path` comes to when its
    /// pass names `route`, sent to a host no route serves.
    fn named(table: &RouteTable, route: &RouteId, path: &str) -> RouteLookup {
        let path = CanonicalPath::new(path).unwrap();
        let host = host("gateway.internal");
        let headers = http::HeaderMap::new();
        let values = RequestHeaders::new(&headers);
        table.find_named(
            route,
            &RouteQuery {
                host: &host,
                method: HttpMethod::Get,
                path: &path,
                values: &values,
            },
        )
    }

    /// A pass names the admin-only route. It is found whatever host the
    /// request named, while a path it does not take, or a route the table
    /// does not hold, finds nothing: a pass never falls through to another
    /// route.
    #[test]
    fn a_named_route_is_found_on_any_host_and_nothing_else_is() {
        let (table, ids) = table_of(vec![
            only_on("/admin/*", 10, &["admin.acme.com"]),
            RouteSpec::on("/*"),
        ]);

        let admin = found(named(&table, &ids[0], "/admin/users"));
        let elsewhere = named(&table, &ids[0], "/billing");
        let unknown = named(&table, &RouteId::new(), "/admin/users");

        assert_eq!(*admin.route_id(), ids[0]);
        assert!(matches!(elsewhere, RouteLookup::NotFound));
        assert!(matches!(unknown, RouteLookup::NotFound));
    }

    #[test]
    fn the_same_path_can_serve_a_different_route_per_domain() {
        let (table, ids) = table_of(vec![
            only_on("/admin/*", 10, &["admin.acme.com"]),
            RouteSpec {
                priority: 20,
                ..RouteSpec::on("/admin/*")
            },
        ]);

        let from_admin = found(lookup(
            &table,
            "admin.acme.com",
            HttpMethod::Get,
            "/admin/users",
        ));
        let from_app = found(lookup(
            &table,
            "app.acme.com",
            HttpMethod::Get,
            "/admin/users",
        ));

        assert_eq!(*from_admin.route_id(), ids[0]);
        assert_eq!(*from_app.route_id(), ids[1]);
    }

    #[test]
    fn a_scoped_route_is_unreachable_from_another_domain() {
        let (table, _) = table_of(vec![only_on("/admin/*", 10, &["admin.acme.com"])]);

        assert!(matches!(
            lookup(&table, "app.acme.com", HttpMethod::Get, "/admin/users"),
            RouteLookup::NotFound
        ));
    }

    #[test]
    fn the_lower_priority_number_is_tried_first() {
        let (table, ids) = table_of(vec![
            RouteSpec {
                priority: 50,
                ..RouteSpec::on("/api/*")
            },
            RouteSpec {
                priority: 10,
                ..RouteSpec::on("/api/*")
            },
        ]);

        let matched = found(lookup(&table, "app.acme.com", HttpMethod::Get, "/api/x"));

        assert_eq!(*matched.route_id(), ids[1]);
    }

    #[test]
    fn on_equal_priority_the_more_specific_route_takes_the_request() {
        let (table, ids) = table_of(vec![RouteSpec::on("/api/*"), RouteSpec::on("/api/users")]);

        let matched = found(lookup(
            &table,
            "app.acme.com",
            HttpMethod::Get,
            "/api/users",
        ));

        assert_eq!(*matched.route_id(), ids[1]);
    }

    /// `/api/users` takes only GET; a POST falls to `/api/*` instead of
    /// ending in "not found".
    #[test]
    fn a_route_refusing_the_method_leaves_the_request_to_the_next() {
        let (table, ids) = table_of(vec![
            RouteSpec {
                methods: vec![HttpMethod::Get],
                ..RouteSpec::on("/api/users")
            },
            RouteSpec::on("/api/*"),
        ]);

        let matched = found(lookup(
            &table,
            "app.acme.com",
            HttpMethod::Post,
            "/api/users",
        ));

        assert_eq!(*matched.route_id(), ids[1]);
    }

    /// Nothing fits: the answer is "not found", never some default route.
    #[test]
    fn a_request_no_route_takes_is_not_found() {
        let (table, _) = table_of(vec![RouteSpec::on("/api/*")]);

        assert!(matches!(
            lookup(&table, "app.acme.com", HttpMethod::Get, "/other"),
            RouteLookup::NotFound
        ));
        assert!(matches!(
            lookup(&RouteTable::default(), "app.acme.com", HttpMethod::Get, "/"),
            RouteLookup::NotFound
        ));
    }

    #[test]
    fn a_disabled_route_takes_nothing() {
        let (table, _) = table_of(vec![RouteSpec {
            status: RouteStatus::Disabled,
            ..RouteSpec::on("/api/*")
        }]);

        assert!(table.is_empty());
    }

    /// A route whose service is gone is dropped rather than compiled
    /// against nothing.
    #[test]
    fn a_route_whose_service_is_missing_is_not_served() {
        let orphan = RouteSpec::on("/api/*").stored(&ServiceId::new());

        let pipelines = pipelines_in(PipelineStatus::Active);
        let setting = RouteSetting {
            services: &HashMap::new(),
            pipelines: &pipelines,
            certificates: ClientCertificates::Verifiable,
        };

        let table = RouteTable::build(vec![orphan], setting);

        assert!(table.is_empty());
    }

    /// Blue/green on a header: the route holding the condition takes the
    /// request only when the header says so.
    #[test]
    fn a_route_condition_reads_the_requests_headers() {
        let blue = RouteConditions::new(vec![RequestCondition::new(
            MatchSubject::Header(HeaderName::new("x-deploy").unwrap()),
            ValueMatch::Exact(HeaderValue::new("blue").unwrap()),
        )])
        .unwrap();
        let (table, ids) = table_of(vec![
            RouteSpec {
                priority: 10,
                conditions: blue,
                ..RouteSpec::on("/api/*")
            },
            RouteSpec {
                priority: 20,
                ..RouteSpec::on("/api/*")
            },
        ]);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-deploy", http::HeaderValue::from_static("blue"));

        let with = found(lookup_with(
            &table,
            &Lookup {
                on: "a.acme.com",
                method: HttpMethod::Get,
                path: "/api/x",
            },
            &headers,
        ));
        let without = found(lookup(&table, "a.acme.com", HttpMethod::Get, "/api/x"));

        assert_eq!(*with.route_id(), ids[0]);
        assert_eq!(*without.route_id(), ids[1]);
    }

    #[test]
    fn strip_prefix_forwards_what_the_wildcard_matched() {
        let (table, _) = table_of(vec![RouteSpec {
            rewrite: PathRewrite::StripPrefix,
            ..RouteSpec::on("/api/v1/*")
        }]);

        let deep = found(lookup(
            &table,
            "a.acme.com",
            HttpMethod::Get,
            "/api/v1/users/123",
        ));
        let own = found(lookup(&table, "a.acme.com", HttpMethod::Get, "/api/v1"));

        assert_eq!(deep.forwarding_path().as_str(), "/users/123");
        assert_eq!(own.forwarding_path().as_str(), "/");
    }

    /// Literal segments match in any case, as the domain says; stripping by
    /// the matched segments still takes the prefix off `/API/V1/...`.
    #[test]
    fn strip_prefix_holds_whatever_case_the_prefix_was_sent_in() {
        let (table, _) = table_of(vec![RouteSpec {
            rewrite: PathRewrite::StripPrefix,
            ..RouteSpec::on("/api/v1/*")
        }]);

        let matched = found(lookup(
            &table,
            "a.acme.com",
            HttpMethod::Get,
            "/API/V1/Users",
        ));

        assert_eq!(matched.forwarding_path().as_str(), "/Users");
    }

    #[test]
    fn a_template_rebuilds_the_path_from_what_was_captured() {
        let (table, _) = table_of(vec![RouteSpec {
            rewrite: PathRewrite::Template(PathTemplate::new("/internal/user/{id}").unwrap()),
            ..RouteSpec::on("/v1/users/{id}")
        }]);

        let matched = found(lookup(
            &table,
            "a.acme.com",
            HttpMethod::Get,
            "/v1/users/a%20b",
        ));

        assert_eq!(matched.forwarding_path().as_str(), "/internal/user/a%20b");
    }

    #[test]
    fn a_template_forwards_a_wildcard_remainder() {
        let (table, _) = table_of(vec![RouteSpec {
            rewrite: PathRewrite::Template(PathTemplate::new("/internal/{rest}").unwrap()),
            ..RouteSpec::on("/api/*")
        }]);

        let matched = found(lookup(
            &table,
            "a.acme.com",
            HttpMethod::Get,
            "/api/users/42",
        ));

        assert_eq!(matched.forwarding_path().as_str(), "/internal/users/42");
    }

    /// The decoded path is what was matched, and it goes upstream encoded
    /// again: `/files private` is never sent as a bare space.
    #[test]
    fn the_forwarded_path_is_the_matched_path_spelled_for_the_wire() {
        let (table, _) = table_of(vec![RouteSpec::on("/files/*")]);

        let matched = found(lookup(
            &table,
            "a.acme.com",
            HttpMethod::Get,
            "/files/a%20b",
        ));

        assert_eq!(matched.forwarding_path().as_str(), "/files/a%20b");
    }
}
