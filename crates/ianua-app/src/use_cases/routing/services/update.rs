//! Update service: change a backend's name, address or health checks.

use std::sync::Arc;

use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{Label, ServiceId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::{ConnectorStore, RouteStore, ServiceStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::routing::connectors::lookup::ensure_upstream_reachable;
use crate::use_cases::routing::lookup::{existing_service, routes_to};
use crate::use_cases::routing::services::upstream_tls::{ensure_no_tls_given, with_tls};

/// What to change on a service. A field left `None` stays as it is.
pub struct UpdateRequest {
    /// The service to change.
    pub service_id: ServiceId,
    /// A new name.
    pub name: Option<Label>,
    /// A new upstream: its backends, retries, balancing, circuit breaker,
    /// assertion audience and whether a connector reaches it. It carries no
    /// TLS; the service keeps its own, changed through
    /// [`ChangeTlsUseCase`](crate::use_cases::routing::services::change_tls::ChangeTlsUseCase).
    pub upstream: Option<Upstream>,
    /// A new health-check policy.
    pub health_check: Option<HealthCheckPolicy>,
}

impl UpdateRequest {
    /// Whether this request changes nothing.
    fn is_empty(&self) -> bool {
        self.name.is_none() && self.upstream.is_none() && self.health_check.is_none()
    }
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// The tenant's routes, each of which must still work with a new
    /// upstream of the service it forwards to.
    pub route_store: Arc<dyn RouteStore>,
    /// The tenant's connectors, one of which may reach a new upstream.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// Internal networks an upstream may target besides public addresses.
    pub upstream_networks: UpstreamNetworks,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a backend.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }

    /// `request` with its new upstream, if any, checked to be reachable the
    /// way it says, and given the TLS `service` has now.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the new upstream carries TLS of its own, a
    ///   direct target is a refused internal address, or its connector is
    ///   revoked or may not dial a target.
    /// - `AppError::NotFound` when its connector is not the tenant's.
    /// - `AppError::Internal` on storage failure.
    async fn vetted(
        &self,
        tenant: &ScopedTenant,
        service: &Service<ResolvedTenant>,
        mut request: UpdateRequest,
    ) -> Result<UpdateRequest, AppError> {
        let Some(given) = request.upstream.take() else {
            return Ok(request);
        };
        ensure_no_tls_given(&given)?;
        let connectors = self.ports.connector_store.as_ref();
        ensure_upstream_reachable(connectors, tenant, &given, &self.ports.upstream_networks)
            .await?;
        request.upstream = Some(with_tls(given, service.upstream().tls()));
        Ok(request)
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Applies the changes `request` carries and records
    /// `routing.service_updated`. A request changing nothing records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without routing-update rights; `NotFound` for a missing service or foreign connector.
    /// - `AppError::Domain` for forbidden internal upstreams or missing audiences required by routes/app sign-in.
    /// - `AppError::Domain` also covers embedded TLS, revoked/unauthorized connectors or contradictory settings including service TLS.
    /// - `AppError::Conflict` for a taken service name; `Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let by = RoutingControl::new(&authority);
        by.ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.service_store.as_ref();
        let mut service = existing_service(store, &tenant, &request.service_id).await?;
        if request.is_empty() {
            return Ok(());
        }
        let request = self.vetted(&tenant, &service, request).await?;
        let routes = routes_to(self.ports.route_store.as_ref(), &tenant, service.id()).await?;
        apply_changes(&mut service, request, &routes, &by).map_err(AppError::from_domain)?;
        store
            .save(&tenant, &service)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), service.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Applies every change `request` carries to `service`, held to the
/// `routes` that forward to it.
fn apply_changes(
    service: &mut Service<ResolvedTenant>,
    request: UpdateRequest,
    routes: &[Route<ResolvedTenant>],
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if let Some(name) = request.name {
        service.rename(name, by)?;
    }
    if let Some(health_check) = request.health_check {
        service.change_health_check(health_check, by)?;
    }
    let Some(upstream) = request.upstream else {
        return Ok(());
    };
    service.replace_upstream(upstream, routes, by)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::backend::tls::{
        UpstreamTls, UpstreamTlsParams, UpstreamTrust,
    };
    use ianua_domain::domains::routing::connector::scope::UpstreamReach;
    use ianua_domain::types::{DomainName, Setting};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakeConnectorStore, FakeRouteStore, FakeServiceStore, RouteShape, awaiting_connector,
        pinned_upstream, route_of, routing_label, service_named, unpinned_upstream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The stores, the audit record, the use case a test runs, and the
    /// service it holds.
    struct Fixture {
        services: Arc<FakeServiceStore>,
        routes: Arc<FakeRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        service: Service<ResolvedTenant>,
        use_case: UpdateUseCase,
    }

    /// A fixture holding the `api` service at `upstream` and `connectors`,
    /// the caller holding what `authorities` says.
    fn fixture_over(
        upstream: Upstream,
        connectors: FakeConnectorStore,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        let service = service_named("api", upstream);
        let services = Arc::new(FakeServiceStore::empty());
        block_on(services.save(&test_ctx().tenant(), &service)).unwrap();
        let routes = Arc::new(FakeRouteStore::empty());
        Fixture {
            use_case: UpdateUseCase::new(UpdatePorts {
                service_store: services.clone(),
                route_store: routes.clone(),
                connector_store: Arc::new(connectors),
                upstream_networks: UpstreamNetworks::public_only(),
                tenant_authorities: Arc::new(authorities),
            }),
            services,
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            service,
        }
    }

    /// A fixture holding the `api` service pinned to `client`, the caller
    /// holding what `authorities` says.
    fn fixture_holding(authorities: FakeTenantAuthorities) -> Fixture {
        fixture_over(
            pinned_upstream("https://backend.example.com:8080", "client"),
            FakeConnectorStore::empty(),
            authorities,
        )
    }

    /// TLS to the public roots under the name `api.corp.internal`.
    fn named_tls() -> UpstreamTls {
        UpstreamTls::new(UpstreamTlsParams {
            trust: UpstreamTrust::PublicRoots,
            client_certificate: Setting::Unset,
            server_name: Setting::Set(DomainName::new("api.corp.internal").unwrap()),
        })
        .unwrap()
    }

    /// Ann moves a service with upstream TLS to `v2`. It keeps its TLS.
    #[test]
    fn a_new_upstream_keeps_the_services_tls() {
        let f = fixture_over(
            pinned_upstream("https://backend.example.com:8080", "client").with_tls(named_tls()),
            FakeConnectorStore::empty(),
            FakeTenantAuthorities::holding_everything(),
        );

        run(
            &f,
            new_upstream(&f, pinned_upstream("https://v2.example.com:8080", "client")),
        )
        .unwrap();

        assert_eq!(saved(&f).upstream().tls(), Some(&named_tls()));
    }

    /// An upstream update carrying embedded TLS settings is refused. Saved
    /// TLS settings remain absent and no update event is recorded.
    #[test]
    fn a_new_upstream_carrying_its_own_tls_is_refused() {
        let f = fixture();
        let upstream =
            pinned_upstream("https://v2.example.com:8080", "client").with_tls(named_tls());

        let result = run(&f, new_upstream(&f, upstream));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(saved(&f).upstream().tls().is_none());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann moves the service behind the payroll connector, whose scope
    /// names its new address. It is saved.
    #[test]
    fn a_new_upstream_through_a_connector_that_may_dial_it_is_saved() {
        let connector = awaiting_connector("payroll", "code", &["*.payroll.corp.internal"]);
        let f = fixture_over(
            unpinned_upstream("https://backend.example.com:8080"),
            FakeConnectorStore::holding(test_ctx().tenant_id(), &connector),
            FakeTenantAuthorities::holding_everything(),
        );
        let upstream = unpinned_upstream("https://app.payroll.corp.internal")
            .through_connector(*connector.id());

        run(&f, new_upstream(&f, upstream)).unwrap();

        assert_eq!(
            saved(&f).upstream().reach(),
            UpstreamReach::Connector(*connector.id())
        );
    }

    /// Moving a service outside its connector's allowed domains is refused.
    /// The service retains direct reach and no update event is recorded.
    #[test]
    fn a_new_upstream_outside_the_connectors_scope_is_refused() {
        let connector = awaiting_connector("payroll", "code", &["*.payroll.corp.internal"]);
        let f = fixture_over(
            unpinned_upstream("https://backend.example.com:8080"),
            FakeConnectorStore::holding(test_ctx().tenant_id(), &connector),
            FakeTenantAuthorities::holding_everything(),
        );
        let upstream =
            unpinned_upstream("https://dc.ad.internal").through_connector(*connector.id());

        let result = run(&f, new_upstream(&f, upstream));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(saved(&f).upstream().reach(), UpstreamReach::Direct);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A fixture holding the `api` service, run by a routing admin.
    fn fixture() -> Fixture {
        fixture_holding(FakeTenantAuthorities::holding_everything())
    }

    fn with_route(f: &Fixture, shape: RouteShape<'_>) {
        let route = route_of(shape, &f.service, &test_pipeline());
        block_on(f.routes.save(&test_ctx().tenant(), &route)).unwrap();
    }

    fn change(service_id: ServiceId) -> UpdateRequest {
        UpdateRequest {
            service_id,
            name: None,
            upstream: None,
            health_check: None,
        }
    }

    fn new_upstream(f: &Fixture, upstream: Upstream) -> UpdateRequest {
        UpdateRequest {
            upstream: Some(upstream),
            ..change(*f.service.id())
        }
    }

    fn run(f: &Fixture, request: UpdateRequest) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    fn saved(f: &Fixture) -> Service<ResolvedTenant> {
        block_on(f.services.find_by_id(&test_ctx().tenant(), f.service.id()))
            .unwrap()
            .unwrap()
    }

    /// Ann moves the backend to `v2`. The service forwards there and the
    /// change is recorded.
    #[test]
    fn a_new_upstream_is_saved_and_recorded() {
        let f = fixture();

        run(
            &f,
            new_upstream(&f, pinned_upstream("https://v2.example.com:8080", "client")),
        )
        .unwrap();

        assert_eq!(
            saved(&f).upstream().url().as_str(),
            "https://v2.example.com:8080"
        );
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.service_updated"]
        );
    }

    /// Ann sends an edit that changes nothing. Nothing is recorded.
    #[test]
    fn an_empty_change_records_nothing() {
        let f = fixture();

        run(&f, change(*f.service.id())).unwrap();

        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Replacing the upstream with the link-local metadata address is refused
    /// and preserves the service's saved address.
    #[test]
    fn a_private_upstream_is_refused() {
        let f = fixture();

        let result = run(
            &f,
            new_upstream(
                &f,
                pinned_upstream("http://169.254.169.254/latest", "client"),
            ),
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(
            saved(&f).upstream().url().as_str(),
            "https://backend.example.com:8080"
        );
    }

    /// Removing the audience while an authenticated route uses the service
    /// is refused. The audience stays set and no update event is recorded.
    #[test]
    fn dropping_the_audience_under_a_signed_in_route_is_refused() {
        let f = fixture();
        with_route(&f, RouteShape::signed_in("API", "/api/*"));

        let result = run(
            &f,
            new_upstream(&f, unpinned_upstream("https://backend.example.com:8080")),
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(saved(&f).upstream().expected_audience().is_some());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann drops the audience while only a public route forwards here.
    /// Nobody signs in there, so it is allowed.
    #[test]
    fn dropping_the_audience_under_public_routes_is_allowed() {
        let f = fixture();
        with_route(&f, RouteShape::public("Docs", "/docs/*"));

        run(
            &f,
            new_upstream(&f, unpinned_upstream("https://backend.example.com:8080")),
        )
        .unwrap();

        assert!(saved(&f).upstream().expected_audience().is_none());
    }

    /// Ann drops the audience on a service nothing routes to yet. It is
    /// allowed.
    #[test]
    fn dropping_the_audience_with_no_route_is_allowed() {
        let f = fixture();

        run(
            &f,
            new_upstream(&f, unpinned_upstream("https://backend.example.com:8080")),
        )
        .unwrap();

        assert!(saved(&f).upstream().expected_audience().is_none());
    }

    /// Ann turns the health checks off. They stay off.
    #[test]
    fn health_checks_can_be_turned_off() {
        let f = fixture();

        run(
            &f,
            UpdateRequest {
                health_check: Some(HealthCheckPolicy::Disabled),
                ..change(*f.service.id())
            },
        )
        .unwrap();

        assert!(saved(&f).health_check().active().is_none());
    }

    /// Ann renames a service that does not exist. She is told it was not
    /// found.
    #[test]
    fn an_unknown_service_is_not_found() {
        let f = fixture();

        let result = run(
            &f,
            UpdateRequest {
                name: Some(routing_label("ghost")),
                ..change(ServiceId::new())
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Changing a service's upstream without the update right is forbidden
    /// and preserves its saved address.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture_holding(FakeTenantAuthorities::holding(&[]));

        let result = run(
            &f,
            new_upstream(&f, pinned_upstream("https://mallory.example.com", "client")),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            saved(&f).upstream().url().as_str(),
            "https://backend.example.com:8080"
        );
    }

    /// A caller without the update right receives a permission refusal even
    /// when the requested service does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_service() {
        let f = fixture_holding(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, change(ServiceId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot rename a service.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_holding(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(
            &f,
            UpdateRequest {
                name: Some(routing_label("mine")),
                ..change(*f.service.id())
            },
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
