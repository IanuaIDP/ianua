//! Create service: define a backend the tenant's routes can forward to.

use std::sync::Arc;

use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::service::{CreateServiceParams, Service};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{Label, ServiceId, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::routing::{ConnectorStore, ServiceStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::routing::connectors::lookup::ensure_upstream_reachable;
use crate::use_cases::routing::services::upstream_tls::{
    UpstreamTlsRequest, client_key_place, ensure_no_tls_given, sealed_tls,
};

/// What a new service is made of.
pub struct CreateRequest {
    /// Service name, unique within the tenant.
    pub name: Label,
    /// Where requests go, and how they are addressed: its backends, retries,
    /// balancing, circuit breaker, assertion audience and whether a
    /// connector reaches it. It carries no TLS; that is given in `tls`.
    pub upstream: Upstream,
    /// How this service's backends are probed.
    pub health_check: HealthCheckPolicy,
    /// How the gateway opens TLS to the upstream, when it needs more than
    /// the public roots.
    pub tls: Setting<UpstreamTlsRequest>,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// The tenant's connectors, one of which may reach the upstream.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// Seals the upstream client certificate's private key.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// The plan's ceiling on services.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Internal networks an upstream may target besides public addresses.
    /// Set by the operator for the whole deployment.
    pub upstream_networks: UpstreamNetworks,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Adds a backend to the tenant.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// `upstream`, once it may be reached the way it says, with `tls`
    /// sealed onto it for the service `service`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the upstream carries TLS of its own, a
    ///   direct target is a refused internal address, its connector is
    ///   revoked or may not dial a target, or the TLS server name is a
    ///   wildcard.
    /// - `AppError::NotFound` when its connector is not the tenant's.
    /// - `AppError::Internal` on storage or sealing failure.
    async fn prepared_upstream(
        &self,
        tenant: &ScopedTenant,
        upstream: Upstream,
        tls: Setting<UpstreamTlsRequest>,
        service: &ServiceId,
    ) -> Result<Upstream, AppError> {
        ensure_no_tls_given(&upstream)?;
        let connectors = self.ports.connector_store.as_ref();
        ensure_upstream_reachable(connectors, tenant, &upstream, &self.ports.upstream_networks)
            .await?;
        let Setting::Set(tls) = tls else {
            return Ok(upstream);
        };
        let place = client_key_place(tenant, service);
        let sealed = sealed_tls(self.ports.encryptor.as_ref(), tls, &place).await?;
        Ok(upstream.with_tls(sealed))
    }

    /// Refuses another service once `caller`'s plan has as many as it
    /// allows in `tenant`.
    ///
    /// # Errors
    ///
    /// `AppError::Forbidden` when the plan's service limit is reached.
    async fn ensure_room_for_another(
        &self,
        caller: &CallerContext,
        tenant: &ScopedTenant,
    ) -> Result<(), AppError> {
        self.ports
            .limit_enforcer
            .check_tenant_limit(caller.plan_limits(), tenant, ResourceKind::Services)
            .await
            .map_err(AppError::from_domain)
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<ServiceId, AppError>;

    /// Creates the service and records `routing.service_created`. A client
    /// key given for upstream TLS is stored sealed, and is in no event.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without routing-creation rights or with a full plan.
    /// - `AppError::Domain` for forbidden internal upstreams, embedded TLS, a revoked/unauthorized connector or contradictory settings.
    /// - `AppError::NotFound` for a connector outside the tenant; `Conflict` for a taken service name.
    /// - `AppError::Internal` on storage, sealing or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<ServiceId, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let by = RoutingControl::new(&authority);
        by.ensure_may(RoutingRight::Create)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let id = ServiceId::new();
        let upstream = self
            .prepared_upstream(&tenant, request.upstream, request.tls, &id)
            .await?;
        let params = CreateServiceParams {
            id,
            name: request.name,
            upstream,
            health_check: request.health_check,
        };
        let mut service = Service::create(params, &by).map_err(AppError::from_domain)?;
        self.ensure_room_for_another(caller, &tenant).await?;
        self.ports
            .service_store
            .save(&tenant, &service)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), service.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(*service.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::backend::assertion::AssertionAudience;
    use ianua_domain::domains::routing::backend::balancing::LoadBalancing;
    use ianua_domain::domains::routing::backend::circuit_breaker::CircuitBreaker;
    use ianua_domain::domains::routing::backend::retry::{
        RetriedMethods, RetryOn, RetryPolicy, UpstreamRetryParams,
    };
    use ianua_domain::domains::routing::backend::tls::{
        UpstreamTls, UpstreamTlsParams, UpstreamTrust,
    };
    use ianua_domain::domains::routing::connector::PrivateConnector;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Audience, CertificatePem, ConnectorId, DomainName};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::domain::{TEST_CERTIFICATE_PEM, TEST_PRIVATE_KEY_PEM};
    use crate::test_support::routing::{
        FakeConnectorStore, FakeServiceStore, awaiting_connector, routing_admin, routing_label,
        unpinned_upstream,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::routing::services::upstream_tls::ClientCertificateRequest;

    /// The stores, the audit record and the use case a test runs.
    struct Fixture {
        services: Arc<FakeServiceStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: CreateUseCase,
    }

    /// A fixture whose ports are the defaults as `ports` changes them.
    fn fixture_with(ports: impl FnOnce(CreatePorts) -> CreatePorts) -> Fixture {
        let services = Arc::new(FakeServiceStore::empty());
        Fixture {
            use_case: CreateUseCase::new(ports(CreatePorts {
                service_store: services.clone(),
                upstream_networks: UpstreamNetworks::public_only(),
                ..CreatePorts::fakes()
            })),
            services,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// A fixture with the default ports.
    fn fixture() -> Fixture {
        fixture_with(|ports| ports)
    }

    /// A fixture holding `connector`.
    fn fixture_holding(connector: &PrivateConnector<ResolvedTenant>) -> Fixture {
        let connectors = FakeConnectorStore::holding(test_ctx().tenant_id(), connector);
        fixture_with(|ports| CreatePorts {
            connector_store: Arc::new(connectors),
            ..ports
        })
    }

    /// A service named `projects-api` at `url`, with no TLS settings.
    fn request(url: &str) -> CreateRequest {
        request_for(unpinned_upstream(url))
    }

    /// A service named `projects-api` forwarding to `upstream`.
    fn request_for(upstream: Upstream) -> CreateRequest {
        CreateRequest {
            name: routing_label("projects-api"),
            upstream,
            health_check: HealthCheckPolicy::default(),
            tls: Setting::Unset,
        }
    }

    /// An upstream at `url`, reached through `connector`.
    fn through(url: &str, connector: ConnectorId) -> Upstream {
        unpinned_upstream(url).through_connector(connector)
    }

    /// Runs the use case for `request`.
    fn run(f: &Fixture, request: CreateRequest) -> Result<ServiceId, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    /// The service `id` as stored.
    fn saved(f: &Fixture, id: &ServiceId) -> Service<ResolvedTenant> {
        block_on(f.services.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
    }

    /// TLS to a private CA, presenting the test client certificate.
    fn private_tls() -> UpstreamTlsRequest {
        UpstreamTlsRequest {
            trust: UpstreamTrust::PrivateCa(CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap()),
            client_certificate: Setting::Set(ClientCertificateRequest {
                certificate: CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap(),
                private_key: Secret::new(TEST_PRIVATE_KEY_PEM),
            }),
            server_name: Setting::Set(DomainName::new("projects.corp.internal").unwrap()),
        }
    }

    /// Ann adds the projects backend. It is saved and the change recorded.
    #[test]
    fn a_service_is_saved_and_recorded() {
        let f = fixture();

        let result = run(&f, request("https://projects.example.com:8080"));

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(f.services.count(), 1);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.service_created"]
        );
    }

    /// Ann's backend retries twice on a refused connection, takes the least
    /// busy backend, has no circuit breaker and names its own assertion
    /// audience. The service keeps every one of those settings.
    #[test]
    fn the_upstream_settings_are_kept_as_given() {
        let f = fixture();
        let retry = RetryPolicy::new(UpstreamRetryParams {
            attempts: 2,
            retry_on: vec![RetryOn::ConnectFailure],
            methods: RetriedMethods::Every,
            base_backoff_ms: 50,
            max_backoff_ms: 500,
        })
        .unwrap();
        let upstream = unpinned_upstream("https://projects.example.com:8080")
            .with_retries(retry)
            .with_balancing(LoadBalancing::LeastConnections)
            .with_circuit_breaker(CircuitBreaker::Off)
            .with_assertion_audience(AssertionAudience::Named(
                Audience::new("projects-api").unwrap(),
            ));

        let id = run(&f, request_for(upstream.clone())).unwrap();

        assert_eq!(*saved(&f, &id).upstream(), upstream);
    }

    /// Ann's backend sits on the company PKI and asks for a client
    /// certificate. The service keeps the CA and name, and the key only
    /// sealed.
    #[test]
    fn a_client_key_is_stored_sealed() {
        let f = fixture();
        let request = CreateRequest {
            tls: Setting::Set(private_tls()),
            ..request("https://projects.example.com:8080")
        };

        let id = run(&f, request).unwrap();

        let service = saved(&f, &id);
        let tls = service.upstream().tls().unwrap();
        assert_eq!(
            *tls.client_certificate().unwrap().private_key(),
            FakeEncryptor::sealed_for(
                TEST_PRIVATE_KEY_PEM,
                &client_key_place(&test_ctx().tenant(), &id)
            )
        );
        assert_eq!(
            tls.server_name().map(DomainName::as_str),
            Some("projects.corp.internal")
        );
    }

    /// An upstream carrying embedded TLS settings is refused and saves no service.
    #[test]
    fn an_upstream_carrying_its_own_tls_is_refused() {
        let f = fixture();
        let tls = UpstreamTls::new(UpstreamTlsParams {
            trust: UpstreamTrust::PublicRoots,
            client_certificate: Setting::Unset,
            server_name: Setting::Unset,
        })
        .unwrap();
        let upstream = unpinned_upstream("https://projects.example.com:8080").with_tls(tls);

        let result = run(&f, request_for(upstream));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.services.count(), 0);
    }

    /// Private TLS settings on a plain HTTP backend are refused, saving no
    /// service and recording no creation event.
    #[test]
    fn tls_on_a_plain_http_backend_is_refused() {
        let f = fixture();
        let request = CreateRequest {
            tls: Setting::Set(private_tls()),
            ..request("http://projects.example.com:8080")
        };

        let result = run(&f, request);

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.services.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann's payroll app has no public address. Reached through the payroll
    /// connector, whose scope names it, the service is saved.
    #[test]
    fn a_private_backend_through_a_connector_that_may_dial_it_is_saved() {
        let connector = awaiting_connector("payroll", "code", &["*.payroll.corp.internal"]);
        let f = fixture_holding(&connector);
        let upstream = through("https://app.payroll.corp.internal", *connector.id());

        let result = run(&f, request_for(upstream));

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(f.services.count(), 1);
    }

    /// A backend outside its connector's allowed domains is refused and
    /// saves no service.
    #[test]
    fn a_backend_outside_the_connectors_scope_is_refused() {
        let connector = awaiting_connector("payroll", "code", &["*.payroll.corp.internal"]);
        let f = fixture_holding(&connector);
        let upstream = through("https://dc.ad.internal", *connector.id());

        let result = run(&f, request_for(upstream));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.services.count(), 0);
    }

    /// A backend using a revoked connector is refused and saves no service.
    #[test]
    fn a_backend_through_a_revoked_connector_is_refused() {
        let mut connector = awaiting_connector("payroll", "code", &["*.payroll.corp.internal"]);
        connector.revoke(&routing_admin()).unwrap();
        let f = fixture_holding(&connector);
        let upstream = through("https://app.payroll.corp.internal", *connector.id());

        let result = run(&f, request_for(upstream));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.services.count(), 0);
    }

    /// Naming a connector absent from the tenant returns not found and saves
    /// no service.
    #[test]
    fn a_connector_the_tenant_does_not_have_is_not_found() {
        let f = fixture();
        let upstream = through("https://app.payroll.corp.internal", ConnectorId::new());

        let result = run(&f, request_for(upstream));

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(f.services.count(), 0);
    }

    /// A direct upstream at the link-local metadata address is refused under
    /// public-only network rules. No service or creation event is stored.
    #[test]
    fn a_private_upstream_is_refused() {
        let f = fixture();

        let result = run(&f, request("http://169.254.169.254/latest"));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.services.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann's operator allows `10.0.0.0/8`. Her service there is saved.
    #[test]
    fn a_private_upstream_inside_an_allowed_network_is_saved() {
        let f = fixture_with(|ports| CreatePorts {
            upstream_networks: UpstreamNetworks::parse_list("10.0.0.0/8").unwrap(),
            ..ports
        });

        let result = run(&f, request("http://10.0.0.5:8080"));

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(f.services.count(), 1);
    }

    /// Acme's plan holds no more services. Ann's new one is refused and
    /// nothing is saved.
    #[test]
    fn a_service_past_the_plan_limit_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports
        });

        let result = run(&f, request("https://projects.example.com:8080"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.services.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Creating a service without tenant rights is forbidden, saving no
    /// service and recording no creation event.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports
        });

        let result = run(&f, request("https://mallory.example.com"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.services.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot create a service and leaves the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports
        });

        let result = run(&f, request("https://projects.example.com:8080"));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.services.count(), 0);
    }
}
