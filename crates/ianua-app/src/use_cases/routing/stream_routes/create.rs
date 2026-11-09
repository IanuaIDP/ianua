//! Create stream route: open a port below HTTP and say who may use it.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::stream::access::StreamAccess;
use ianua_domain::domains::routing::stream::{
    CreateStreamRouteParams, ListenPort, StreamBackend, StreamPolicy, StreamProtocol, StreamRoute,
    StreamTimeouts,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{Label, StreamRouteId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::routing::StreamRouteStore;
use crate::services::routing::reachability::reject_private_stream_backends;
use crate::use_case::Command;
use crate::use_cases::routing::stream_routes::access::{StreamAccessPorts, ensure_access_known};

/// What a new stream route is made of.
pub struct CreateRequest {
    /// Name, unique within the tenant.
    pub name: Label,
    /// How the proxy speaks on the port.
    pub protocol: StreamProtocol,
    /// The externally bound socket through which clients reach this service.
    pub listen_port: ListenPort,
    /// Which server names the handshake may ask for.
    pub sni: RouteHosts,
    /// What is checked on the wire.
    pub policy: StreamPolicy,
    /// Who by name may pass: anyone the policy lets through, people meeting
    /// a route policy, or named consumers.
    pub access: StreamAccess,
    /// Where accepted streams go.
    pub backends: Vec<StreamBackend>,
    /// How long a stream may take to start, and stay silent.
    pub timeouts: StreamTimeouts,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// The plan's ceiling on stream routes.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// The tenant's consumers and permission catalogue, which the access
    /// may name.
    pub access: StreamAccessPorts,
    /// Internal networks a backend may sit in besides public addresses.
    /// Set by the operator for the whole deployment.
    pub upstream_networks: UpstreamNetworks,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Opens a port.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<StreamRouteId, AppError>;

    /// Opens the port `request` describes and records
    /// `routing.stream_route_created`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without routing-creation rights or with a full plan.
    /// - `AppError::NotFound` for a consumer outside the tenant; `Domain` for forbidden internal backends.
    /// - `AppError::Domain` also covers protocol-incompatible policy/server names/access or undeclared people-policy permissions.
    /// - `AppError::Conflict` for a port claimed by any tenant; `Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<StreamRouteId, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Create)
            .map_err(AppError::from_domain)?;
        reject_private_stream_backends(&request.backends, &self.ports.upstream_networks)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        ensure_access_known(self.ports.access.records(), &tenant, &request.access).await?;
        let mut route = new_stream_route(request, &control)?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(caller.plan_limits(), &tenant, ResourceKind::StreamRoutes)
            .await
            .map_err(AppError::from_domain)?;
        self.ports
            .stream_route_store
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

/// The stream route `request` describes, opened by `by`.
fn new_stream_route(
    request: CreateRequest,
    by: &RoutingControl<'_>,
) -> Result<StreamRoute<ResolvedTenant>, AppError> {
    StreamRoute::create(
        CreateStreamRouteParams {
            name: request.name,
            protocol: request.protocol,
            listen_port: request.listen_port,
            sni: request.sni,
            policy: request.policy,
            access: request.access,
            backends: request.backends,
            timeouts: request.timeouts,
        },
        by,
    )
    .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::stream::access::StreamConsumers;
    use ianua_domain::types::{ConsumerId, TenantId};

    use super::*;
    use crate::tenancy::ScopedTenant;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::consumers::{
        FakeConsumerStore, consumer_named, consumers_of_test_tenant,
    };
    use crate::test_support::routing::{FakeStreamRouteStore, routing_label, stream_route_on};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    struct Fixture {
        routes: Arc<FakeStreamRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: CreateUseCase,
    }

    fn fixture_with(ports: impl FnOnce(CreatePorts) -> CreatePorts) -> Fixture {
        let routes = Arc::new(FakeStreamRouteStore::empty());
        Fixture {
            use_case: CreateUseCase::new(ports(CreatePorts {
                stream_route_store: routes.clone(),
                access: StreamAccessPorts {
                    resource_type_store: Arc::new(FakeResourceTypeStore::seeded(
                        test_ctx().tenant_id(),
                    )),
                    ..StreamAccessPorts::fakes()
                },
                upstream_networks: UpstreamNetworks::public_only(),
                ..CreatePorts::fakes()
            })),
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn fixture() -> Fixture {
        fixture_with(|ports| ports)
    }

    fn request(host: &str, protocol: StreamProtocol, policy: StreamPolicy) -> CreateRequest {
        CreateRequest {
            name: routing_label("postgres"),
            protocol,
            listen_port: ListenPort::new(15432).unwrap(),
            sni: RouteHosts::Any,
            policy,
            access: StreamAccess::AnyHolder,
            backends: vec![StreamBackend::new(host, 5432, 100).unwrap()],
            timeouts: StreamTimeouts::default(),
        }
    }

    fn tcp_to(host: &str) -> CreateRequest {
        request(host, StreamProtocol::Tcp, StreamPolicy::Public)
    }

    fn tunnel_for(access: StreamAccess) -> CreateRequest {
        CreateRequest {
            access,
            ..request("db.example.com", StreamProtocol::Tcp, StreamPolicy::Tunnel)
        }
    }

    fn run(f: &Fixture, request: CreateRequest) -> Result<StreamRouteId, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    /// Ann opens port 15432 to Acme's database. It is saved and the change
    /// recorded.
    #[test]
    fn a_port_is_opened_and_recorded() {
        let f = fixture();

        let result = run(&f, tcp_to("db.example.com"));

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(f.routes.count(), 1);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.stream_route_created"]
        );
    }

    /// Ann opens a signed-in tunnel to the database for people signed in to
    /// Acme. It is saved with that access.
    #[test]
    fn a_tunnel_for_signed_in_people_is_opened() {
        let f = fixture();

        let id = run(
            &f,
            tunnel_for(StreamAccess::People(RoutePolicy::Authenticated)),
        )
        .unwrap();

        let saved = block_on(f.routes.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.access(),
            &StreamAccess::People(RoutePolicy::Authenticated)
        );
    }

    /// Ann opens a tunnel for the billing consumer Acme has. It is saved.
    #[test]
    fn a_tunnel_for_a_known_consumer_is_opened() {
        let billing = consumer_named("billing", DataClassLevel::Internal);
        let named = StreamConsumers::new(vec![*billing.id()]).unwrap();
        let f = fixture_with(|mut ports| {
            ports.access.consumer_store = consumers_of_test_tenant(billing);
            ports
        });

        let result = run(&f, tunnel_for(StreamAccess::Consumers(named)));

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(f.routes.count(), 1);
    }

    /// A tunnel names two consumers. Their existence is checked together,
    /// and the saved route and its audit record retain the requested access.
    #[test]
    fn named_consumers_share_one_validation_read() {
        let billing = consumer_named("billing", DataClassLevel::Internal);
        let metrics = consumer_named("metrics", DataClassLevel::Internal);
        let named = StreamConsumers::new(vec![*billing.id(), *metrics.id()]).unwrap();
        let consumers = Arc::new(FakeConsumerStore::empty());
        consumers.consumers.lock().unwrap().extend([
            (test_ctx().tenant_id(), billing),
            (test_ctx().tenant_id(), metrics),
        ]);
        let f = fixture_with(|mut ports| {
            ports.access.consumer_store = consumers.clone();
            ports
        });
        let access = StreamAccess::Consumers(named);

        let id = run(&f, tunnel_for(access.clone())).unwrap();

        let saved = block_on(f.routes.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert_eq!(saved.access(), &access);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.stream_route_created"]
        );
        assert_eq!(consumers.id_reads(), 1);
    }

    /// A tunnel naming an unknown consumer returns not found, saves no
    /// route and records no creation event.
    #[test]
    fn a_tunnel_naming_an_unknown_consumer_is_refused() {
        let f = fixture();
        let named = StreamConsumers::new(vec![ConsumerId::new()]).unwrap();

        let result = run(&f, tunnel_for(StreamAccess::Consumers(named)));

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(f.routes.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A public TCP port cannot require authenticated people. The incompatible
    /// settings are refused and no route is saved.
    #[test]
    fn people_on_a_public_port_are_refused() {
        let f = fixture();

        let result = run(
            &f,
            CreateRequest {
                access: StreamAccess::People(RoutePolicy::Authenticated),
                ..tcp_to("db.example.com")
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.routes.count(), 0);
    }

    /// A tunnel cannot use unrestricted holder access. The incompatible
    /// settings are refused and no route is saved.
    #[test]
    fn a_tunnel_open_to_anyone_is_refused() {
        let f = fixture();

        let result = run(&f, tunnel_for(StreamAccess::AnyHolder));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.routes.count(), 0);
    }

    /// A backend at the link-local metadata address is refused under
    /// public-only network rules. No stream route or creation event is stored.
    #[test]
    fn a_private_backend_is_refused() {
        let f = fixture();

        let result = run(&f, tcp_to("169.254.169.254"));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.routes.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann's operator allows `10.0.0.0/8`. Her port onto a database there is
    /// opened.
    #[test]
    fn a_private_backend_inside_an_allowed_network_is_opened() {
        let f = fixture_with(|ports| CreatePorts {
            upstream_networks: UpstreamNetworks::parse_list("10.0.0.0/8").unwrap(),
            ..ports
        });

        let result = run(&f, tcp_to("10.0.0.5"));

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(f.routes.count(), 1);
    }

    /// Acme's plan holds no more stream routes. Ann's new port is refused and
    /// nothing is saved.
    #[test]
    fn a_port_past_the_plan_limit_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports
        });

        let result = run(&f, tcp_to("db.example.com"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.routes.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann asks for a client certificate on a port the proxy only passes
    /// through. It could never check one, so it is refused and nothing is
    /// saved.
    #[test]
    fn a_policy_the_protocol_cannot_honour_is_refused() {
        let f = fixture();

        let result = run(
            &f,
            request(
                "db.example.com",
                StreamProtocol::TlsPassthrough,
                StreamPolicy::MutualTls,
            ),
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.routes.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann opens a port another tenant already listens on. It is refused as
    /// taken.
    #[test]
    fn a_claimed_port_is_a_conflict() {
        let f = fixture();
        let elsewhere = ScopedTenant::for_test(TenantId::new());
        block_on(f.routes.save(&elsewhere, &stream_route_on(15432))).unwrap();

        let result = run(&f, tcp_to("db.example.com"));

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
    }

    /// Creating a stream route without tenant rights is forbidden, saving no
    /// route and recording no creation event.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports
        });

        let result = run(&f, tcp_to("db.example.com"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.routes.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot create a stream route and leaves the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(|ports| CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports
        });

        let result = run(&f, tcp_to("db.example.com"));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.routes.count(), 0);
    }
}
