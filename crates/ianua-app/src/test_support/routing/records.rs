//! Routing records a test starts from, made through the domain the way a
//! routing admin makes them: services, routes, stream routes, egress
//! policies, and the verified domains routes answer on.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::{HostHeader, Upstream, UpstreamTimeout};
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::egress::{
    CreateEgressPolicyParams, EgressDestination, EgressPolicy, ServiceIdentity,
};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::{CreateRouteParams, Route, RoutePipeline};
use ianua_domain::domains::routing::service::{CreateServiceParams, Service};
use ianua_domain::domains::routing::stream::access::StreamAccess;
use ianua_domain::domains::routing::stream::{
    CreateStreamRouteParams, ListenPort, StreamBackend, StreamPolicy, StreamProtocol, StreamRoute,
    StreamTimeouts,
};
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    DomainConnection, DomainProof, DomainVerificationToken, RegisteredDomain, RegisteredDomainRow,
};
use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::test_support::authority::anyone_holding;
use ianua_domain::types::{Audience, DomainId, DomainName, HttpUrl, Label, ServiceId, UrlPath};

use crate::ports::domain::RegisteredDomainStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::block_on;
use crate::test_support::domain::FakeDomainStore;

/// Someone who manages routing and pipelines, so every change a test makes
/// to set up its records is allowed.
#[must_use]
pub fn routing_admin() -> RoutingControl<'static> {
    RoutingControl::new(anyone_holding(&[
        SystemPermission::ManageRouting,
        SystemPermission::Pipeline(PipelineAction::Manage),
    ]))
}

/// A label the test spells out.
///
/// # Panics
///
/// Panics if `value` is not a valid label.
#[must_use]
pub fn routing_label(value: &str) -> Label {
    Label::new("name", value).expect("the test label is valid")
}

/// An upstream at `url` that pins no audience.
///
/// # Panics
///
/// Panics if `url` is not a valid URL.
#[must_use]
pub fn unpinned_upstream(url: &str) -> Upstream {
    Upstream::new(
        HttpUrl::new(url).expect("the test URL is valid"),
        UpstreamTimeout::DEFAULT,
        HostHeader::Rewrite,
    )
}

/// An upstream at `url` that pins the audience `audience`.
///
/// # Panics
///
/// Panics if `url` or `audience` is not valid.
#[must_use]
pub fn pinned_upstream(url: &str, audience: &str) -> Upstream {
    unpinned_upstream(url).with_audience(Audience::new(audience).expect("the audience is valid"))
}

/// An active service named `name` forwarding to `upstream`.
///
/// # Panics
///
/// Panics if the domain refuses the service, which it never does here.
#[must_use]
pub fn service_named(name: &str, upstream: Upstream) -> Service<ResolvedTenant> {
    Service::create(
        CreateServiceParams {
            id: ServiceId::new(),
            name: routing_label(name),
            upstream,
            health_check: HealthCheckPolicy::default(),
        },
        &routing_admin(),
    )
    .expect("a routing admin creates a service")
}

/// What a test route looks like: its name, path and policy.
pub struct RouteShape<'a> {
    /// The route's name.
    pub name: &'a str,
    /// The path pattern it matches.
    pub path: &'a str,
    /// What a caller must prove.
    pub policy: RoutePolicy,
    /// The domains it answers on.
    pub hosts: RouteHosts,
}

impl<'a> RouteShape<'a> {
    /// A route named `name` on `path`, open to anyone on every host.
    #[must_use]
    pub fn public(name: &'a str, path: &'a str) -> Self {
        Self {
            name,
            path,
            policy: RoutePolicy::Public,
            hosts: RouteHosts::Any,
        }
    }

    /// A route named `name` on `path`, for signed-in callers on every host.
    #[must_use]
    pub fn signed_in(name: &'a str, path: &'a str) -> Self {
        Self {
            policy: RoutePolicy::Authenticated,
            ..Self::public(name, path)
        }
    }
}

/// An active route of `shape`, forwarding to `service` through `pipeline`.
///
/// # Panics
///
/// Panics if the domain refuses the route, such as a signed-in route on a
/// service that pins no audience.
#[must_use]
pub fn route_of(
    shape: RouteShape<'_>,
    service: &Service<ResolvedTenant>,
    pipeline: &impl RoutePipeline,
) -> Route<ResolvedTenant> {
    Route::create(
        CreateRouteParams {
            name: routing_label(shape.name),
            path_pattern: UrlPath::new(shape.path).expect("the test path is valid"),
            methods: Vec::new(),
            policy: shape.policy,
            hosts: shape.hosts,
            path_rewrite: PathRewrite::Keep,
            priority: 100,
        },
        service,
        pipeline,
        &routing_admin(),
    )
    .expect("a routing admin creates the route")
}

/// The same route, disabled, as it must be before it is deleted.
///
/// # Panics
///
/// Panics if the route is already disabled.
#[must_use]
pub fn disabled(mut route: Route<ResolvedTenant>) -> Route<ResolvedTenant> {
    route
        .disable(&routing_admin())
        .expect("an active route is disabled");
    route
}

/// An open TCP stream route named `postgres-<port>` on `port`, to one
/// public database. Names are unique in a tenant, so each port gets its own.
///
/// # Panics
///
/// Panics if `port` is not one a stream route may listen on.
#[must_use]
pub fn stream_route_on(port: u16) -> StreamRoute<ResolvedTenant> {
    StreamRoute::create(
        CreateStreamRouteParams {
            name: routing_label(&format!("postgres-{port}")),
            protocol: StreamProtocol::Tcp,
            listen_port: ListenPort::new(port).expect("the test port is valid"),
            sni: RouteHosts::Any,
            policy: StreamPolicy::Public,
            access: StreamAccess::AnyHolder,
            backends: vec![StreamBackend::new("db.example.com", 5432, 1).expect("valid backend")],
            timeouts: StreamTimeouts::default(),
        },
        &routing_admin(),
    )
    .expect("a routing admin opens the port")
}

/// An open signed-in tunnel on `port` to one public database, letting in
/// whoever `access` names.
///
/// # Panics
///
/// Panics if `port` is not one a stream route may listen on, or `access`
/// lets in anyone, which a tunnel refuses.
#[must_use]
pub fn tunnel_on(port: u16, access: StreamAccess) -> StreamRoute<ResolvedTenant> {
    StreamRoute::create(
        CreateStreamRouteParams {
            name: routing_label("postgres-tunnel"),
            protocol: StreamProtocol::Tcp,
            listen_port: ListenPort::new(port).expect("the test port is valid"),
            sni: RouteHosts::Any,
            policy: StreamPolicy::Tunnel,
            access,
            backends: vec![StreamBackend::new("db.example.com", 5432, 1).expect("valid backend")],
            timeouts: StreamTimeouts::default(),
        },
        &routing_admin(),
    )
    .expect("a routing admin opens the tunnel")
}

/// An open port on `port` that ends TLS for the names `sni` allows and
/// asks for a client certificate, letting in whoever `access` names.
///
/// # Panics
///
/// Panics if `port` is not one a stream route may listen on, or `access`
/// names people, whom a certificate never names.
#[must_use]
pub fn certificate_port_on(
    port: u16,
    sni: RouteHosts,
    access: StreamAccess,
) -> StreamRoute<ResolvedTenant> {
    StreamRoute::create(
        CreateStreamRouteParams {
            name: routing_label(&format!("mtls-{port}")),
            protocol: StreamProtocol::TlsTerminate,
            listen_port: ListenPort::new(port).expect("the test port is valid"),
            sni,
            policy: StreamPolicy::MutualTls,
            access,
            backends: vec![StreamBackend::new("db.example.com", 5432, 1).expect("valid backend")],
            timeouts: StreamTimeouts::default(),
        },
        &routing_admin(),
    )
    .expect("a routing admin opens the port")
}

/// A policy letting the service `service` reach `api.github.com` on 443
/// with internal data.
///
/// # Panics
///
/// Panics if `service` is not a service identity.
#[must_use]
pub fn egress_policy_for(service: &str) -> EgressPolicy<ResolvedTenant> {
    EgressPolicy::create(
        CreateEgressPolicyParams {
            name: routing_label("fetcher"),
            service: ServiceIdentity::new(service).expect("the test identity is valid"),
            destinations: vec![github()],
            max_data_class: DataClassLevel::Internal,
        },
        &routing_admin(),
    )
    .expect("a routing admin creates the policy")
}

/// `api.github.com` on 443.
///
/// # Panics
///
/// Never: the name and port are valid.
#[must_use]
pub fn github() -> EgressDestination {
    EgressDestination::new(DomainName::new("api.github.com").expect("valid name"), 443)
        .expect("a public destination")
}

/// A domain store holding `names`, each registered by `tenant` and verified.
///
/// # Panics
///
/// Panics if a name is not a valid domain.
#[must_use]
pub fn verified_domains(tenant: &ScopedTenant, names: &[&str]) -> Arc<FakeDomainStore> {
    let store = Arc::new(FakeDomainStore::empty());
    for name in names {
        let proof = DomainProof::Verified { at: clock::now() };
        block_on(store.save(tenant, &registered(name, proof))).expect("the fake keeps the domain");
    }
    store
}

/// A domain store holding `name`, registered by `tenant` and not yet proved.
///
/// # Panics
///
/// Panics if `name` is not a valid domain.
#[must_use]
pub fn unproved_domain(tenant: &ScopedTenant, name: &str) -> Arc<FakeDomainStore> {
    let store = Arc::new(FakeDomainStore::empty());
    block_on(store.save(tenant, &registered(name, DomainProof::Unproved)))
        .expect("the fake keeps the domain");
    store
}

fn registered(name: &str, proof: DomainProof) -> RegisteredDomain<ResolvedTenant> {
    RegisteredDomain::reconstitute(RegisteredDomainRow {
        id: DomainId::new(),
        domain: DomainName::new(name).expect("the test domain is valid"),
        connection: DomainConnection::SelfManaged,
        proof,
        dns_challenge_token: DomainVerificationToken::new("token").expect("valid token"),
        tls_status: TlsStatus::NotRequired,
        created_at: proof.verified_at().unwrap_or_else(clock::now),
    })
    .expect("a self-managed domain row holds")
}
