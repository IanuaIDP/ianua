//! Connectors linking to a real listener over TLS and HTTP/2 on the
//! loopback interface, and requests carried down their links to a backend.
//!
//! Each test plays the connector itself: a TLS client with the certificate
//! the connector authority signed, serving HTTP/2 on the link and answering
//! every `CONNECT` by piping to a backend it was given.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ianua_app::ports::routing::{ConnectorAuthority, ConnectorIssue};
use ianua_app::test_support::routing::{
    FakeConnectorSightings, awaiting_connector, connector_code_hash, service_named,
    unpinned_upstream,
};
use ianua_domain::domains::proxy::pipeline::UpgradeRule;
use ianua_domain::domains::proxy::request::body::ByteCap;
use ianua_domain::domains::routing::connector::tunnel::{ConnectorTunnel, ConnectorTunnelRow};
use ianua_domain::domains::routing::connector::{ConnectorStatus, PrivateConnector};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{
    CertificatePem, CertificateRequestPem, ConnectorId, CorrelationId, Expiry, PublicKeyPin,
    ServiceId, TenantId,
};
use ianua_infra::cache::{CacheBackendHealthReports, MemoryState};
use ianua_infra::crypto::{
    ConnectorPki, ConnectorPkiValidity, RcgenConnectorAuthority, issue_connector_pki,
};
use ianua_infra::dns::DnsBackendDiscovery;
use rcgen::{CertificateParams, KeyPair};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::forward::{
    ClientKeys, Clients, DiscoverySettings, DiscoveryWatch, ForwardError, ForwardSettings,
    ForwardTarget, Forwarder, HealthChecks, ProbeSettings, RequestBody, ResponseInspection,
    ResponseSpan, ServicePool, ServicePools, TunnelLimits, UpgradeTerms,
};
use crate::listen::ListenerPem;
use crate::observability::TunnelCloseRecord;

/// What the wiki backend answers.
const WIKI: &str = "the wiki's front page";

/// Room for a handful of links, and short timeouts.
fn limits() -> LinkLimits {
    LinkLimits {
        max_links: 8,
        links_per_connector: 4,
        streams_per_link: 8,
        handshake: Duration::from_secs(2),
        open: Duration::from_secs(2),
        keepalive: Duration::from_secs(5),
        sighting: Duration::from_secs(60),
    }
}

/// A connector authority and the listener's certificate under it.
fn authority() -> (ConnectorPki, RcgenConnectorAuthority) {
    let pki =
        issue_connector_pki(&["localhost".to_owned()], ConnectorPkiValidity::default()).unwrap();
    let signer = RcgenConnectorAuthority::new(
        &CertificatePem::new(pki.authority.certificate_pem.clone()).unwrap(),
        &pki.authority.private_key_pem,
    )
    .unwrap();
    (pki, signer)
}

/// A connector's agent: its key, the certificate signed for it, and what
/// the tenant holds of it.
struct Agent {
    tenant: TenantId,
    connector: ConnectorId,
    key: KeyPair,
    certificate_pem: String,
    tunnel: ConnectorTunnel,
    pinned: PublicKeyPin,
}

impl Agent {
    /// What the tenant holds of this connector, with `status`.
    fn tunnel_with(&self, status: ConnectorStatus) -> ConnectorTunnel {
        tunnel(self.connector, &self.tunnel, self.pinned, status)
    }
}

/// A tunnel for `connector` with `scope_of`'s scope, `key` and `status`.
fn tunnel(
    connector: ConnectorId,
    scope_of: &ConnectorTunnel,
    key: PublicKeyPin,
    status: ConnectorStatus,
) -> ConnectorTunnel {
    ConnectorTunnel::reconstitute(ConnectorTunnelRow {
        id: connector,
        scope: scope_of.scope().clone(),
        key,
        status,
    })
    .unwrap()
}

/// An agent of a connector of `tenant` allowed to dial
/// `wiki.corp.internal`, enrolled with a fresh key and signed by `signer`
/// as a connector of `named_tenant`.
async fn agent_named(
    signer: &RcgenConnectorAuthority,
    tenant: TenantId,
    named_tenant: TenantId,
) -> Agent {
    let key = KeyPair::generate().unwrap();
    let request = certificate_request(&key);
    let pin = signer.key_of(&request).unwrap();
    let mut connector = awaiting_connector("wiki", "wiki-code", &["wiki.corp.internal"]);
    let certificate = connector
        .enroll(&connector_code_hash("wiki-code"), pin)
        .unwrap();
    let issued = signer
        .issue(ConnectorIssue {
            tenant: named_tenant,
            connector: *connector.id(),
            request: &request,
            certificate: &certificate,
        })
        .await
        .unwrap();
    Agent {
        tenant,
        connector: *connector.id(),
        key,
        certificate_pem: issued.certificate_pem,
        tunnel: enrolled_tunnel(&connector, pin),
        pinned: pin,
    }
}

/// The active tunnel snapshot installed after this fixture's connector enrolls.
fn enrolled_tunnel(
    connector: &PrivateConnector<ResolvedTenant>,
    key: PublicKeyPin,
) -> ConnectorTunnel {
    ConnectorTunnel::reconstitute(ConnectorTunnelRow {
        id: *connector.id(),
        scope: connector.scope().clone(),
        key,
        status: ConnectorStatus::Active,
    })
    .unwrap()
}

/// A signing request proving possession of the connector's generated key.
fn certificate_request(key: &KeyPair) -> CertificateRequestPem {
    CertificateRequestPem::new(
        CertificateParams::default()
            .serialize_request(key)
            .unwrap()
            .pem()
            .unwrap(),
    )
    .unwrap()
}

/// An agent of a connector of a fresh tenant, its certificate naming that
/// tenant.
async fn agent(signer: &RcgenConnectorAuthority) -> Agent {
    let tenant = TenantId::new();
    agent_named(signer, tenant, tenant).await
}

/// The gateway side: the listener and the links it keeps.
struct Gateway {
    address: SocketAddr,
    links: Arc<ConnectorLinks>,
    sightings: Arc<FakeConnectorSightings>,
    stop: CancellationToken,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// A listener under `pki`, held to `limits`.
async fn gateway_with(pki: &ConnectorPki, limits: LinkLimits) -> Gateway {
    let tls = listener_tls(pki);
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let links = Arc::new(ConnectorLinks::new(limits));
    let sightings = Arc::new(FakeConnectorSightings::default());
    let stop = CancellationToken::new();
    let listener = ConnectorListener::new(ConnectorListenerParts {
        socket,
        tls,
        links: Arc::clone(&links),
        sightings: sightings.clone(),
        limits,
    });
    tokio::spawn(listener.run(stop.clone()));
    Gateway {
        address,
        links,
        sightings,
        stop,
    }
}

/// The listener identity and trust anchors issued by the fixture's connector authority.
fn listener_tls(pki: &ConnectorPki) -> Arc<tokio_rustls::rustls::ServerConfig> {
    let provider = Arc::new(ring::default_provider());
    server_config(
        &provider,
        &ListenerPem {
            authority: pki.authority.certificate_pem.clone(),
            chain: pki.listener.certificate_pem.clone(),
            key: pki.listener.private_key_pem.clone(),
        },
    )
    .unwrap()
}

async fn gateway(pki: &ConnectorPki) -> Gateway {
    gateway_with(pki, limits()).await
}

/// Every certificate in `pem`.
fn certificates(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// TLS for a connector trusting `authority_pem` for the listener and
/// presenting `agent`'s certificate, or none.
fn connector_tls(authority_pem: &str, agent: Option<&Agent>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for anchor in certificates(authority_pem) {
        roots.add(anchor).unwrap();
    }
    let builder = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let mut config = match agent {
        Some(agent) => builder
            .with_client_auth_cert(
                certificates(&agent.certificate_pem),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(agent.key.serialize_der())),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// What the test connector saw: how many `CONNECT`s it was sent.
#[derive(Default)]
struct Seen {
    connects: AtomicUsize,
}

/// Links to `gateway` with `tls`, serving every `CONNECT` by piping to
/// `backend`. None when the handshake fails on the connector's side.
async fn link(
    gateway: SocketAddr,
    tls: Arc<ClientConfig>,
    backend: SocketAddr,
    seen: Arc<Seen>,
) -> Option<JoinHandle<()>> {
    let tcp = TcpStream::connect(gateway).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let stream = TlsConnector::from(tls).connect(name, tcp).await.ok()?;
    Some(tokio::spawn(async move {
        let service = service_fn(move |request: Request<Incoming>| {
            seen.connects.fetch_add(1, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(piped(request, backend)) }
        });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }))
}

/// Answers a `CONNECT` with `200` and pipes the stream to `backend`.
fn piped(request: Request<Incoming>, backend: SocketAddr) -> Response<Empty<Bytes>> {
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(request).await else {
            return;
        };
        let Ok(mut tcp) = TcpStream::connect(backend).await else {
            return;
        };
        let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut tcp).await;
    });
    Response::new(Empty::new())
}

/// An HTTP/1 backend answering every request with [`WIKI`].
async fn wiki() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_: Request<Incoming>| async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                        WIKI.as_bytes(),
                    ))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service)
                    .await;
            });
        }
    });
    address
}

/// A backend that takes connections and never answers.
async fn silent() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
        }
    });
    address
}

/// Whether `holds` turns true within two seconds.
async fn eventually(holds: impl Fn() -> bool) -> bool {
    for _ in 0..100 {
        if holds() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    holds()
}

/// Whether `task` ends within two seconds.
async fn ends(task: JoinHandle<()>) -> bool {
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .is_ok()
}

/// Links `agent` to `gateway` and waits for the link to be held.
async fn linked(
    gateway: &Gateway,
    pki: &ConnectorPki,
    agent: &Agent,
    backend: SocketAddr,
) -> (JoinHandle<()>, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let task = link(
        gateway.address,
        connector_tls(&pki.authority.certificate_pem, Some(agent)),
        backend,
        Arc::clone(&seen),
    )
    .await
    .unwrap();
    let links = Arc::clone(&gateway.links);
    let (tenant, connector) = (agent.tenant, agent.connector);
    assert!(eventually(|| links.live(tenant, connector) == 1).await);
    (task, seen)
}

/// Asserts the connection `tls` makes for `agent` is closed and never
/// becomes a link.
async fn assert_refused(gateway: &Gateway, tls: Arc<ClientConfig>, agent: &Agent) {
    let task = link(
        gateway.address,
        tls,
        wiki().await,
        Arc::new(Seen::default()),
    )
    .await;
    if let Some(task) = task {
        assert!(ends(task).await, "the refused connection stays open");
    }
    assert_eq!(gateway.links.live(agent.tenant, agent.connector), 0);
    assert!(gateway.sightings.noted().is_empty());
}

/// Forwarding settings for the pools.
fn forward_settings() -> ForwardSettings {
    ForwardSettings {
        networks: UpstreamNetworks::public_only(),
        connect_timeout: Duration::from_secs(2),
        response_deadline: Duration::from_secs(10),
        long_lived_idle: Duration::from_secs(10),
        pool_idle_timeout: Duration::from_secs(30),
        pool_max_idle_per_backend: 4,
        tunnels: TunnelLimits {
            max_open: NonZeroUsize::MIN,
            lifetime: Duration::from_secs(10),
            idle: Duration::from_secs(10),
            recheck_every: Duration::from_secs(10),
            recheck_timeout: Duration::from_secs(1),
        },
    }
}

/// Pools reaching connectors through `links`.
fn pools(links: &Arc<ConnectorLinks>) -> ServicePools {
    ServicePools::new(
        Clients::new(&forward_settings(), Arc::clone(links)).unwrap(),
        HealthChecks::new(
            CancellationToken::new(),
            ProbeSettings {
                max_in_flight: NonZeroUsize::MIN,
            },
            Arc::new(CacheBackendHealthReports::new(Arc::new(MemoryState::new(
                100,
            )))),
        ),
        Arc::new(DiscoveryWatch::new(
            Arc::new(DnsBackendDiscovery::new(Duration::from_secs(1))),
            DiscoverySettings {
                tick: Duration::from_secs(1),
                lookup_timeout: Duration::from_secs(1),
                max_in_flight: NonZeroUsize::MIN,
            },
        )),
    )
}

/// Sends a `GET /` to `url`, a service of `agent`'s tenant reached through
/// its connector, through `links`.
async fn forwarded(
    links: &Arc<ConnectorLinks>,
    agent: &Agent,
    url: &str,
) -> Result<Response<crate::forward::ResponseBody>, ForwardError> {
    let pools = pools(links);
    let service = service_named(
        "wiki",
        unpinned_upstream(url).through_connector(agent.connector),
    );
    let id: ServiceId = *service.id();
    pools.reconcile_tenant(agent.tenant, &[service], &ClientKeys::none());
    let pool = pools.pool(agent.tenant, &id).unwrap();
    let request: Request<RequestBody> = Request::get("/")
        .body(
            Empty::<Bytes>::new()
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
        .unwrap();
    Forwarder::new(&forward_settings())
        .forward(request, wiki_target(pool))
        .await
}

/// A streamed wiki request with the same body and upgrade bounds on every link.
fn wiki_target(pool: Arc<ServicePool>) -> ForwardTarget {
    ForwardTarget {
        pool,
        path: "/".to_owned(),
        body_limit: ByteCap::new(1_024).unwrap(),
        client_host: None,
        affinity: None,
        inspection: ResponseInspection::Streamed,
        span: ResponseSpan::Bounded,
        upgrade: UpgradeTerms {
            rule: UpgradeRule::Allowed,
            expiry: Expiry::Never,
            authority: None,
            correlation_id: CorrelationId::new(),
            closing: TunnelCloseRecord::unobserved(),
        },
    }
}

/// Acme's connector links with the certificate the authority signed for
/// it. A request for its wiki goes down the link, the connector dials the
/// wiki from inside, and the wiki's answer comes back. The link is noted
/// seen.
#[tokio::test]
async fn carries_requests_and_responses_through_connectors() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let agent = agent(&signer).await;
    gateway
        .links
        .install(agent.tenant, vec![agent.tunnel.clone()]);
    let backend = wiki().await;
    let (_task, seen) = linked(&gateway, &pki, &agent, backend).await;

    let answered = forwarded(&gateway.links, &agent, "http://wiki.corp.internal:8080")
        .await
        .unwrap();

    assert_eq!(answered.status(), StatusCode::OK);
    let body = answered.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, WIKI.as_bytes());
    assert!(seen.connects.load(Ordering::SeqCst) >= 1);
    let sightings = Arc::clone(&gateway.sightings);
    assert!(eventually(|| !sightings.noted().is_empty()).await);
}

/// A connection without a client certificate is refused, leaving no live
/// connector link or recorded sighting.
#[tokio::test]
async fn connections_without_certificates_are_refused() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let agent = agent(&signer).await;
    gateway
        .links
        .install(agent.tenant, vec![agent.tunnel.clone()]);

    assert_refused(
        &gateway,
        connector_tls(&pki.authority.certificate_pem, None),
        &agent,
    )
    .await;
}

/// A connector certificate signed by a foreign authority is refused even
/// when its connector is installed, leaving no link or sighting.
#[tokio::test]
async fn foreign_certificate_authorities_are_refused() {
    let (pki, signer) = authority();
    let (_, hers) = authority();
    let gateway = gateway(&pki).await;
    let acme = agent(&signer).await;
    let forged = agent_named(&hers, acme.tenant, acme.tenant).await;
    gateway.links.install(
        acme.tenant,
        vec![
            acme.tunnel.clone(),
            forged.tunnel_with(ConnectorStatus::Active),
        ],
    );

    assert_refused(
        &gateway,
        connector_tls(&pki.authority.certificate_pem, Some(&forged)),
        &forged,
    )
    .await;
}

/// A connector installed as revoked cannot open a link with its issued
/// certificate, and no sighting is recorded.
#[tokio::test]
async fn a_revoked_connectors_link_is_refused() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let agent = agent(&signer).await;
    gateway.links.install(
        agent.tenant,
        vec![agent.tunnel_with(ConnectorStatus::Revoked)],
    );

    assert_refused(
        &gateway,
        connector_tls(&pki.authority.certificate_pem, Some(&agent)),
        &agent,
    )
    .await;
}

/// A certificate naming another tenant cannot open a link to the connector
/// installed under Acme, and no sighting is recorded.
#[tokio::test]
async fn another_tenants_connector_is_refused() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let acme = TenantId::new();
    let bobs = agent_named(&signer, acme, TenantId::new()).await;
    gateway.links.install(acme, vec![bobs.tunnel.clone()]);

    let task = link(
        gateway.address,
        connector_tls(&pki.authority.certificate_pem, Some(&bobs)),
        wiki().await,
        Arc::new(Seen::default()),
    )
    .await;

    if let Some(task) = task {
        assert!(ends(task).await);
    }
    assert_eq!(gateway.links.live(acme, bobs.connector), 0);
    assert!(gateway.sightings.noted().is_empty());
}

/// An issued certificate for a connector absent from the gateway's table
/// opens no link and records no sighting.
#[tokio::test]
async fn an_unknown_connector_is_refused() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let agent = agent(&signer).await;

    assert_refused(
        &gateway,
        connector_tls(&pki.authority.certificate_pem, Some(&agent)),
        &agent,
    )
    .await;
}

/// A certificate whose key differs from the connector's installed pin is
/// refused, leaving no live link or sighting.
#[tokio::test]
async fn certificates_for_other_keys_are_refused() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let agent = agent(&signer).await;
    gateway.links.install(
        agent.tenant,
        vec![tunnel(
            agent.connector,
            &agent.tunnel,
            PublicKeyPin::from_digest([9; 32]),
            ConnectorStatus::Active,
        )],
    );

    assert_refused(
        &gateway,
        connector_tls(&pki.authority.certificate_pem, Some(&agent)),
        &agent,
    )
    .await;
}

/// Ann revokes the connector while its link is open. When the tenant's
/// connectors are read again, the link is closed at once.
#[tokio::test]
async fn a_revocation_closes_a_live_link() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let agent = agent(&signer).await;
    gateway
        .links
        .install(agent.tenant, vec![agent.tunnel.clone()]);
    let (task, _) = linked(&gateway, &pki, &agent, wiki().await).await;

    gateway.links.install(
        agent.tenant,
        vec![agent.tunnel_with(ConnectorStatus::Revoked)],
    );

    assert_eq!(gateway.links.live(agent.tenant, agent.connector), 0);
    assert!(ends(task).await, "the revoked connector's link stays open");
}

/// The tenant stops being served. Every link it holds closes.
#[tokio::test]
async fn a_withdrawn_tenant_loses_its_links() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let agent = agent(&signer).await;
    gateway
        .links
        .install(agent.tenant, vec![agent.tunnel.clone()]);
    let (task, _) = linked(&gateway, &pki, &agent, wiki().await).await;

    gateway.links.withdraw(&agent.tenant);

    assert_eq!(gateway.links.live(agent.tenant, agent.connector), 0);
    assert!(ends(task).await);
}

/// The connector's server loses power while a request waits on the wiki.
/// The request is answered `502`, and the link is removed at once.
#[tokio::test]
async fn answers_bad_gateway_after_link_drops() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let agent = agent(&signer).await;
    gateway
        .links
        .install(agent.tenant, vec![agent.tunnel.clone()]);
    let (task, seen) = linked(&gateway, &pki, &agent, silent().await).await;
    let links = Arc::clone(&gateway.links);
    let (tenant, connector) = (agent.tenant, agent.connector);
    let waiting =
        tokio::spawn(
            async move { forwarded(&links, &agent, "http://wiki.corp.internal:8080").await },
        );
    assert!(eventually(|| seen.connects.load(Ordering::SeqCst) >= 1).await);

    task.abort();

    let answered = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    let refused = answered.expect_err("the request fails");
    assert_eq!(refused.status(), StatusCode::BAD_GATEWAY);
    let links = Arc::clone(&gateway.links);
    assert!(eventually(|| links.live(tenant, connector) == 0).await);
}

/// The connector is enrolled but holds no link to this gateway. A request
/// for its wiki is answered `503`, never dialled from the gateway itself.
#[tokio::test]
async fn offline_connectors_answer_unavailable() {
    let (_, signer) = authority();
    let agent = agent(&signer).await;
    let links = Arc::new(ConnectorLinks::new(limits()));
    links.install(agent.tenant, vec![agent.tunnel.clone()]);

    let refused = forwarded(&links, &agent, "http://wiki.corp.internal:8080")
        .await
        .expect_err("the request is refused");

    assert!(matches!(refused, ForwardError::ConnectorOffline));
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// A request for a backend outside the linked connector's scope returns
/// an address refusal without sending the connector a CONNECT request.
#[tokio::test]
async fn backends_outside_connector_scope_are_unreachable() {
    let (pki, signer) = authority();
    let gateway = gateway(&pki).await;
    let agent = agent(&signer).await;
    gateway
        .links
        .install(agent.tenant, vec![agent.tunnel.clone()]);
    let (_task, seen) = linked(&gateway, &pki, &agent, wiki().await).await;

    let refused = forwarded(&gateway.links, &agent, "http://vault.example.com:8080")
        .await
        .expect_err("the request is refused");

    assert!(matches!(refused, ForwardError::AddressRefused));
    assert_eq!(seen.connects.load(Ordering::SeqCst), 0);
}

/// With one link allowed per connector, a second connection closes while
/// the connector retains one live link.
#[tokio::test]
async fn excess_connector_links_are_refused() {
    let (pki, signer) = authority();
    let gateway = gateway_with(
        &pki,
        LinkLimits {
            links_per_connector: 1,
            ..limits()
        },
    )
    .await;
    let agent = agent(&signer).await;
    gateway
        .links
        .install(agent.tenant, vec![agent.tunnel.clone()]);
    let (_first, _) = linked(&gateway, &pki, &agent, wiki().await).await;

    let second = link(
        gateway.address,
        connector_tls(&pki.authority.certificate_pem, Some(&agent)),
        wiki().await,
        Arc::new(Seen::default()),
    )
    .await
    .unwrap();

    assert!(ends(second).await);
    assert_eq!(gateway.links.live(agent.tenant, agent.connector), 1);
}

/// When another connector occupies the gateway's only link slot, a second
/// connector cannot establish a live link.
#[tokio::test]
async fn excess_gateway_links_are_refused() {
    let (pki, signer) = authority();
    let gateway = gateway_with(
        &pki,
        LinkLimits {
            max_links: 1,
            ..limits()
        },
    )
    .await;
    let first = agent(&signer).await;
    let second = agent(&signer).await;
    gateway
        .links
        .install(first.tenant, vec![first.tunnel.clone()]);
    gateway
        .links
        .install(second.tenant, vec![second.tunnel.clone()]);
    let (_held, _) = linked(&gateway, &pki, &first, wiki().await).await;

    let refused = link(
        gateway.address,
        connector_tls(&pki.authority.certificate_pem, Some(&second)),
        wiki().await,
        Arc::new(Seen::default()),
    )
    .await;

    if let Some(task) = refused {
        assert!(ends(task).await);
    }
    assert_eq!(gateway.links.live(second.tenant, second.connector), 0);
}
