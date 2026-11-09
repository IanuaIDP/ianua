//! The egress gateway's loop over the app's fakes: services connecting in
//! the clear on a free port, a resolver that answers every name with the
//! test's own destination, and destinations that remember what reached
//! them.

use std::convert::Infallible;
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use hyper::service::service_fn;
use ianua_app::ports::routing::{CrossTenantEgressPolicies, EgressPolicyStore as _};
use ianua_app::tenancy::ScopedTenant;
use ianua_app::test_support::agents::FakeExposureGate;
use ianua_app::test_support::crypto::FakeAssertionVerifier;
use ianua_app::test_support::routing::{
    FailingEgressPolicies, FakeEgressPolicyStore, routing_admin,
};
use ianua_app::test_support::{FakeEventDispatcher, block_on};
use ianua_app::use_cases::routing::egress::DecidePorts;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::assertion::AssertedCaller;
use ianua_domain::domains::routing::egress::{
    CreateEgressPolicyParams, EgressDestination, EgressPolicy,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{
    AgentId, CidrRange, DelegationId, DomainName, Label, PrincipalRef, TenantId, UserId,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::*;
use crate::listen::{Served, serve};

const FETCHER: &str = "spiffe://ianua.test/ns/svc/sa/fetcher";

/// A resolver answering every name with the loopback address.
struct Loopback;

impl Resolve for Loopback {
    async fn addresses(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
    }
}

/// A destination echoing what it is sent, counting the connections it
/// took.
async fn echoing() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let taken = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&taken);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    (port, taken)
}

/// A plain HTTP destination remembering the headers and path of each
/// request.
async fn answering() -> (u16, Arc<Mutex<Vec<(String, HeaderMap)>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&heard);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let kept = Arc::clone(&kept);
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let kept = Arc::clone(&kept);
                    async move {
                        kept.lock()
                            .unwrap()
                            .push((request.uri().to_string(), request.headers().clone()));
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"fetched",
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (port, heard)
}

/// Acme's policy for the fetcher, listing `api.github.com` on `port` and
/// letting out data up to `class`.
fn policy(port: u16, class: DataClassLevel) -> EgressPolicy<ResolvedTenant> {
    EgressPolicy::create(
        CreateEgressPolicyParams {
            name: Label::new("name", "fetcher").unwrap(),
            service: ServiceIdentity::new(FETCHER).unwrap(),
            destinations: vec![
                EgressDestination::new(DomainName::new("api.github.com").unwrap(), port).unwrap(),
            ],
            max_data_class: class,
        },
        &routing_admin(),
    )
    .unwrap()
}

/// The egress gateway for one tenant, Acme, serving services in the clear
/// on a free port, and what it records.
struct Bench {
    address: SocketAddr,
    tenant: ScopedTenant,
    assertions: Arc<FakeAssertionVerifier>,
    sink: Arc<FakeEventDispatcher>,
}

impl Bench {
    /// Acme's policy for the fetcher on `port`, letting out data up to
    /// `class`, with loopback destinations permitted.
    async fn new(port: u16, class: DataClassLevel) -> Self {
        let store = Arc::new(FakeEgressPolicyStore::default());
        let tenant = ScopedTenant::for_test(TenantId::new());
        block_on(store.save(&tenant, &policy(port, class))).unwrap();
        Self::over(store, tenant, loopback()).await
    }

    /// The egress gateway deciding through `policies`, for `tenant`'s
    /// assertions, reaching what `networks` permits.
    async fn over(
        policies: Arc<dyn CrossTenantEgressPolicies>,
        tenant: ScopedTenant,
        networks: UpstreamNetworks,
    ) -> Self {
        let assertions = Arc::new(FakeAssertionVerifier::default());
        let sink = Arc::new(FakeEventDispatcher::new());
        let decision = Decision {
            use_case: DecideUseCase::new(DecidePorts {
                policies,
                assertions: assertions.clone(),
                exposure: Arc::new(FakeExposureGate::default()),
            }),
            auditor: RequestAuditor::system(sink.clone()),
        };
        let address = serve_fetcher(Arc::new(gateway(decision, networks))).await;
        Self {
            address,
            tenant,
            assertions,
            sink,
        }
    }

    /// Sends `head` as the fetcher, and reads the answer's head back.
    async fn send(&self, head: &str) -> (TcpStream, String) {
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        let mut byte = [0_u8; 1];
        while !answer.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            answer.push(byte[0]);
        }
        (stream, String::from_utf8_lossy(&answer).into_owned())
    }

    /// An assertion of Acme's naming an agent.
    fn assertion(&self) -> Secret {
        self.assertions.issue(
            *self.tenant,
            AssertedCaller::Agent {
                agent_id: AgentId::new(),
                acting_for: PrincipalRef::User(UserId::new()),
                delegation_id: DelegationId::new(),
            },
        )
    }
}

/// Builds a gateway whose resolver sends permitted destinations to loopback.
fn gateway(decision: Decision, networks: UpstreamNetworks) -> Egress<Loopback> {
    let reach = Reach {
        resolver: Loopback,
        networks,
        timeout: Duration::from_secs(5),
    };
    let limits = WayOutLimits {
        decision: Duration::from_secs(5),
        request: Duration::from_secs(5),
        idle: Duration::from_secs(5),
        tunnels: 8,
    };
    Egress::new(
        decision,
        reach,
        limits,
        Shutdown::new(Duration::from_secs(1)),
    )
}

/// Accepts test connections as the fetcher without performing a TLS handshake.
async fn serve_fetcher(egress: Arc<Egress<Loopback>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            let who = Served {
                service: ServiceIdentity::new(FETCHER).unwrap(),
                peer,
                header: Duration::from_secs(5),
            };
            tokio::spawn(serve(stream, who, Arc::clone(&egress)));
        }
    });
    address
}

/// The loopback block, standing in for the internal networks an operator
/// lists.
fn loopback() -> UpstreamNetworks {
    UpstreamNetworks::new(vec![CidrRange::new("127.0.0.0/8").unwrap()])
}

/// The fetcher tunnels to `api.github.com`, which Acme's policy lists,
/// and its bytes cross both ways.
#[tokio::test]
async fn a_listed_destination_is_tunnelled() {
    let (port, _) = echoing().await;
    let bench = Bench::new(port, DataClassLevel::Restricted).await;

    let (mut tunnel, head) = bench
        .send(&format!(
            "CONNECT api.github.com:{port} HTTP/1.1\r\nHost: api.github.com:{port}\r\n\r\n"
        ))
        .await;
    tunnel.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    tunnel.read_exact(&mut echoed).await.unwrap();

    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(&echoed, b"ping");
}

/// An unlisted destination receives no connection and the fetcher gets a
/// forbidden response.
#[tokio::test]
async fn an_unlisted_destination_is_refused() {
    let (port, taken) = echoing().await;
    let bench = Bench::new(port, DataClassLevel::Restricted).await;

    let (_, head) = bench
        .send(&format!(
            "CONNECT evil.example.com:{port} HTTP/1.1\r\nHost: evil.example.com\r\n\r\n"
        ))
        .await;

    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(taken.load(Ordering::SeqCst), 0);
}

/// A service without an egress policy receives a forbidden response and
/// never connects to its destination.
#[tokio::test]
async fn services_without_policies_reach_nothing() {
    let (port, taken) = echoing().await;
    let bench = Bench::over(
        Arc::new(FakeEgressPolicyStore::default()),
        ScopedTenant::for_test(TenantId::new()),
        loopback(),
    )
    .await;

    let (_, head) = bench
        .send(&format!(
            "CONNECT api.github.com:{port} HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        ))
        .await;

    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(taken.load(Ordering::SeqCst), 0);
}

/// A numeric IP target is refused as a bad request before policy routing.
#[tokio::test]
async fn address_targets_are_refused() {
    let bench = Bench::new(443, DataClassLevel::Restricted).await;

    let (_, head) = bench
        .send("CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")
        .await;

    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
}

/// Forwarding strips the agent assertion and proxy credential while
/// preserving the origin-form path, host and Accept header.
#[tokio::test]
async fn the_assertion_never_reaches_the_destination() {
    let (port, heard) = answering().await;
    let bench = Bench::new(port, DataClassLevel::Restricted).await;
    let assertion = bench.assertion();

    let (_, head) = bench
        .send(&format!(
            "GET http://api.github.com:{port}/a?b=1 HTTP/1.1\r\nHost: api.github.com:{port}\r\nX-Ianua-Assertion: {}\r\nProxy-Authorization: Basic eA==\r\nAccept: */*\r\n\r\n",
            assertion.expose()
        ))
        .await;

    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let heard = heard.lock().unwrap();
    let (path, headers) = &heard[0];
    assert_eq!(path, "/a?b=1");
    assert!(!headers.contains_key(ASSERTION_HEADER));
    assert!(!headers.contains_key("proxy-authorization"));
    assert_eq!(headers["host"], format!("api.github.com:{port}"));
    assert_eq!(headers["accept"], "*/*");
}

/// An unattributed call under an internal-data policy is forbidden without
/// connecting or recording an agent denial.
#[tokio::test]
async fn lower_clearance_requires_an_attributed_call() {
    let (port, taken) = echoing().await;
    let bench = Bench::new(port, DataClassLevel::Internal).await;

    let (_, head) = bench
        .send(&format!(
            "CONNECT api.github.com:{port} HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        ))
        .await;

    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(taken.load(Ordering::SeqCst), 0);
    assert!(bench.sink.records.lock().unwrap().is_empty());
}

/// An attributed request to an unlisted host is forbidden and records one
/// agent egress-denied event.
#[tokio::test]
async fn refusals_are_attributed_to_the_agent() {
    let (port, _) = echoing().await;
    let bench = Bench::new(port, DataClassLevel::Restricted).await;
    let assertion = bench.assertion();

    let (_, head) = bench
        .send(&format!(
            "CONNECT evil.example.com:{port} HTTP/1.1\r\nHost: evil.example.com\r\nX-Ianua-Assertion: {}\r\n\r\n",
            assertion.expose()
        ))
        .await;

    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(
        bench.sink.records.lock().unwrap().as_slice(),
        ["agents.egress_denied"]
    );
}

/// A listed host resolving to loopback produces a gateway error under
/// public-only network rules, without connecting to the destination.
#[tokio::test]
async fn an_internal_address_is_never_dialled() {
    let (port, taken) = echoing().await;
    let store = Arc::new(FakeEgressPolicyStore::default());
    let tenant = ScopedTenant::for_test(TenantId::new());
    block_on(store.save(&tenant, &policy(port, DataClassLevel::Restricted))).unwrap();
    let bench = Bench::over(store, tenant, UpstreamNetworks::public_only()).await;

    let (_, head) = bench
        .send(&format!(
            "CONNECT api.github.com:{port} HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        ))
        .await;

    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(taken.load(Ordering::SeqCst), 0);
}

/// An unavailable policy store produces an unavailable response without
/// opening a destination connection.
#[tokio::test]
async fn an_unreachable_policy_store_refuses() {
    let (port, taken) = echoing().await;
    let bench = Bench::over(
        Arc::new(FailingEgressPolicies),
        ScopedTenant::for_test(TenantId::new()),
        loopback(),
    )
    .await;

    let (_, head) = bench
        .send(&format!(
            "CONNECT api.github.com:{port} HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        ))
        .await;

    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert_eq!(taken.load(Ordering::SeqCst), 0);
}
