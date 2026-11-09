//! The forwarder against real backends on the loopback interface: what a
//! request meets on its way out, and what holds the answer on its way back.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::stream;
use http::{Request, Response, StatusCode, header};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use ianua_domain::domains::proxy::pipeline::{UpgradeRefusal, UpgradeRule};
use ianua_domain::domains::proxy::request::body::ByteCap;
use ianua_domain::domains::routing::backend::circuit_breaker::{BreakerSettings, CircuitBreaker};
use ianua_domain::domains::routing::backend::health_check::{
    ActiveHealthCheck, ActiveHealthCheckParams, HealthCheckPolicy,
};
use ianua_domain::domains::routing::backend::upstream::{HostHeader, Upstream, UpstreamTimeout};
use ianua_domain::types::{CorrelationId, Expiry, HttpUrl, Seconds, UrlPath};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use self::support::{backend, pool_with, settings};
use super::body::ResponseBody;
use super::client::{BoxError, RequestBody, empty_body};
use super::error::ForwardError;
use super::health::{Tally, probe_round};
use super::pool::ServicePool;
use super::settings::ForwardSettings;
use super::target::{ForwardTarget, ResponseInspection, ResponseSpan};
use super::upgrade::UpgradeTerms;
use super::{BodyError, Forwarder};
use crate::observability::TunnelCloseRecord;

/// What every test needs to build pools and settings.
pub(super) mod support {
    use std::num::{NonZeroU32, NonZeroUsize};
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use ianua_app::ports::routing::BackendDiscovery;
    use ianua_domain::domains::routing::backend::discovery::{DiscoveredBackends, Discovery};
    use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
    use ianua_domain::domains::routing::backend::upstream::{
        HostHeader, Upstream, UpstreamTimeout, WeightedBackend,
    };
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::security::ssrf::UpstreamNetworks;
    use ianua_domain::types::{HttpUrl, ServiceId, TenantId};

    use super::super::client::Clients;
    use super::super::pool::ServicePool;
    use super::super::registry::ServiceSpec;
    use super::super::settings::{DiscoverySettings, ForwardSettings, ProbeSettings, TunnelLimits};
    use crate::connectors::{ConnectorLinks, LinkLimits};

    /// Settings reaching the loopback interface and one private network.
    pub(in crate::forward) fn settings() -> ForwardSettings {
        ForwardSettings {
            networks: UpstreamNetworks::parse_list("127.0.0.0/8, 10.0.0.0/8").unwrap(),
            connect_timeout: Duration::from_secs(2),
            response_deadline: Duration::from_secs(10),
            long_lived_idle: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(30),
            pool_max_idle_per_backend: 8,
            tunnels: TunnelLimits {
                max_open: NonZeroUsize::new(4).unwrap(),
                lifetime: Duration::from_secs(60),
                idle: Duration::from_secs(5),
                recheck_every: Duration::from_secs(1),
                recheck_timeout: Duration::from_secs(1),
            },
        }
    }

    pub(in crate::forward) fn clients() -> Clients {
        Clients::new(
            &settings(),
            Arc::new(ConnectorLinks::new(LinkLimits {
                max_links: 4,
                links_per_connector: 2,
                streams_per_link: 4,
                handshake: Duration::from_secs(1),
                open: Duration::from_secs(1),
                keepalive: Duration::from_secs(5),
                sighting: Duration::from_secs(60),
            })),
        )
        .unwrap()
    }

    pub(in crate::forward) fn probe_settings() -> ProbeSettings {
        ProbeSettings {
            max_in_flight: NonZeroUsize::new(4).unwrap(),
        }
    }

    pub(in crate::forward) fn discovery_settings() -> DiscoverySettings {
        DiscoverySettings {
            tick: Duration::from_secs(1),
            lookup_timeout: Duration::from_secs(1),
            max_in_flight: NonZeroUsize::new(4).unwrap(),
        }
    }

    pub(in crate::forward) fn backend(url: &str, weight: u32) -> WeightedBackend {
        let weight = NonZeroU32::new(weight).unwrap();
        WeightedBackend::new(HttpUrl::new(url).unwrap(), weight)
    }

    /// An upstream spreading traffic evenly over `urls`.
    pub(in crate::forward) fn upstream_over(urls: &[&str]) -> Upstream {
        let backends = urls.iter().map(|url| backend(url, 1)).collect();
        let primary = HttpUrl::new(urls[0]).unwrap();
        Upstream::with_backends(
            primary,
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
            backends,
        )
    }

    pub(in crate::forward) fn pool_with(
        upstream: &Upstream,
        health: &HealthCheckPolicy,
    ) -> ServicePool {
        let clients = clients();
        let client = clients
            .for_upstream(TenantId::new(), upstream, None)
            .unwrap();
        let spec = ServiceSpec {
            id: ServiceId::new(),
            upstream,
            health,
        };
        ServicePool::new(&spec, client, clients.networks())
    }

    /// A resolver that is never reachable.
    pub(in crate::forward) struct NoResolver;

    #[async_trait]
    impl BackendDiscovery for NoResolver {
        async fn resolve(
            &self,
            _discovery: &Discovery,
            _configured: &HttpUrl,
        ) -> Result<DiscoveredBackends, DomainError> {
            Err(DomainError::infra_msg("resolver unreachable"))
        }
    }
}

type Answer = Response<BoxBody<Bytes, Infallible>>;

/// A backend on the loopback interface answering each request with
/// `answer`.
async fn serve<F>(answer: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Answer + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let answer = Arc::new(answer);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let answer = Arc::clone(&answer);
            let service = service_fn(move |request| {
                let answered = answer(request);
                async move { Ok::<_, Infallible>(answered) }
            });
            tokio::spawn(
                http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades(),
            );
        }
    });
    address
}

/// A backend that takes connections and never answers.
async fn hung() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    address
}

/// An address nothing listens on.
async fn closed() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// An answer whose length is declared.
fn text(body: impl Into<Bytes>) -> Answer {
    Response::new(Full::new(body.into()).boxed())
}

/// An answer whose length is not declared, sent in chunks.
fn chunked(body: &'static str) -> Answer {
    let frame = Frame::data(Bytes::from_static(body.as_bytes()));
    let frames = stream::iter([Ok::<_, Infallible>(frame)]);
    Response::new(StreamBody::new(frames).boxed())
}

fn url(address: SocketAddr) -> String {
    format!("http://{address}")
}

fn pool_over(
    addresses: &[SocketAddr],
    timeout_secs: u32,
    breaker: CircuitBreaker,
) -> Arc<ServicePool> {
    let urls: Vec<String> = addresses.iter().map(|address| url(*address)).collect();
    let backends = urls.iter().map(|url| backend(url, 1)).collect();
    let upstream = Upstream::with_backends(
        HttpUrl::new(&urls[0]).unwrap(),
        UpstreamTimeout::seconds(timeout_secs).unwrap(),
        HostHeader::Rewrite,
        backends,
    )
    .with_circuit_breaker(breaker);
    Arc::new(pool_with(&upstream, &HealthCheckPolicy::Disabled))
}

fn pool_at(address: SocketAddr) -> Arc<ServicePool> {
    pool_over(&[address], 30, CircuitBreaker::default())
}

fn target(
    pool: Arc<ServicePool>,
    inspection: ResponseInspection,
    rule: UpgradeRule,
) -> ForwardTarget {
    ForwardTarget {
        pool,
        path: "/orders".to_owned(),
        body_limit: ByteCap::new(BODY_LIMIT).unwrap(),
        client_host: None,
        affinity: None,
        inspection,
        span: ResponseSpan::Bounded,
        upgrade: UpgradeTerms {
            rule,
            expiry: Expiry::Never,
            authority: None,
            correlation_id: CorrelationId::new(),
            closing: TunnelCloseRecord::unobserved(),
        },
    }
}

fn streamed(pool: Arc<ServicePool>) -> ForwardTarget {
    target(pool, ResponseInspection::Streamed, UpgradeRule::Allowed)
}

/// The largest request body the test pipeline takes.
const BODY_LIMIT: u64 = 16;

/// A request as the client sent it: its path is the route's to rewrite,
/// its query travels on.
fn get() -> Request<RequestBody> {
    Request::get("/anything?page=2").body(empty_body()).unwrap()
}

/// A request carrying `body` in chunks, its length not declared.
fn post_streaming(body: &'static str) -> Request<RequestBody> {
    let frame = Frame::data(Bytes::from_static(body.as_bytes()));
    let frames = stream::iter([Ok::<_, BoxError>(frame)]);
    Request::post("/anything")
        .body(StreamBody::new(frames).boxed())
        .unwrap()
}

fn forwarder() -> Forwarder {
    Forwarder::new(&settings())
}

async fn read(response: Response<ResponseBody>) -> Result<Bytes, BodyError> {
    Ok(response.into_body().collect().await?.to_bytes())
}

#[tokio::test]
async fn backend_requests_and_responses_stream() {
    let address = serve(|request| {
        let seen = request.uri().path_and_query().map(ToString::to_string);
        text(seen.unwrap_or_default())
    })
    .await;

    let response = forwarder()
        .forward(get(), streamed(pool_at(address)))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(read(response).await.unwrap(), "/orders?page=2");
}

/// What a counting backend heard.
#[derive(Default)]
struct Heard {
    requests: AtomicUsize,
    bytes: AtomicUsize,
}

/// A backend that reads each request's whole body before it answers,
/// counting the requests and the body bytes it receives.
async fn counting() -> (SocketAddr, Arc<Heard>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let heard = Arc::new(Heard::default());
    let counted = Arc::clone(&heard);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let counted = Arc::clone(&counted);
            let service = service_fn(move |request: Request<Incoming>| {
                let counted = Arc::clone(&counted);
                async move {
                    counted.requests.fetch_add(1, Ordering::SeqCst);
                    let mut body = request.into_body();
                    while let Some(Ok(frame)) = body.frame().await {
                        let size = frame.data_ref().map_or(0, Bytes::len);
                        counted.bytes.fetch_add(size, Ordering::SeqCst);
                    }
                    Ok::<_, Infallible>(text("ok"))
                }
            });
            tokio::spawn(http1::Builder::new().serve_connection(TokioIo::new(stream), service));
        }
    });
    (address, heard)
}

#[tokio::test]
async fn refuses_declared_oversized_bodies_before_forwarding() {
    let (address, heard) = counting().await;
    let mut request = get();
    request
        .headers_mut()
        .insert(header::CONTENT_LENGTH, "1024".parse().unwrap());

    let refused = forwarder()
        .forward(request, streamed(pool_at(address)))
        .await;

    assert!(matches!(refused, Err(ForwardError::RequestTooLarge)));
    assert_eq!(refused.unwrap_err().status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(heard.requests.load(Ordering::SeqCst), 0);
}

/// A body that declares no length is held to the limit as it streams, and
/// the backend never receives the part past it.
#[tokio::test]
async fn stops_oversized_streaming_request_bodies() {
    let (address, heard) = counting().await;
    let request = post_streaming("far more than sixteen bytes of body");

    let refused = forwarder()
        .forward(request, streamed(pool_at(address)))
        .await;

    assert!(matches!(refused, Err(ForwardError::RequestTooLarge)));
    assert_eq!(heard.bytes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn forwards_bounded_request_bodies_whole() {
    let (address, heard) = counting().await;

    let answered = forwarder()
        .forward(post_streaming("short body"), streamed(pool_at(address)))
        .await;

    assert!(answered.is_ok());
    assert_eq!(heard.bytes.load(Ordering::SeqCst), "short body".len());
}

#[tokio::test]
async fn a_hung_backend_times_out() {
    let address = hung().await;
    let pool = pool_over(&[address], 1, CircuitBreaker::default());
    let started = Instant::now();

    let refused = forwarder().forward(get(), streamed(pool)).await;

    assert!(matches!(refused, Err(ForwardError::TimedOut)));
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// A backend that refuses every connection is set aside after its
/// failures in a row, and the requests after go to the one that works.
#[tokio::test]
async fn removes_broken_backends_from_rotation() {
    let broken = closed().await;
    let working = serve(|_| text("ok")).await;
    let breaker = CircuitBreaker::On(BreakerSettings::new(2, Seconds::new(60)).unwrap());
    let pool = pool_over(&[broken, working], 5, breaker);
    let forwarder = forwarder();

    let mut failures = 0;
    for _ in 0..6 {
        let answered = forwarder.forward(get(), streamed(Arc::clone(&pool))).await;
        failures += usize::from(answered.is_err());
    }
    let after: Vec<bool> = futures_util::future::join_all(
        (0..6).map(|_| forwarder.forward(get(), streamed(Arc::clone(&pool)))),
    )
    .await
    .iter()
    .map(Result::is_ok)
    .collect();

    assert_eq!(failures, 2);
    assert!(after.iter().all(|answered| *answered));
}

/// The probe marks a backend down once it fails, and up again once it
/// passes.
#[tokio::test]
async fn probe_results_control_backend_availability() {
    let healthy = Arc::new(AtomicBool::new(false));
    let answering = Arc::clone(&healthy);
    let address = serve(move |_| {
        let mut answer = text("");
        *answer.status_mut() = if answering.load(Ordering::SeqCst) {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        answer
    })
    .await;
    let pool = pool_at(address);
    let check = health_check();
    let probes = Semaphore::new(1);
    let mut tally = Tally::default();

    probe_round(&pool, &check, &probes, &mut tally).await;
    let after_failing = pool.members()[0].takes_traffic(Instant::now());
    healthy.store(true, Ordering::SeqCst);
    probe_round(&pool, &check, &probes, &mut tally).await;
    let after_passing = pool.members()[0].takes_traffic(Instant::now());

    assert!(!after_failing);
    assert!(after_passing);
}

/// The API's view of a service is what the gateway's probes hold: after a
/// round in which the only backend failed, the report says it is down.
#[tokio::test]
async fn probes_report_each_backends_health() {
    use ianua_app::ports::routing::{BackendHealthReader, BackendVerdict};
    use ianua_app::tenancy::ScopedTenant;
    use ianua_app::test_support::routing::FakeBackendHealth;
    use ianua_domain::types::{ServiceId, TenantId};

    use super::health::Reporter;

    let pool = pool_at(
        serve(|_| {
            let mut answer = text("");
            *answer.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            answer
        })
        .await,
    );
    let check = health_check();
    let board = Arc::new(FakeBackendHealth::default());
    let tenant = ScopedTenant::for_background(TenantId::new());
    let service_id = ServiceId::new();
    let reporter = Reporter {
        tenant,
        service_id,
        reports: Arc::clone(&board) as Arc<dyn ianua_app::ports::routing::BackendHealthReports>,
        valid_for: Duration::from_secs(30),
    };
    let mut tally = Tally::default();

    probe_round(&pool, &check, &Semaphore::new(1), &mut tally).await;
    reporter.report(&pool.members(), &tally).await;

    let report = board.latest(&tenant, &service_id).await.unwrap().unwrap();
    assert_eq!(report.backends.len(), 1);
    assert_eq!(report.backends[0].verdict, BackendVerdict::Down);
}

/// One successful or failed probe changes availability, without panic-mode fallback.
fn health_check() -> ActiveHealthCheck {
    ActiveHealthCheck::new(ActiveHealthCheckParams {
        path: UrlPath::new("/healthz").unwrap(),
        interval_secs: Seconds::new(10),
        timeout_secs: Seconds::new(2),
        healthy_threshold: 1,
        unhealthy_threshold: 1,
        panic_threshold_percent: 0,
    })
    .unwrap()
}

#[tokio::test]
async fn services_without_backends_are_refused() {
    let pool = pool_at(serve(|_| text("ok")).await);
    pool.replace_backends(Vec::new());

    let refused = forwarder().forward(get(), streamed(pool)).await;

    assert!(matches!(refused, Err(ForwardError::NoBackends)));
}

/// A WebSocket request under a response-inspection refusal returns an
/// upgrade error without sending any request to the backend.
#[tokio::test]
async fn forbidden_upgrades_never_reach_backends() {
    let heard = Arc::new(AtomicUsize::new(0));
    let counting = Arc::clone(&heard);
    let address = serve(move |_| {
        counting.fetch_add(1, Ordering::SeqCst);
        text("ok")
    })
    .await;
    let mut request = get();
    request
        .headers_mut()
        .insert(header::CONNECTION, "Upgrade".parse().unwrap());
    request
        .headers_mut()
        .insert(header::UPGRADE, "websocket".parse().unwrap());
    let rule = UpgradeRule::Refused(UpgradeRefusal::InspectsResponses);

    let refused = forwarder()
        .forward(
            request,
            target(pool_at(address), ResponseInspection::Streamed, rule),
        )
        .await;

    assert!(matches!(refused, Err(ForwardError::UpgradeRefused(_))));
    assert_eq!(heard.load(Ordering::SeqCst), 0);
}

fn inspected(pool: Arc<ServicePool>, bytes: u64) -> ForwardTarget {
    let cap = ResponseInspection::Inspected(ByteCap::new(bytes).unwrap());
    target(pool, cap, UpgradeRule::Allowed)
}

#[tokio::test]
async fn refuses_declared_oversized_responses() {
    let address = serve(|_| text("far more than ten bytes of answer")).await;

    let refused = forwarder()
        .forward(get(), inspected(pool_at(address), 10))
        .await;

    assert!(matches!(refused, Err(ForwardError::ResponseTooLarge)));
}

/// A body that declares no length is held to the limit as it streams.
#[tokio::test]
async fn stops_oversized_streaming_responses() {
    let address = serve(|_| chunked("far more than ten bytes of answer")).await;

    let response = forwarder()
        .forward(get(), inspected(pool_at(address), 10))
        .await
        .unwrap();

    assert!(matches!(read(response).await, Err(BodyError::TooLong)));
}

#[tokio::test]
async fn streams_bounded_responses_whole() {
    let address = serve(|_| chunked("short")).await;

    let response = forwarder()
        .forward(get(), inspected(pool_at(address), 10))
        .await
        .unwrap();

    assert_eq!(read(response).await.unwrap(), "short");
}

/// An answer typed `content_type` sending one event every `every`,
/// `frames` times, its length not declared.
fn trickling(content_type: &'static str, frames: usize, every: Duration) -> Answer {
    let events = stream::unfold(0, move |sent| async move {
        if sent == frames {
            return None;
        }
        tokio::time::sleep(every).await;
        let event = Frame::data(Bytes::from_static(b"data: tick\n\n"));
        Some((Ok::<_, Infallible>(event), sent + 1))
    });
    let mut answer = Response::new(StreamBody::new(events).boxed());
    answer.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    answer
}

/// A forwarder holding whole answers to `deadline` and long-lived ones to
/// `idle`.
fn forwarder_holding(deadline: Duration, idle: Duration) -> Forwarder {
    Forwarder::new(&ForwardSettings {
        response_deadline: deadline,
        long_lived_idle: idle,
        ..settings()
    })
}

/// A live feed of server-sent events runs past the response deadline. It
/// keeps sending, so it is not cut off.
#[tokio::test]
async fn active_event_streams_outlive_response_deadlines() {
    let every = Duration::from_millis(100);
    let address = serve(move |_| trickling("text/event-stream", 5, every)).await;
    let forwarder = forwarder_holding(Duration::from_millis(250), Duration::from_secs(2));

    let response = forwarder
        .forward(get(), streamed(pool_at(address)))
        .await
        .unwrap();

    assert_eq!(read(response).await.unwrap().len(), 5 * 12);
}

/// An event stream whose first event arrives after the idle limit fails
/// its body read with the went-quiet error.
#[tokio::test]
async fn silent_event_streams_are_stopped() {
    let silent = Duration::from_secs(5);
    let address = serve(move |_| trickling("text/event-stream", 1, silent)).await;
    let forwarder = forwarder_holding(Duration::from_secs(30), Duration::from_millis(200));

    let response = forwarder
        .forward(get(), streamed(pool_at(address)))
        .await
        .unwrap();

    assert!(matches!(read(response).await, Err(BodyError::WentQuiet)));
}

/// A JSON response sending chunks before the idle limit still fails its
/// body read when the overall response deadline expires.
#[tokio::test]
async fn ordinary_trickling_responses_obey_deadlines() {
    let every = Duration::from_millis(100);
    let address = serve(move |_| trickling("application/json", 10, every)).await;
    let forwarder = forwarder_holding(Duration::from_millis(250), Duration::from_secs(2));

    let response = forwarder
        .forward(get(), streamed(pool_at(address)))
        .await
        .unwrap();

    assert!(matches!(read(response).await, Err(BodyError::TimedOut)));
}

/// A chunked stream the route marks long-lived is held to its silences,
/// not to the deadline.
#[tokio::test]
async fn keeps_streams_open_beyond_response_deadlines() {
    let every = Duration::from_millis(100);
    let address = serve(move |_| trickling("application/x-ndjson", 5, every)).await;
    let forwarder = forwarder_holding(Duration::from_millis(250), Duration::from_secs(2));
    let mut marked = streamed(pool_at(address));
    marked.span = ResponseSpan::LongLived;

    let response = forwarder.forward(get(), marked).await.unwrap();

    assert_eq!(read(response).await.unwrap().len(), 5 * 12);
}

#[tokio::test]
async fn backend_connection_headers_never_reach_clients() {
    let address = serve(|_| {
        let mut answer = text("ok");
        answer
            .headers_mut()
            .insert("connection", "x-internal".parse().unwrap());
        answer
            .headers_mut()
            .insert("x-internal", "1".parse().unwrap());
        answer
    })
    .await;

    let response = forwarder()
        .forward(get(), streamed(pool_at(address)))
        .await
        .unwrap();

    assert!(response.headers().get("x-internal").is_none());
}

/// A backend that agrees to a switch, then echoes four bytes.
async fn echoing_after_a_switch() -> SocketAddr {
    serve(|request| {
        tokio::spawn(async move {
            let Ok(upgraded) = hyper::upgrade::on(request).await else {
                return;
            };
            let mut io = TokioIo::new(upgraded);
            let mut heard = [0_u8; 4];
            if io.read_exact(&mut heard).await.is_ok() {
                let _ = io.write_all(&heard).await;
            }
        });
        let mut answer = text("");
        *answer.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        answer
            .headers_mut()
            .insert(header::CONNECTION, "upgrade".parse().unwrap());
        answer
            .headers_mut()
            .insert(header::UPGRADE, "websocket".parse().unwrap());
        answer
    })
    .await
}

/// A gateway on the loopback interface forwarding every request to `pool`
/// under `rule`.
async fn gateway(pool: Arc<ServicePool>, rule: UpgradeRule) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let forwarder = Arc::new(forwarder());
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let forwarder = Arc::clone(&forwarder);
            let pool = Arc::clone(&pool);
            let service = service_fn(move |request: Request<Incoming>| {
                let forwarder = Arc::clone(&forwarder);
                let pool = Arc::clone(&pool);
                async move {
                    Ok::<_, Infallible>(forward_request(&forwarder, pool, rule, request).await)
                }
            });
            tokio::spawn(
                http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades(),
            );
        }
    });
    address
}

/// Forwards a fixture request, returning the forwarder's refusal status on failure.
async fn forward_request(
    forwarder: &Forwarder,
    pool: Arc<ServicePool>,
    rule: UpgradeRule,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let request = request.map(|body| body.map_err(BoxError::from).boxed());
    let target = target(pool, ResponseInspection::Streamed, rule);
    forwarder
        .forward(request, target)
        .await
        .unwrap_or_else(|error| {
            let mut refusal = Response::new(ResponseBody::empty());
            *refusal.status_mut() = error.status();
            refusal
        })
}

/// A WebSocket handshake as a client sends it.
const HANDSHAKE: &str = "GET /chat HTTP/1.1\r\n\
                         Host: shop.example\r\n\
                         Connection: Upgrade\r\n\
                         Upgrade: websocket\r\n\r\n";

/// Sends a WebSocket handshake to `address` and answers with the status
/// line and the open connection.
async fn switch_at(address: SocketAddr) -> (String, TcpStream) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(HANDSHAKE.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap();
    let status = head.lines().next().unwrap_or_default().to_owned();
    (status, stream)
}

/// A switch the rule allows becomes a tunnel to the backend.
#[tokio::test]
async fn tunnels_permitted_upgrades_to_backends() {
    let backend = echoing_after_a_switch().await;
    let gateway = gateway(pool_at(backend), UpgradeRule::Allowed).await;

    let (status, mut stream) = switch_at(gateway).await;
    stream.write_all(b"ping").await.unwrap();
    let mut heard = [0_u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut heard))
        .await
        .unwrap()
        .unwrap();

    assert!(status.starts_with("HTTP/1.1 101"), "{status}");
    assert_eq!(&heard, b"ping");
}

#[tokio::test]
async fn forbidden_upgrades_answer_forbidden() {
    let backend = echoing_after_a_switch().await;
    let rule = UpgradeRule::Refused(UpgradeRefusal::MeteredCaller);
    let gateway = gateway(pool_at(backend), rule).await;

    let (status, _) = switch_at(gateway).await;

    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
}
