//! The runner's loop over the app's fakes, with a destination of its own
//! that remembers what it heard.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Mutex;

use http::Method;
use http_body_util::Empty;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use ianua_app::test_support::agents::{FakeRunnerKeys, FakeRunnerProofs, FakeRunnerTokens};
use ianua_app::use_cases::agents::runner::{CredentialPorts, ForgetPorts};
use ianua_domain::domains::agents::runner::GatewayTransport;
use ianua_domain::types::DomainName;
use tokio::net::TcpListener;

use super::*;
use crate::outbound::{Trust, outbound};

/// One request a destination heard.
#[derive(Debug, Clone)]
struct HeardRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
}

impl HeardRequest {
    /// The request line and headers of `request`.
    fn of(request: &Request<Incoming>) -> Self {
        Self {
            method: request.method().clone(),
            uri: request.uri().clone(),
            headers: request.headers().clone(),
        }
    }
}

/// What a destination answers every request with.
#[derive(Debug, Clone)]
struct Answer {
    status: StatusCode,
    headers: Vec<(&'static str, &'static str)>,
    delay: Duration,
}

impl Answer {
    /// `200 OK` at once, with `headers`.
    fn ok(headers: Vec<(&'static str, &'static str)>) -> Self {
        Self {
            status: StatusCode::OK,
            headers,
            delay: Duration::ZERO,
        }
    }

    /// Records the received request before returning the configured delayed response.
    async fn respond(
        &self,
        request: HeardRequest,
        heard: &Mutex<Vec<HeardRequest>>,
    ) -> Response<Full<Bytes>> {
        heard.lock().unwrap().push(request);
        tokio::time::sleep(self.delay).await;
        let mut response = Response::new(Full::new(Bytes::from_static(b"done")));
        *response.status_mut() = self.status;
        for &(name, value) in &self.headers {
            response
                .headers_mut()
                .insert(name, HeaderValue::from_static(value));
        }
        response
    }
}

/// A destination on a free port answering with `answer`, and what it
/// heard.
async fn destination(answer: Answer) -> (SocketAddr, Arc<Mutex<Vec<HeardRequest>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&heard);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let kept = Arc::clone(&kept);
            let answer = answer.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let kept = Arc::clone(&kept);
                    let answer = answer.clone();
                    async move {
                        let response = answer.respond(HeardRequest::of(&request), &kept).await;
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, heard)
}

/// A runner for Acme's agent, its requests going to the destination at
/// `address`, and the fakes it holds tokens and proofs with.
struct Bench {
    runner: Runner,
    tokens: Arc<FakeRunnerTokens>,
}

impl Bench {
    fn new(address: SocketAddr, keys: FakeRunnerKeys, limits: RequestLimits) -> Self {
        let tokens = Arc::new(FakeRunnerTokens::default());
        let gateway = GatewayAddress::new(
            DomainName::new("api.acme.test").unwrap(),
            GatewayTransport::Plain,
        );
        let use_cases = use_cases(keys, tokens.clone(), gateway.clone());
        let destinations = Destinations {
            gateway_url: Url::parse(&format!("http://{address}")).unwrap(),
            gateway,
            agents_url: Url::parse(&format!("http://{address}/agents")).unwrap(),
        };
        Self {
            runner: Runner::new(
                use_cases,
                Outbounds {
                    gateway: outbound(Duration::from_secs(5), &Trust::Public).unwrap(),
                    platform: outbound(Duration::from_secs(5), &Trust::Public).unwrap(),
                },
                destinations,
                limits,
            ),
            tokens,
        }
    }

    async fn at(answer: Answer) -> (Self, Arc<Mutex<Vec<HeardRequest>>>) {
        let (address, heard) = destination(answer).await;
        (
            Self::new(address, FakeRunnerKeys::holding(), limits()),
            heard,
        )
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Response<RunnerBody> {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        self.runner
            .handle(request.body(Empty::<Bytes>::new()).unwrap())
            .await
    }
}

/// Uses one token fake for both credential exchange and refused-token removal.
fn use_cases(
    keys: FakeRunnerKeys,
    tokens: Arc<FakeRunnerTokens>,
    gateway: GatewayAddress,
) -> RunnerUseCases {
    RunnerUseCases {
        credential: CredentialUseCase::new(
            CredentialPorts {
                keys: Arc::new(keys),
                tokens: tokens.clone(),
                proofs: Arc::new(FakeRunnerProofs::default()),
            },
            gateway,
        ),
        forget: ForgetUseCase::new(ForgetPorts { tokens }),
    }
}

fn limits() -> RequestLimits {
    RequestLimits {
        timeout: Duration::from_secs(5),
        in_flight: 8,
    }
}

/// Ann's agent reads `/reports?month=1`. It reaches the gateway as the
/// tenant's host with the runner's bound token and a proof for this
/// request, keeping only its descriptive headers: the token it found, its
/// cookie and the identity it claims stay behind.
#[tokio::test]
async fn requests_use_only_the_runners_credential() {
    let (bench, heard) = Bench::at(Answer::ok(Vec::new())).await;

    let answer = bench
        .send(
            "GET",
            "/reports?month=1",
            &[
                ("authorization", "Bearer stolen"),
                ("cookie", "session=abc"),
                ("x-forwarded-user", "admin"),
                ("dpop", "forged"),
                ("content-type", "application/json"),
            ],
        )
        .await;

    assert_eq!(answer.status(), StatusCode::OK);
    let heard = heard.lock().unwrap();
    let request = &heard[0];
    assert_eq!(request.uri.to_string(), "/reports?month=1");
    assert_eq!(
        request.headers["authorization"],
        "Bearer token-proof_of_possession"
    );
    assert_eq!(request.headers["dpop"], "GET http://api.acme.test/reports");
    assert_eq!(request.headers["host"], "api.acme.test");
    assert_eq!(request.headers["content-type"], "application/json");
    assert!(!request.headers.contains_key("cookie"));
    assert!(!request.headers.contains_key("x-forwarded-user"));
}

/// A gateway response loses its session cookie before reaching the agent,
/// while its content type remains intact.
#[tokio::test]
async fn the_agent_is_handed_no_session() {
    let (bench, _) = Bench::at(Answer::ok(vec![
        ("set-cookie", "session=s"),
        ("content-type", "text/plain"),
    ]))
    .await;

    let answer = bench.send("GET", "/reports", &[]).await;

    assert!(!answer.headers().contains_key("set-cookie"));
    assert_eq!(answer.headers()["content-type"], "text/plain");
}

/// A message to `orders.created` goes to the relay with the bearer token
/// and its query, and no proof.
#[tokio::test]
async fn relays_messages_with_a_bearer_token() {
    let (bench, heard) = Bench::at(Answer::ok(Vec::new())).await;

    let answer = bench
        .send("POST", "/_ianua/messages/orders.created?wait=5", &[])
        .await;

    assert_eq!(answer.status(), StatusCode::OK);
    let heard = heard.lock().unwrap();
    assert_eq!(
        heard[0].uri.to_string(),
        "/agents/messages/orders.created?wait=5"
    );
    assert_eq!(heard[0].method, Method::POST);
    assert_eq!(heard[0].headers["authorization"], "Bearer token-bearer");
    assert!(!heard[0].headers.contains_key("dpop"));
}

/// A topic containing encoded path traversal is refused as a bad request
/// without contacting the destination.
#[tokio::test]
async fn refuses_malformed_topic_names() {
    let (bench, heard) = Bench::at(Answer::ok(Vec::new())).await;

    let answer = bench
        .send("POST", "/_ianua/messages/..%2F..%2Fsignup", &[])
        .await;

    assert_eq!(answer.status(), StatusCode::BAD_REQUEST);
    assert!(heard.lock().unwrap().is_empty());
}

/// TRACE is refused as an unsupported method without contacting the destination.
#[tokio::test]
async fn an_unknown_method_is_refused() {
    let (bench, heard) = Bench::at(Answer::ok(Vec::new())).await;

    let answer = bench.send("TRACE", "/reports", &[]).await;

    assert_eq!(answer.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(heard.lock().unwrap().is_empty());
}

/// When the runner cannot obtain its key, the request fails with a gateway
/// error and never forwards the agent's supplied credential.
#[tokio::test]
async fn no_key_means_nothing_leaves() {
    let (address, heard) = destination(Answer::ok(Vec::new())).await;
    let bench = Bench::new(address, FakeRunnerKeys::refusing(), limits());

    let answer = bench
        .send("GET", "/reports", &[("authorization", "Bearer stolen")])
        .await;

    assert_eq!(answer.status(), StatusCode::BAD_GATEWAY);
    assert!(heard.lock().unwrap().is_empty());
}

/// The gateway refuses the token after Ann revoked the delegation behind
/// it. The next request exchanges a new one instead of sending the
/// refused one again.
#[tokio::test]
async fn a_refused_token_is_exchanged_again() {
    let (bench, _) = Bench::at(Answer {
        status: StatusCode::UNAUTHORIZED,
        headers: Vec::new(),
        delay: Duration::ZERO,
    })
    .await;

    bench.send("GET", "/reports", &[]).await;
    bench.send("GET", "/reports", &[]).await;

    assert_eq!(bench.tokens.exchanges(), 2);
}

/// A destination that exceeds the request deadline produces a gateway timeout.
#[tokio::test]
async fn times_out_hung_destinations() {
    let (address, _) = destination(Answer {
        status: StatusCode::OK,
        headers: Vec::new(),
        delay: Duration::from_secs(10),
    })
    .await;
    let bench = Bench::new(
        address,
        FakeRunnerKeys::holding(),
        RequestLimits {
            timeout: Duration::from_millis(200),
            in_flight: 8,
        },
    );

    let answer = bench.send("GET", "/reports", &[]).await;

    assert_eq!(answer.status(), StatusCode::GATEWAY_TIMEOUT);
}

/// With no available request slots, the runner answers unavailable
/// without contacting the destination.
#[tokio::test]
async fn excess_requests_are_answered_busy() {
    let (address, heard) = destination(Answer::ok(Vec::new())).await;
    let bench = Bench::new(
        address,
        FakeRunnerKeys::holding(),
        RequestLimits {
            timeout: Duration::from_secs(5),
            in_flight: 0,
        },
    );

    let answer = bench.send("GET", "/reports", &[]).await;

    assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(heard.lock().unwrap().is_empty());
}
