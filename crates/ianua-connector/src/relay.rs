//! What the connector does with each request the gateway sends down a
//! link: a `CONNECT host:port` for a target the allow list names is dialled
//! and its bytes carried both ways; anything else is refused and nothing
//! is dialled.
//!
//! - Not a `CONNECT`: `405`.
//! - A `CONNECT` naming no host and port: `400`.
//! - A target the list does not name: `403`.
//! - Every relay the connector may hold is in use: `503`.
//! - The target did not answer in time: `504`; it refused or failed: `502`.
//! - Reached: `200`, and the stream carries the target's bytes.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use ianua_boot::shutdown::Shutdown;
use ianua_boot::tunnel::splice;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::dial::{DialError, Dialer, Resolve};
use crate::targets::Target;

/// How often a link is pinged, and how long a ping may go unanswered
/// before the link is taken for dead.
const KEEPALIVE: Duration = Duration::from_secs(20);

/// The answer to every request: a status, no body.
pub type Answer = Response<Empty<Bytes>>;

/// The relays of every link: what may be dialled and how much may be held
/// open at once.
pub struct Relay<R> {
    dialer: Dialer<R>,
    idle: Duration,
    room: Arc<Semaphore>,
    shutdown: Shutdown,
}

impl<R: Resolve> Relay<R> {
    /// Relays dialling through `dialer`, each ended after `idle` with
    /// nothing moving, at most `most` open at once across every link, each
    /// waited for by `shutdown`.
    #[must_use]
    pub(crate) fn new(dialer: Dialer<R>, idle: Duration, most: usize, shutdown: Shutdown) -> Self {
        Self {
            dialer,
            idle,
            room: Arc::new(Semaphore::new(most.min(Semaphore::MAX_PERMITS))),
            shutdown,
        }
    }

    /// The answer to `request`, a relay started behind it when it is a
    /// `CONNECT` to a listed target that answered.
    pub async fn answer(&self, mut request: Request<Incoming>) -> Answer {
        if request.method() != Method::CONNECT {
            return status(StatusCode::METHOD_NOT_ALLOWED);
        }
        let Some(target) = target_of(&request) else {
            return status(StatusCode::BAD_REQUEST);
        };
        if !self.dialer.targets.permits(&target) {
            tracing::info!(%target, "refused a target the allow list does not name");
            return status(StatusCode::FORBIDDEN);
        }
        let Ok(held) = Arc::clone(&self.room).try_acquire_owned() else {
            tracing::warn!(%target, "refused a target: every relay is in use");
            return status(StatusCode::SERVICE_UNAVAILABLE);
        };
        let stream = match self.dialer.dial(&target).await {
            Ok(stream) => stream,
            Err(error) => return refused_dial(&target, &error),
        };
        let upgrade = hyper::upgrade::on(&mut request);
        let idle = self.idle;
        self.shutdown.spawn_until_stopped(async move {
            let Ok(upgraded) = upgrade.await else {
                return;
            };
            relay_bytes(TokioIo::new(upgraded), stream, idle, target).await;
            drop(held);
        });
        status(StatusCode::OK)
    }
}

/// Serves the gateway's requests on the link `io` through `relay`, at most
/// `streams` at once, until the link ends.
///
/// # Errors
///
/// The link's HTTP/2 error when it ends badly.
pub async fn serve<I, R>(io: I, relay: Arc<Relay<R>>, streams: u32) -> Result<(), hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: Resolve,
{
    let service = service_fn(move |request| {
        let relay = Arc::clone(&relay);
        async move { Ok::<_, Infallible>(relay.answer(request).await) }
    });
    http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .max_concurrent_streams(streams)
        .keep_alive_interval(Some(KEEPALIVE))
        .keep_alive_timeout(KEEPALIVE)
        .serve_connection(TokioIo::new(io), service)
        .await
}

/// Carries one relay's bytes until it ends.
async fn relay_bytes<G>(mut gateway: G, mut stream: TcpStream, idle: Duration, target: Target)
where
    G: AsyncRead + AsyncWrite + Unpin,
{
    let ended = splice(&mut gateway, &mut stream, idle).await;
    tracing::debug!(%target, ended = ended.as_str(), "a relay ended");
}

/// The target a `CONNECT` names: an authority alone, no scheme or path.
fn target_of(request: &Request<Incoming>) -> Option<Target> {
    let uri = request.uri();
    let bare = uri.scheme().is_none() && uri.path_and_query().is_none_or(|path| path == "/");
    if !bare {
        return None;
    }
    Target::parse(uri.authority()?.as_str()).ok()
}

/// The answer to a dial that failed.
fn refused_dial(target: &Target, error: &DialError) -> Answer {
    tracing::info!(%target, %error, "a listed target could not be reached");
    match error {
        DialError::TimedOut => status(StatusCode::GATEWAY_TIMEOUT),
        DialError::NoAddress | DialError::Failed(_) => status(StatusCode::BAD_GATEWAY),
    }
}

fn status(code: StatusCode) -> Answer {
    let mut answer = Response::new(Empty::new());
    *answer.status_mut() = code;
    answer
}

#[cfg(test)]
mod tests {
    use hyper::client::conn::http2 as client;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;
    use crate::dial::SystemResolver;
    use crate::targets::AllowList;

    /// A link to a relay allowing `entries`, as the gateway holds it.
    async fn link(entries: &[&str]) -> client::SendRequest<Empty<Bytes>> {
        let dialer = Dialer {
            resolver: SystemResolver,
            targets: AllowList::parse(entries.iter().copied()).unwrap(),
            timeout: Duration::from_secs(2),
        };
        let shutdown = Shutdown::new(Duration::from_secs(1));
        let relay = Arc::new(Relay::new(dialer, Duration::from_secs(5), 16, shutdown));
        let (gateway_end, connector_end) = tokio::io::duplex(64 * 1024);
        tokio::spawn(serve(connector_end, relay, 16));
        let (sender, connection) =
            client::handshake(TokioExecutor::new(), TokioIo::new(gateway_end))
                .await
                .unwrap();
        tokio::spawn(connection);
        sender
    }

    async fn ask(
        sender: &mut client::SendRequest<Empty<Bytes>>,
        method: Method,
        uri: &str,
    ) -> Response<Incoming> {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Empty::new())
            .unwrap();
        sender.send_request(request).await.unwrap()
    }

    /// The gateway asks for Acme's listed wiki. The connector answers 200
    /// and the wiki's bytes come back up the link.
    #[tokio::test]
    async fn a_listed_target_is_relayed() {
        let wiki = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = wiki.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut socket, _) = wiki.accept().await.unwrap();
            let mut heard = [0_u8; 4];
            socket.read_exact(&mut heard).await.unwrap();
            socket.write_all(b"pong").await.unwrap();
        });
        let mut sender = link(&[address.as_str()]).await;

        let answer = ask(&mut sender, Method::CONNECT, &address).await;
        assert_eq!(answer.status(), StatusCode::OK);
        let mut tunnel = TokioIo::new(hyper::upgrade::on(answer).await.unwrap());
        tunnel.write_all(b"ping").await.unwrap();
        let mut heard = [0_u8; 4];
        tunnel.read_exact(&mut heard).await.unwrap();

        assert_eq!(&heard, b"pong");
    }

    /// An unlisted local target is forbidden and receives no connection
    /// during the observation window.
    #[tokio::test]
    async fn an_unlisted_target_is_refused_and_never_dialled() {
        let domain_controller = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = domain_controller.local_addr().unwrap().to_string();
        let mut sender = link(&["wiki.corp.internal:443"]).await;

        let answer = ask(&mut sender, Method::CONNECT, &address).await;
        let dialled =
            tokio::time::timeout(Duration::from_millis(100), domain_controller.accept()).await;

        assert_eq!(answer.status(), StatusCode::FORBIDDEN);
        assert!(dialled.is_err());
    }

    /// A GET sent down the connector link is refused as an unsupported method.
    #[tokio::test]
    async fn a_request_other_than_connect_is_refused() {
        let mut sender = link(&["wiki.corp.internal:443"]).await;

        let answer = ask(&mut sender, Method::GET, "http://wiki.corp.internal/").await;

        assert_eq!(answer.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// A listed target that refuses the connection is answered 502.
    #[tokio::test]
    async fn a_target_that_refuses_is_answered_bad_gateway() {
        let gone = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = gone.local_addr().unwrap().to_string();
        drop(gone);
        let mut sender = link(&[address.as_str()]).await;

        let answer = ask(&mut sender, Method::CONNECT, &address).await;

        assert_eq!(answer.status(), StatusCode::BAD_GATEWAY);
    }
}
