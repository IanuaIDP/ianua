//! The stack's ingress, in front of the platform as a load balancer is in
//! production: it ends TLS for the stack's domain and every name under
//! it, and forwards each request to the API over plain HTTP, saying who
//! the client was and that it came over HTTPS.
//!
//! The `X-Forwarded-*` headers a client sent are taken off before the
//! ingress sets its own, so a client cannot claim another address. Every
//! scenario client arrives from loopback, so each names the address it
//! stands for in [`CLIENT_ADDRESS`], a header only the scenarios send: the
//! ingress forwards that address as `X-Forwarded-For`, as a load balancer
//! forwards the address a connection came from, and takes the header off,
//! so the platform never sees it. A request's body is read whole before it
//! is forwarded, up to [`BUFFERED_MOST`], as nginx does by default, so an
//! API that refuses a body early still has its answer delivered; the
//! answer's body streams through. Only the head of the API's answer is
//! waited for, and for a bounded time. A WebSocket handshake the API
//! accepts is joined through both ways, as a load balancer passes an
//! upgraded connection on, until either side closes it.

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{HOST, HeaderMap, HeaderName, HeaderValue};
use http::uri::{PathAndQuery, Uri};
use http::{Request, Response, Version};
use http_body_util::{BodyExt as _, Either, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use ianua_boot::shutdown::Shutdown;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::wire::Status;

/// The connections served at once.
const CONNECTIONS: usize = 256;

/// The longest a TLS handshake may take.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);

/// The longest the head of the API's answer may take.
const ANSWER_WAIT: Duration = Duration::from_secs(60);

/// The largest request body the ingress reads before forwarding it: well
/// above what the API takes, so the API's own limit is what a scenario
/// meets.
const BUFFERED_MOST: usize = 16 * 1024 * 1024;

/// The header a scenario client names the address it stands for in. The
/// ingress reads it in place of the connection's own address, and never
/// forwards it.
pub(crate) const CLIENT_ADDRESS: &str = "x-scenario-client-address";

/// The headers a client may not set, as the ingress sets them itself.
const FORWARDING: [&str; 5] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

/// What the ingress answers with: the API's answer, or its own refusal.
type Answer = Response<Either<Incoming, Full<Bytes>>>;

/// Where requests go, the client that takes them there, and the stop that
/// ends the upgraded connections joined through.
#[derive(Clone)]
struct Upstream {
    address: SocketAddr,
    client: Client<HttpConnector, Full<Bytes>>,
    shutdown: Shutdown,
}

/// Opens the ingress on a port of loopback, serving `tls` and forwarding
/// to the API at `upstream`, until `shutdown` stops it, and answers where
/// it listens.
///
/// # Errors
///
/// When no port can be listened on.
pub(crate) async fn open(
    tls: Arc<ServerConfig>,
    upstream: SocketAddr,
    shutdown: &Shutdown,
) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let upstream = Upstream {
        address: upstream,
        client: Client::builder(TokioExecutor::new()).build_http(),
        shutdown: shutdown.clone(),
    };
    let accepting = accept(listener, TlsAcceptor::from(tls), upstream, shutdown.clone());
    shutdown.spawn_until_stopped(accepting);
    Ok(address)
}

/// Takes connections until the stop, each served as a task of its own,
/// no more than [`CONNECTIONS`] at once.
async fn accept(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    upstream: Upstream,
    shutdown: Shutdown,
) {
    let permits = Arc::new(Semaphore::new(CONNECTIONS));
    loop {
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            return;
        };
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let connection = serve(stream, peer, acceptor.clone(), upstream.clone());
        shutdown.spawn_until_stopped(async move {
            connection.await;
            drop(permit);
        });
    }
}

/// Ends TLS on `stream` and serves the requests on it.
async fn serve(stream: TcpStream, peer: SocketAddr, acceptor: TlsAcceptor, upstream: Upstream) {
    let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_WAIT, acceptor.accept(stream)).await else {
        return;
    };
    let service = service_fn(move |request| forwarded(request, peer, upstream.clone()));
    let builder = auto::Builder::new(TokioExecutor::new());
    let serving = builder.serve_connection_with_upgrades(TokioIo::new(tls), service);
    if let Err(error) = serving.await {
        tracing::debug!(%error, "a connection to the ingress ended early");
    }
}

/// `request` forwarded to the API, and its answer, a `Status::BAD_REQUEST` when it names
/// no host or a client address that is none, a `Status::PAYLOAD_TOO_LARGE` when its body is
/// past [`BUFFERED_MOST`] or cannot be read whole, or a `Status::BAD_GATEWAY` when the API
/// cannot be reached or does not answer in time. An answer switching
/// protocols has both upgraded connections joined.
async fn forwarded(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    upstream: Upstream,
) -> Result<Answer, Infallible> {
    let client_side = hyper::upgrade::on(&mut request);
    let Some(client) = client_address(request.headers(), peer) else {
        return Ok(refusal(
            Status::BAD_REQUEST,
            "the scenario client address is no IP address",
        ));
    };
    let Some(request) = buffered(request).await else {
        return Ok(refusal(
            Status::PAYLOAD_TOO_LARGE,
            "the request body could not be read whole by the ingress",
        ));
    };
    let Some(outbound) = outbound(request, client, upstream.address) else {
        return Ok(refusal(Status::BAD_REQUEST, "the request names no host"));
    };
    let answered = tokio::time::timeout(ANSWER_WAIT, upstream.client.request(outbound));
    let Ok(Ok(mut answer)) = answered.await else {
        return Ok(refusal(
            Status::BAD_GATEWAY,
            "the ingress could not reach the platform",
        ));
    };
    if answer.status() == Status::SWITCHING_PROTOCOLS {
        let api_side = hyper::upgrade::on(&mut answer);
        join_upgraded(client_side, api_side, &upstream.shutdown);
    }
    Ok(answer.map(Either::Left))
}

/// `request` with its body read whole, unless it is past [`BUFFERED_MOST`]
/// or cannot be read.
async fn buffered(request: Request<Incoming>) -> Option<Request<Full<Bytes>>> {
    let (parts, body) = request.into_parts();
    let read = Limited::new(body, BUFFERED_MOST).collect().await.ok()?;
    Some(Request::from_parts(parts, Full::new(read.to_bytes())))
}

/// Joins the client's upgraded connection to the API's once both have
/// switched, copying both ways until either closes it or the stop.
fn join_upgraded(client_side: OnUpgrade, api_side: OnUpgrade, shutdown: &Shutdown) {
    shutdown.spawn_until_stopped(async move {
        let (Ok(client), Ok(api)) = tokio::join!(client_side, api_side) else {
            return;
        };
        let (mut client, mut api) = (TokioIo::new(client), TokioIo::new(api));
        if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut api).await {
            tracing::debug!(%error, "an upgraded connection through the ingress ended early");
        }
    });
}

/// The address the client stands for: the one it named in
/// [`CLIENT_ADDRESS`], or the connection's own. `None` when it named one
/// that is no IP address.
fn client_address(headers: &HeaderMap, peer: SocketAddr) -> Option<IpAddr> {
    let Some(named) = headers.get(CLIENT_ADDRESS) else {
        return Some(peer.ip());
    };
    named.to_str().ok()?.trim().parse().ok()
}

/// `request` as it goes to the API at `upstream`: over HTTP/1.1, to the
/// same path, for the same host, with the ingress's own word that `client`
/// sent it. `None` when it names no host.
fn outbound<B>(request: Request<B>, client: IpAddr, upstream: SocketAddr) -> Option<Request<B>> {
    let (mut parts, body) = request.into_parts();
    let host = parts
        .headers
        .get(HOST)
        .cloned()
        .or_else(|| authority_of(&parts.uri))?;
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", PathAndQuery::as_str)
        .to_owned();
    parts.uri = Uri::builder()
        .scheme("http")
        .authority(upstream.to_string())
        .path_and_query(path)
        .build()
        .ok()?;
    parts.version = Version::HTTP_11;
    forward_headers(&mut parts.headers, client, host)?;
    Some(Request::from_parts(parts, body))
}

/// Replaces client-supplied forwarding claims with the ingress's own trusted values.
fn forward_headers(headers: &mut HeaderMap, client: IpAddr, host: HeaderValue) -> Option<()> {
    for name in FORWARDING.into_iter().chain([CLIENT_ADDRESS]) {
        headers.remove(name);
    }
    let client = HeaderValue::from_str(&client.to_string()).ok()?;
    headers.insert(HeaderName::from_static("x-forwarded-for"), client);
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    headers.insert(HeaderName::from_static("x-forwarded-host"), host.clone());
    headers.insert(HOST, host);
    Some(())
}

/// The host an HTTP/2 request names in its authority.
fn authority_of(uri: &Uri) -> Option<HeaderValue> {
    let authority = uri.authority()?;
    HeaderValue::from_str(authority.as_str()).ok()
}

/// The ingress's own answer with `status` and `why`.
fn refusal(status: Status, why: &'static str) -> Answer {
    let mut answer = Response::new(Either::Right(Full::new(Bytes::from_static(why.as_bytes()))));
    *answer.status_mut() = status;
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 50_000))
    }

    fn naming(address: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_ADDRESS, HeaderValue::from_str(address).unwrap());
        headers
    }

    /// A client that names an address arrives from it, as the platform is
    /// told.
    #[test]
    fn a_named_address_is_the_clients() {
        let client = client_address(&naming("203.0.113.7"), peer());

        assert_eq!(client, Some(IpAddr::from([203, 0, 113, 7])));
    }

    /// A client that names none arrives from its connection's address.
    #[test]
    fn without_a_named_address_the_connection_is_the_clients() {
        assert_eq!(client_address(&HeaderMap::new(), peer()), Some(peer().ip()));
    }

    /// An invalid named client address returns no address instead of
    /// falling back to the connection's loopback address.
    #[test]
    fn a_named_address_that_is_none_is_refused() {
        assert_eq!(client_address(&naming("not an address"), peer()), None);
    }
}
