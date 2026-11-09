//! What the listeners hand each request to, and how they serve a
//! connection with it.
//!
//! The listeners know nothing about requests. A [`Handler`] answers each
//! one, given the facts of the connection it came on; the listener runs
//! HTTP/1.1 and HTTP/2 over the connection, closes it once it has moved no
//! bytes for the idle limit, and at a stop lets the requests in flight
//! finish before it closes.

use std::convert::Infallible;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::{Body as HttpBody, Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::WaitForCancellationFutureOwned;

use super::activity;
use super::connection::ConnectionFacts;

/// An error a response body may end with.
pub(crate) type BodyError = Box<dyn std::error::Error + Send + Sync>;

/// Answers the requests on a connection.
///
/// Every outcome is a response: a refusal is answered, never raised, so
/// nothing between the handler and the client decides what an error means.
pub(crate) trait Handler: Clone + Send + Sync + 'static {
    /// The body of the responses it gives.
    type Body: HttpBody<Data = Bytes, Error: Into<BodyError>> + Send + 'static;

    /// The response to `request`, which came on the connection `connection`
    /// describes.
    fn handle(
        &self,
        request: Request<Incoming>,
        connection: Arc<ConnectionFacts>,
    ) -> impl Future<Output = Response<Self::Body>> + Send;
}

/// The limits one HTTP connection is served under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HttpLimits {
    /// How long a connection may move no bytes before it is closed.
    pub idle: Duration,
    /// How long an HTTP/1.1 request's headers may take to arrive.
    pub header_read: Duration,
    /// How many headers an HTTP/1.1 request may carry.
    pub max_headers: usize,
    /// How many HTTP/2 streams a connection may hold open at once.
    pub max_streams: u32,
}

/// HTTP bounds and the shutdown signal governing one connection's lifetime.
pub(super) struct ConnectionLifetime<'a> {
    /// Request and idle bounds enforced while serving this connection.
    pub limits: &'a HttpLimits,
    /// Begins graceful shutdown while allowing requests in flight to finish.
    pub stopping: WaitForCancellationFutureOwned,
}

/// Serves HTTP on `io` with `handler` until the connection ends, goes
/// quiet for the idle limit, or, after `stopping`, finishes the requests
/// in flight.
pub(super) async fn serve<I, H>(
    io: I,
    handler: H,
    facts: ConnectionFacts,
    lifetime: ConnectionLifetime<'_>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler,
{
    let (io, clock) = activity::track(io);
    let facts = Arc::new(facts);
    let service = hyper::service::service_fn(move |request| {
        let handler = handler.clone();
        let facts = Arc::clone(&facts);
        async move { Ok::<_, Infallible>(handler.handle(request, facts).await) }
    });
    let builder = builder(lifetime.limits);
    let mut connection = pin!(builder.serve_connection_with_upgrades(TokioIo::new(io), service));

    tokio::select! {
        ended = connection.as_mut() => {
            log_end(ended);
            return;
        }
        () = clock.quiet(lifetime.limits.idle) => {
            tracing::debug!("connection closed after going quiet");
            return;
        }
        () = lifetime.stopping => {}
    }

    connection.as_mut().graceful_shutdown();
    tokio::select! {
        ended = connection => log_end(ended),
        () = clock.quiet(lifetime.limits.idle) => {
            tracing::debug!("connection closed going quiet while stopping");
        }
    }
}

fn builder(limits: &HttpLimits) -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read)
        .max_headers(limits.max_headers);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(limits.max_streams);
    builder
}

fn log_end(ended: Result<(), BodyError>) {
    if let Err(error) = ended {
        tracing::debug!(%error, "connection ended with an error");
    }
}
