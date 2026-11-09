//! The listener services connect to: each connection taken while there is
//! room for it, its TLS handshake and each request's head held to their
//! time, the service named by its client certificate, and every request
//! handed to the [`Egress`] gateway.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::routing::egress::ServiceIdentity;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::dial::Resolve;
use crate::handler::Egress;
use crate::tls::service_of;

/// How long the loop waits after the listener failed to take a
/// connection, so a lack of file handles does not spin it.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What one connection may take on.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionLimits {
    /// The most connections held at once; one past it is closed at once.
    pub connections: usize,
    /// How long a service may take to finish the TLS handshake.
    pub handshake: Duration,
    /// How long a service may take to send a request's head.
    pub header: Duration,
}

/// Takes services' connections on `listener` until `shutdown` stops, each
/// over TLS through `acceptor` and served on a task `shutdown` waits for.
pub(crate) async fn accept<R: Resolve>(
    listener: TcpListener,
    taking: Taking<R>,
    shutdown: Shutdown,
) {
    let room = Arc::new(Semaphore::new(taking.limits.connections));
    let taking = Arc::new(taking);
    loop {
        let accepted = tokio::select! {
            () = shutdown.stopping() => return,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "the egress listener could not take a connection");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let Ok(held) = Arc::clone(&room).try_acquire_owned() else {
            tracing::warn!(%peer, "egress refused a connection: it holds all it may");
            continue;
        };
        let taking = Arc::clone(&taking);
        shutdown.spawn_until_stopped(async move {
            taking.connection(stream, peer).await;
            drop(held);
        });
    }
}

/// What every connection is taken with: the TLS, the gateway, and the
/// limits.
pub(crate) struct Taking<R> {
    pub(crate) acceptor: TlsAcceptor,
    pub(crate) egress: Arc<Egress<R>>,
    pub(crate) limits: ConnectionLimits,
}

impl<R: Resolve> Taking<R> {
    /// Ends the TLS handshake of `stream`, names the service by its
    /// certificate, and serves its requests. A handshake that fails or
    /// takes too long, or a certificate that names no service, ends the
    /// connection.
    async fn connection(&self, stream: TcpStream, peer: SocketAddr) {
        let handshake = self.acceptor.accept(stream);
        let Ok(Ok(tls)) = tokio::time::timeout(self.limits.handshake, handshake).await else {
            tracing::info!(%peer, decision = "deny", reason = "tls_handshake_failed", "egress decided");
            return;
        };
        let Some(service) = service_of(tls.get_ref().1) else {
            tracing::info!(%peer, decision = "deny", reason = "no_service_identity", "egress decided");
            return;
        };
        let who = Served {
            service,
            peer,
            header: self.limits.header,
        };
        serve(tls, who, Arc::clone(&self.egress)).await;
    }
}

/// Who a connection is from and how long it may take over each head.
#[derive(Debug, Clone)]
pub struct Served {
    /// The service, as its certificate names it.
    pub service: ServiceIdentity,
    /// Where it connected from.
    pub peer: SocketAddr,
    /// How long it may take to send a request's head.
    pub header: Duration,
}

/// Serves the requests the service `who` names sends over `io`, upgrades
/// included, through `egress`.
pub async fn serve<S, R>(io: S, who: Served, egress: Arc<Egress<R>>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: Resolve,
{
    let Served {
        service,
        peer,
        header,
    } = who;
    let service = Arc::new(service);
    let handler = service_fn(move |request: hyper::Request<Incoming>| {
        let egress = Arc::clone(&egress);
        let service = Arc::clone(&service);
        async move { Ok::<_, Infallible>(egress.handle(request, &service, peer).await) }
    });
    let ended = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header)
        .serve_connection(TokioIo::new(io), handler)
        .with_upgrades()
        .await;
    if let Err(error) = ended {
        tracing::debug!(%error, "a connection from a service ended");
    }
}
