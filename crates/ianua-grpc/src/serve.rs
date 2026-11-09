//! Listening for the data planes, over mutual TLS.
//!
//! # Why mutual, and not a token
//!
//! The callers are machines this deployment owns. A bearer token would be a
//! shared secret sitting in a file on a public-facing box, identical on every
//! one of them, rotated by hand and by everyone at once. A client certificate
//! is per-host, expires on its own, and proves possession of a key that never
//! travels.
//!
//! # Deny by default
//!
//! A caller without a certificate the deployment's own authority signed
//! never completes the handshake, so it never reaches a service: no
//! certificate, one from another authority, or one past its dates all end
//! the connection before a byte of the contract is read.
//!
//! # Bounded
//!
//! A handshake must finish within five seconds, a call's answer
//! must start within [`CALL_TIMEOUT`], a bounded number of connections are
//! open at once, each carries at most a few streams, and the zone service
//! holds a bounded number of streams open at once. A stream that goes
//! quiet is pinged, and a peer that stops answering is dropped.

use std::fmt;
use std::future::Future;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::Stream;
use ianua_domain::shared::security::secret::Secret;
use ianua_proto::dns::v1::dns_zones_server::DnsZonesServer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tonic::transport::server::{Connected, Server, TcpConnectInfo};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use crate::dns_zones::DnsZonesService;

/// How often an open connection is pinged. A stream is quiet whenever no
/// tenant is editing DNS, and a load balancer between the two ends reads a
/// quiet connection as a dead one and cuts it. The nameserver pings on the
/// same interval from its side, as either end may be behind it.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// How long a ping may go unanswered before the connection is dropped.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a TLS handshake may take.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a call may take before its answer starts. A stream's later
/// messages are not held to it.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// How many streams one connection may hold at once: a nameserver needs
/// one stream and a report now and then.
const STREAMS_PER_CONNECTION: u32 = 4;

/// How many connections are open at once. A deployment runs a handful of
/// nameservers; the rest of the bound is room for reconnects.
const MAX_CONNECTIONS: usize = 64;

/// How long a failed accept is waited out before the next.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// What the listener proves itself with, and checks callers against.
/// `Debug` shows no key.
#[derive(Clone)]
pub struct GrpcTls {
    /// This server's certificate chain, PEM.
    pub certificate_pem: String,
    /// This server's private key, PEM.
    pub private_key_pem: Secret,
    /// The authority that signs the data planes' certificates, PEM: the
    /// deployment's own, never a public root, which would let any
    /// certificate on the internet in.
    pub client_ca_pem: String,
}

impl fmt::Debug for GrpcTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcTls").finish_non_exhaustive()
    }
}

/// Everything the listener needs to start.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Where to listen.
    pub listen: SocketAddr,
    /// How both ends authenticate.
    pub tls: GrpcTls,
}

/// Why the listener did not start, or stopped.
#[derive(Debug, thiserror::Error)]
pub enum GrpcError {
    /// The address could not be taken.
    #[error("the gRPC listener could not listen on {address}")]
    Bind {
        /// The address asked for.
        address: SocketAddr,
        /// Why it was refused.
        #[source]
        cause: std::io::Error,
    },
    /// The certificate, its key, or the client authority could not be
    /// used.
    #[error("the gRPC listener's TLS could not be set up")]
    Tls(#[source] tonic::transport::Error),
    /// The listener failed while serving.
    #[error("the gRPC listener failed")]
    Serve(#[source] tonic::transport::Error),
}

/// The listener, its port taken and its TLS checked, not yet serving.
pub struct GrpcListener {
    listener: TcpListener,
    address: SocketAddr,
    tls: ServerTlsConfig,
    zones: DnsZonesService,
    ending: CancellationToken,
}

impl fmt::Debug for GrpcListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcListener")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl GrpcListener {
    /// Takes the port `config` names and sets up its TLS, so a start that
    /// cannot serve fails here rather than in a task nobody awaits.
    ///
    /// # Errors
    ///
    /// [`GrpcError::Bind`] when the port cannot be taken, and
    /// [`GrpcError::Tls`] when the certificate, key or client authority
    /// will not load.
    pub async fn open(config: GrpcConfig, zones: DnsZonesService) -> Result<Self, GrpcError> {
        install_crypto_provider();
        let tls = tls_of(&config.tls);
        Server::builder()
            .tls_config(tls.clone())
            .map_err(GrpcError::Tls)?;
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(|cause| bound_error(config.listen, cause))?;
        let address = listener
            .local_addr()
            .map_err(|cause| bound_error(config.listen, cause))?;
        let ending = CancellationToken::new();
        Ok(Self {
            listener,
            address,
            tls,
            zones: zones.ending_on(ending.clone()),
            ending,
        })
    }

    /// Where the listener listens, the port named even where any was asked
    /// for.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Serves the zone stream until `stopping` is done, then ends every
    /// open stream so the stop is not held by streams that never end on
    /// their own; each nameserver keeps its zones and tries again.
    ///
    /// # Errors
    ///
    /// [`GrpcError::Tls`] or [`GrpcError::Serve`] when the server fails.
    pub async fn serve(self, stopping: impl Future<Output = ()>) -> Result<(), GrpcError> {
        tracing::info!(address = %self.address, "grpc listening with mutual TLS");
        let ending = self.ending;
        let stopped = async move {
            stopping.await;
            ending.cancel();
        };
        Server::builder()
            .tls_config(self.tls)
            .map_err(GrpcError::Tls)?
            .timeout(CALL_TIMEOUT)
            .max_concurrent_streams(STREAMS_PER_CONNECTION)
            .http2_keepalive_interval(Some(KEEPALIVE_INTERVAL))
            .http2_keepalive_timeout(Some(KEEPALIVE_TIMEOUT))
            .tcp_keepalive(Some(KEEPALIVE_INTERVAL))
            .add_service(DnsZonesServer::new(self.zones))
            .serve_with_incoming_shutdown(counted(self.listener), stopped)
            .await
            .map_err(GrpcError::Serve)
    }
}

/// The connections `listener` accepts, at most [`MAX_CONNECTIONS`] open at
/// once: one past the bound is closed as it is accepted, and its place
/// comes free when an open one closes. An accept that fails, as when the
/// process is out of file handles, is waited out briefly rather than
/// retried at once.
fn counted(listener: TcpListener) -> impl Stream<Item = std::io::Result<CountedStream>> {
    let places = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    async_stream::stream! {
        loop {
            let (stream, from) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::debug!(%error, "a nameserver link connection was not accepted");
                    tokio::time::sleep(ACCEPT_RETRY).await;
                    continue;
                }
            };
            let Ok(place) = Arc::clone(&places).try_acquire_owned() else {
                tracing::warn!(%from, "a nameserver link connection was refused: at capacity");
                continue;
            };
            if let Err(error) = stream.set_nodelay(true) {
                tracing::debug!(%error, "nodelay could not be set");
            }
            yield Ok(CountedStream { stream, _place: place });
        }
    }
}

/// An accepted connection holding its place among those allowed open
/// until it is dropped.
struct CountedStream {
    stream: TcpStream,
    _place: OwnedSemaphorePermit,
}

impl Connected for CountedStream {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}

impl AsyncRead for CountedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// The server's TLS: its identity, and a client certificate from the
/// deployment's authority required of every caller.
fn tls_of(tls: &GrpcTls) -> ServerTlsConfig {
    ServerTlsConfig::new()
        .identity(Identity::from_pem(
            &tls.certificate_pem,
            tls.private_key_pem.expose(),
        ))
        .client_ca_root(Certificate::from_pem(&tls.client_ca_pem))
        .client_auth_optional(false)
        .timeout(HANDSHAKE_TIMEOUT)
}

/// A refusal of the port at `address`.
fn bound_error(address: SocketAddr, cause: std::io::Error) -> GrpcError {
    GrpcError::Bind { address, cause }
}

/// Selects the rustls crypto provider before the first handshake.
///
/// More than one provider is reachable across the dependency graph and
/// rustls refuses to guess: without this the listener starts, accepts, and
/// panics on a worker thread mid-handshake, so every client sees a socket
/// that opens and closes without a byte. `ring` matches every other place
/// in the workspace that installs one; a second install only says one is
/// in place already.
fn install_crypto_provider() {
    if tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a TLS crypto provider was installed already");
    }
}
