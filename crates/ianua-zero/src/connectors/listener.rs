//! The listener connectors dial out to.
//!
//! Every connection is judged before a byte of HTTP/2 is spoken. The TLS
//! handshake requires a client certificate chaining to the connector
//! authority and HTTP/2 as the protocol; a connection without either is
//! closed. The certificate's name says which tenant's connector it is, and
//! the link is let in only when that tenant holds that connector enrolled
//! with the key the certificate carries, not revoked. Only then is the
//! HTTP/2 connection opened, with the gateway as its client, and the link
//! added; it is removed the moment the connection ends or the gateway
//! closes it.
//!
//! Connections are bounded: one past the most links the gateway holds is
//! closed at once, and every step has a timeout.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::client::conn::http2::{Connection, SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use ianua_app::ports::routing::ConnectorSightings;
use ianua_domain::shared::errors::DomainError;
use ianua_infra::crypto::{ConnectorIdentity, connector_identity};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use super::LinkLimits;
use super::links::{ConnectorLinks, LinkRefusal, NewLink};
use super::sightings::Sighting;
use super::tls::LINK_PROTOCOL;

/// The HTTP/2 connection of one link, the gateway its client.
type LinkConnection = Connection<TokioIo<TlsStream<TcpStream>>, Empty<Bytes>, TokioExecutor>;

/// How long the listener waits after it fails to accept a connection, so
/// a process out of file handles does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Why a connection did not become a link. None of it names a key.
#[derive(Debug, thiserror::Error)]
enum Refused {
    #[error("the TLS handshake did not finish in time")]
    HandshakeTimedOut,
    #[error("the TLS handshake failed")]
    Handshake(#[source] std::io::Error),
    #[error("the connector did not speak HTTP/2")]
    Protocol,
    #[error("the connector presented no certificate")]
    NoCertificate,
    #[error("the certificate names no connector")]
    Identity(#[source] DomainError),
    #[error("the link is not let in")]
    Link(#[source] LinkRefusal),
    #[error("the HTTP/2 handshake did not finish in time")]
    Http2TimedOut,
    #[error("the HTTP/2 handshake failed")]
    Http2(#[source] hyper::Error),
}

/// What the listener is made of.
pub(crate) struct ConnectorListenerParts {
    /// The bound socket.
    pub socket: TcpListener,
    /// Its TLS, from [`super::server_config`].
    pub tls: Arc<ServerConfig>,
    /// Where links are judged and kept.
    pub links: Arc<ConnectorLinks>,
    /// Where sightings are noted.
    pub sightings: Arc<dyn ConnectorSightings>,
    /// What links are held to.
    pub limits: LinkLimits,
}

/// Accepts private-network links while limiting concurrent connector handshakes.
pub(crate) struct ConnectorListener {
    socket: TcpListener,
    link: LinkMaker,
    permits: Arc<Semaphore>,
}

/// What each connection is turned into a link with.
#[derive(Clone)]
struct LinkMaker {
    acceptor: TlsAcceptor,
    links: Arc<ConnectorLinks>,
    sightings: Arc<dyn ConnectorSightings>,
    limits: LinkLimits,
}

/// One accepted socket and the capacity permit held for its entire link.
struct AcceptedLink {
    tcp: TcpStream,
    peer: SocketAddr,
    _permit: OwnedSemaphorePermit,
    closed: CancellationToken,
}

/// A connector admitted by TLS identity and ready to exchange HTTP/2 streams.
struct NegotiatedLink {
    identity: ConnectorIdentity,
    sender: SendRequest<Empty<Bytes>>,
    connection: LinkConnection,
}

impl ConnectorListener {
    /// The listener `parts` describe.
    #[must_use]
    pub(crate) fn new(parts: ConnectorListenerParts) -> Self {
        Self {
            socket: parts.socket,
            permits: Arc::new(Semaphore::new(parts.limits.max_links)),
            link: LinkMaker {
                acceptor: TlsAcceptor::from(parts.tls),
                links: parts.links,
                sightings: parts.sightings,
                limits: parts.limits,
            },
        }
    }

    /// Takes connectors' connections until `stop` fires; every link closes
    /// with it.
    pub(crate) async fn run(self, stop: CancellationToken) {
        loop {
            let accepted = tokio::select! {
                () = stop.cancelled() => return,
                accepted = self.socket.accept() => accepted,
            };
            let Ok((tcp, peer)) = accepted else {
                tracing::warn!("a connector connection could not be accepted");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            };
            let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
                tracing::warn!(%peer, "a connector connection was closed: the gateway holds as many links as it may");
                continue;
            };
            tokio::spawn(self.link.clone().serve(AcceptedLink {
                tcp,
                peer,
                _permit: permit,
                closed: stop.child_token(),
            }));
        }
    }
}

impl LinkMaker {
    /// Turns `tcp` into a link and holds it until it ends, logging why one
    /// was refused.
    async fn serve(self, accepted: AcceptedLink) {
        let AcceptedLink {
            tcp,
            peer,
            _permit,
            closed,
        } = accepted;
        let Err(refused) = self.serve_link(tcp, closed).await else {
            return;
        };
        tracing::info!(%peer, reason = %refused, "a connector connection was refused");
    }

    /// The link `tcp` becomes, held until it ends or `closed` fires.
    async fn serve_link(&self, tcp: TcpStream, closed: CancellationToken) -> Result<(), Refused> {
        let NegotiatedLink {
            identity,
            sender,
            connection,
        } = self.negotiate(tcp).await?;
        let link = self
            .links
            .register(
                NewLink {
                    identity,
                    sender,
                    closed: closed.clone(),
                },
                self.limits.streams_per_link,
            )
            .map_err(Refused::Link)?;
        tracing::info!(tenant = %identity.tenant, connector = %identity.connector, "a connector linked");
        tokio::spawn(self.sighting(&identity).note_while_open(closed.clone()));
        tokio::select! {
            ended = connection => log_end(&identity, ended),
            () = closed.cancelled() => {}
        }
        self.links
            .remove(identity.tenant, identity.connector, &link);
        tracing::info!(tenant = %identity.tenant, connector = %identity.connector, "a connector link ended");
        Ok(())
    }

    /// Checks the TLS identity before opening HTTP/2, bounding each handshake.
    async fn negotiate(&self, tcp: TcpStream) -> Result<NegotiatedLink, Refused> {
        let handshake = self.limits.handshake;
        let tls = tokio::time::timeout(handshake, self.acceptor.accept(tcp))
            .await
            .map_err(|_| Refused::HandshakeTimedOut)?
            .map_err(Refused::Handshake)?;
        let identity = identity_of(&tls)?;
        self.links.admits(&identity).map_err(Refused::Link)?;
        let (sender, connection) = tokio::time::timeout(handshake, self.http2(tls))
            .await
            .map_err(|_| Refused::Http2TimedOut)?
            .map_err(Refused::Http2)?;
        Ok(NegotiatedLink {
            identity,
            sender,
            connection,
        })
    }

    /// The HTTP/2 connection over `tls`, with the gateway as its client.
    async fn http2(
        &self,
        tls: TlsStream<TcpStream>,
    ) -> Result<(SendRequest<Empty<Bytes>>, LinkConnection), hyper::Error> {
        let keepalive = self.limits.keepalive;
        hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(keepalive)
            .keep_alive_timeout(keepalive)
            .keep_alive_while_idle(true)
            .handshake(TokioIo::new(tls))
            .await
    }

    /// The sightings of the link `identity` names.
    fn sighting(&self, identity: &ConnectorIdentity) -> Sighting {
        Sighting {
            sightings: Arc::clone(&self.sightings),
            tenant: identity.tenant,
            connector: identity.connector,
            every: self.limits.sighting,
        }
    }
}

/// Who the connector on `tls` is, once it speaks HTTP/2 and presented a
/// certificate the authority wrote a connector's name into.
fn identity_of(tls: &TlsStream<TcpStream>) -> Result<ConnectorIdentity, Refused> {
    let (_, connection) = tls.get_ref();
    if connection.alpn_protocol() != Some(LINK_PROTOCOL) {
        return Err(Refused::Protocol);
    }
    let leaf = connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or(Refused::NoCertificate)?;
    connector_identity(leaf.as_ref()).map_err(Refused::Identity)
}

/// Logs how a link's connection ended, when it ended on an error.
fn log_end(identity: &ConnectorIdentity, ended: Result<(), hyper::Error>) {
    let Err(error) = ended else {
        return;
    };
    tracing::info!(
        tenant = %identity.tenant,
        connector = %identity.connector,
        %error,
        "a connector link broke"
    );
}
