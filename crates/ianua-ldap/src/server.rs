//! The LDAP listener: it takes connections, ends TLS, reads the protocol
//! and enforces what the use cases answer.
//!
//! It decides nothing itself: every bind, search and write is answered by
//! a directory use case, and wherever a decision is missing or failed the
//! answer is a refusal. Connections are bounded in number, in how long they
//! may sit idle and how long a handshake may take; binds are bounded per
//! source address before any tenant is named.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ianua_domain::types::CertificateFingerprint;
use ldap3_proto::LdapCodec;
use ldap3_proto::proto::LdapMsg;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::{LdapConfig, LdapLimits};
use crate::error::LdapError;
use crate::ip_throttle::IpBindThrottle;
use crate::ops::{self, Then};
use crate::ports::LdapPorts;
use crate::session::Session;
use crate::tls::ReloadableAcceptor;

/// Entries a single search returns at most.
pub(crate) const SIZE_LIMIT: usize = 1000;

/// The wait every refused bind takes, blunting password guessing.
pub(crate) const FAILED_BIND_DELAY: Duration = Duration::from_millis(250);

/// How long the listener waits after a connection could not be accepted,
/// so running out of file handles does not spin it.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// The LDAP server, listening and ready to serve.
pub struct LdapServer {
    listener: TcpListener,
    tls: Option<Arc<ReloadableAcceptor>>,
    connections: Arc<Connections>,
}

/// What every connection shares.
struct Connections {
    ports: LdapPorts,
    throttle: IpBindThrottle,
    limits: LdapLimits,
}

impl LdapServer {
    /// Listens where `config` says, with its TLS loaded, asking `ports` for
    /// every decision.
    ///
    /// # Errors
    ///
    /// [`LdapError`] when the address cannot be taken or the TLS files do
    /// not read.
    pub async fn open(config: LdapConfig, ports: LdapPorts) -> Result<Self, LdapError> {
        let tls = config
            .tls
            .map(ReloadableAcceptor::new)
            .transpose()?
            .map(Arc::new);
        let listener =
            TcpListener::bind(config.listen)
                .await
                .map_err(|cause| LdapError::Listen {
                    address: config.listen,
                    cause,
                })?;
        Ok(Self {
            listener,
            tls,
            connections: Arc::new(Connections {
                ports,
                throttle: IpBindThrottle::new(config.limits.binds_per_ip_per_minute),
                limits: config.limits,
            }),
        })
    }

    /// The address it listens on.
    ///
    /// # Errors
    ///
    /// When the socket cannot tell.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The TLS acceptor, for reloading its certificate; `None` without TLS.
    #[must_use]
    pub fn acceptor(&self) -> Option<Arc<ReloadableAcceptor>> {
        self.tls.clone()
    }

    /// Serves until `stop` is done, then takes no new connection, lets each
    /// one finish the operation in hand, and returns once all are closed.
    pub async fn serve(self, stop: impl Future<Output = ()> + Send) {
        let slots = Arc::new(Semaphore::new(self.connections.limits.max_connections));
        let closing = CancellationToken::new();
        let open = TaskTracker::new();
        tokio::pin!(stop);
        loop {
            let accepted = tokio::select! {
                () = &mut stop => break,
                accepted = self.listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "ldap: a connection could not be accepted");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                tracing::warn!(%peer, "ldap: connection refused, every slot is taken");
                continue;
            };
            let connection = self.connection(peer, closing.clone(), slot);
            open.spawn(connection.run(stream, self.tls.clone()));
        }
        closing.cancel();
        open.close();
        open.wait().await;
    }

    /// Binds an accepted peer to the shared limits and its held connection slot.
    fn connection(
        &self,
        peer: SocketAddr,
        closing: CancellationToken,
        slot: OwnedSemaphorePermit,
    ) -> Connection {
        Connection {
            shared: Arc::clone(&self.connections),
            peer,
            closing,
            _slot: slot,
        }
    }
}

/// One accepted connection.
struct Connection {
    shared: Arc<Connections>,
    peer: SocketAddr,
    closing: CancellationToken,
    _slot: OwnedSemaphorePermit,
}

impl Connection {
    /// Ends TLS on `stream` when the server has it, then converses.
    async fn run(self, stream: TcpStream, tls: Option<Arc<ReloadableAcceptor>>) {
        let Some(tls) = tls else {
            let session = Session::new(self.peer.ip(), None);
            return converse(&self.shared, stream, session, &self.closing).await;
        };
        let handshake = tokio::time::timeout(
            self.shared.limits.handshake_timeout,
            tls.load().accept(stream),
        );
        let shaken = tokio::select! {
            () = self.closing.cancelled() => return,
            shaken = handshake => shaken,
        };
        let stream = match shaken {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                tracing::debug!(peer = %self.peer, %error, "ldap: TLS handshake failed");
                return;
            }
            Err(_) => {
                tracing::debug!(peer = %self.peer, "ldap: TLS handshake timed out");
                return;
            }
        };
        let session = Session::new(self.peer.ip(), presented(&stream));
        converse(&self.shared, stream, session, &self.closing).await;
    }
}

/// The fingerprint of the client certificate the handshake checked, if the
/// client presented one.
fn presented(
    stream: &tokio_rustls::server::TlsStream<TcpStream>,
) -> Option<CertificateFingerprint> {
    let (_, connection) = stream.get_ref();
    let certificate = connection.peer_certificates()?.first()?;
    Some(CertificateFingerprint::from_digest(
        Sha256::digest(certificate).into(),
    ))
}

/// Reads messages off `stream` and answers each, until the client unbinds,
/// sits idle too long, sends what cannot be read, or the server closes.
async fn converse<S>(
    shared: &Connections,
    stream: S,
    mut session: Session,
    closing: &CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut framed = Framed::new(stream, LdapCodec::default());
    let idle = shared.limits.idle_timeout;
    loop {
        let next = tokio::select! {
            () = closing.cancelled() => return,
            next = tokio::time::timeout(idle, framed.next()) => next,
        };
        let message = match next {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(_))) => {
                sent(&mut framed, [ops::malformed()], idle).await;
                return;
            }
            Ok(None) | Err(_) => return,
        };
        let reply = ops::reply(&shared.ports, &shared.throttle, &mut session, message).await;
        if !sent(&mut framed, reply.answers, idle).await {
            return;
        }
        match reply.then {
            Then::Read => {}
            Then::Close => return,
        }
    }
}

/// Whether every one of `messages` was sent, each given up on after
/// `within`: a client that stops reading does not hold the connection.
async fn sent<S>(
    framed: &mut Framed<S, LdapCodec>,
    messages: impl IntoIterator<Item = LdapMsg>,
    within: Duration,
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    for message in messages {
        let Ok(Ok(())) = tokio::time::timeout(within, framed.send(message)).await else {
            return false;
        };
    }
    true
}

#[cfg(test)]
mod tests;
