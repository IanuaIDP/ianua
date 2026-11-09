//! A listener speaking mutual TLS, for the API's relay listener the gateway
//! calls inside the deployment's network: one certificate served, and a
//! client certificate of the internal authority required of every
//! connection.
//!
//! Handshakes run beside each other, each held to a timeout and at most
//! [`MOST_HANDSHAKES`] at once, so one client that stalls its handshake
//! holds up nobody else; connections that finished theirs wait in a
//! bounded queue for the server to take them.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{self, RootCertStore, ServerConfig};
use tokio_rustls::server::TlsStream;

/// The most handshakes run at once.
const MOST_HANDSHAKES: usize = 64;

/// The most finished connections waiting for the server.
const MOST_WAITING: usize = 64;

/// How long taking connections pauses after the socket refused one, as
/// when the process is out of file handles, so the loop does not spin.
const ACCEPT_PAUSE: Duration = Duration::from_millis(50);

/// What a mutual TLS listener is made of, as PEM text.
pub(crate) struct MutualPem<'a> {
    /// The internal authority, the only one a client's certificate may
    /// chain to.
    pub authority: &'a str,
    /// The certificate chain served.
    pub chain: &'a str,
    /// Its private key.
    pub key: &'a str,
}

/// Why a listener's mutual TLS could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum MutualTlsError {
    /// A certificate or the key does not read as PEM.
    #[error("a certificate or key of the relay listener does not read")]
    Unreadable(#[source] rustls::pki_types::pem::Error),
    /// The authority or the chain holds no certificate.
    #[error("the relay listener's authority or chain holds no certificate")]
    NoCertificate,
    /// The client certificate check could not be built.
    #[error("the relay listener's client certificate check could not be built")]
    Verifier(#[source] rustls::server::VerifierBuilderError),
    /// rustls refused a certificate or the key.
    #[error("the relay listener's TLS settings were refused")]
    Tls(#[source] rustls::Error),
}

/// The server's TLS `pem` describes.
///
/// # Errors
///
/// Any [`MutualTlsError`].
pub(crate) fn server_config(pem: &MutualPem<'_>) -> Result<Arc<ServerConfig>, MutualTlsError> {
    let provider = Arc::new(ring::default_provider());
    let mut roots = RootCertStore::empty();
    for anchor in certificates(pem.authority)? {
        roots.add(anchor).map_err(MutualTlsError::Tls)?;
    }
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .map_err(MutualTlsError::Verifier)?;
    let key =
        PrivateKeyDer::from_pem_slice(pem.key.as_bytes()).map_err(MutualTlsError::Unreadable)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(MutualTlsError::Tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(pem.chain)?, key)
        .map_err(MutualTlsError::Tls)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Every certificate in `pem`, refused when it holds none.
fn certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, MutualTlsError> {
    let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(MutualTlsError::Unreadable)?;
    if certificates.is_empty() {
        return Err(MutualTlsError::NoCertificate);
    }
    Ok(certificates)
}

/// Connections whose mutual TLS handshake finished, as the server takes
/// them.
pub(crate) struct MutualListener {
    finished: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl MutualListener {
    /// Takes connections on `socket` with `config`, each handshake held to
    /// `handshake`, until `shutdown` stops.
    ///
    /// # Errors
    ///
    /// The socket's error when its address cannot be read.
    pub(crate) fn start(
        socket: TcpListener,
        config: Arc<ServerConfig>,
        handshake: Duration,
        shutdown: &Shutdown,
    ) -> io::Result<Self> {
        let local = socket.local_addr()?;
        let (sender, finished) = mpsc::channel(MOST_WAITING);
        let accepting = Accepting {
            socket,
            acceptor: TlsAcceptor::from(config),
            handshake,
            permits: Arc::new(Semaphore::new(MOST_HANDSHAKES)),
            sender,
        };
        let stopping = shutdown.stopping();
        shutdown.spawn("the relay listener's handshakes", async move {
            tokio::select! {
                () = accepting.run() => {}
                () = stopping => {}
            }
        });
        Ok(Self { finished, local })
    }
}

impl axum::serve::Listener for MutualListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.finished.recv().await {
            Some(finished) => finished,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// The loop taking connections and running their handshakes.
struct Accepting {
    socket: TcpListener,
    acceptor: TlsAcceptor,
    handshake: Duration,
    permits: Arc<Semaphore>,
    sender: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
}

impl Accepting {
    /// Takes connections until the socket fails for good or the server is
    /// gone, each handshake run on its own under a permit.
    async fn run(self) {
        loop {
            let Ok(permit) = Arc::clone(&self.permits).acquire_owned().await else {
                return;
            };
            let (stream, peer) = match self.socket.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::debug!(%error, "a relay connection was not taken");
                    tokio::time::sleep(ACCEPT_PAUSE).await;
                    continue;
                }
            };
            let acceptor = self.acceptor.clone();
            let sender = self.sender.clone();
            let handshake = self.handshake;
            tokio::spawn(async move {
                let accepted = tokio::time::timeout(handshake, acceptor.accept(stream)).await;
                drop(permit);
                let Ok(Ok(stream)) = accepted else {
                    tracing::debug!(%peer, "a relay handshake was refused or took too long");
                    return;
                };
                if sender.send((stream, peer)).await.is_err() {
                    tracing::debug!(%peer, "the relay listener stopped before taking a connection");
                }
            });
        }
    }
}
