//! The links to the gateway: one to every address its name resolves to,
//! each opened outward over mutual TLS and held as HTTP/2 with the gateway
//! as the client, so nothing in the network accepts a connection from
//! outside.
//!
//! The name is resolved again on a timer: a link opens for each new
//! address, up to the most links allowed, and the link of an address gone
//! is closed. A link that ends opens again after a wait that grows while
//! it keeps failing and starts short again once one held. No link opens
//! with a certificate that has run out; it waits for the renewal.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ianua_boot::shutdown::Shutdown;
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_util::sync::CancellationToken;

use crate::backoff::Backoff;
use crate::config::GatewayAddress;
use crate::dial::Resolve;
use crate::relay::{Relay, serve};
use crate::tls::{Credentials, HTTP2};

/// How long a link must have held for the next wait to start short again.
const STEADY: Duration = Duration::from_secs(60);

/// Why a link ended or never opened.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The gateway's name is not one a certificate can be checked against.
    #[error("the gateway's name is not a TLS server name")]
    Name,
    /// The gateway could not be reached.
    #[error("the gateway could not be reached")]
    Connect(#[source] std::io::Error),
    /// The TLS handshake failed: the gateway's certificate is not the
    /// connector authority's, or the gateway refused the connector's.
    #[error("the TLS handshake with the gateway failed")]
    Handshake(#[source] std::io::Error),
    /// Reaching the gateway and the handshake took too long.
    #[error("the gateway did not finish the handshake in time")]
    TimedOut,
    /// The gateway did not agree to speak HTTP/2.
    #[error("the gateway did not agree to HTTP/2")]
    NotHttp2,
    /// The link's HTTP/2 ended badly.
    #[error("the link ended")]
    Http(#[source] hyper::Error),
}

/// Where the links go and how they are held.
#[derive(Debug, Clone)]
pub(crate) struct LinkSettings {
    /// The gateway's connector listener.
    pub gateway: GatewayAddress,
    /// The most links held at once.
    pub links: usize,
    /// The most relays at once on one link.
    pub streams: u32,
    /// The longest reaching the gateway and the handshake may take.
    pub handshake: Duration,
    /// How often the gateway's name is resolved again.
    pub resolve: Duration,
    /// The longest wait before a link opens again.
    pub backoff_max: Duration,
}

/// The links to the gateway, and how many are open now.
pub struct Links<R> {
    settings: LinkSettings,
    name: ServerName<'static>,
    relay: Arc<Relay<R>>,
    credentials: watch::Receiver<Credentials>,
    live: watch::Sender<usize>,
    shutdown: Shutdown,
}

/// What [`Links`] are built from.
pub(crate) struct LinkParts<R> {
    /// Where the links go and how they are held.
    pub settings: LinkSettings,
    /// What each request on a link is answered by.
    pub relay: Arc<Relay<R>>,
    /// The certificate links open with now, replaced on each renewal.
    pub credentials: watch::Receiver<Credentials>,
    /// Waits for every link.
    pub shutdown: Shutdown,
}

impl<R: Resolve> Links<R> {
    /// Links built from `parts`, none open yet.
    ///
    /// # Errors
    ///
    /// [`LinkError::Name`] when the gateway's host is not a TLS server
    /// name.
    pub(crate) fn new(parts: LinkParts<R>) -> Result<Self, LinkError> {
        let name = ServerName::try_from(parts.settings.gateway.host().to_owned())
            .map_err(|_| LinkError::Name)?;
        Ok(Self {
            settings: parts.settings,
            name,
            relay: parts.relay,
            credentials: parts.credentials,
            live: watch::Sender::new(0),
            shutdown: parts.shutdown,
        })
    }

    /// How many links are open, as it changes.
    #[must_use]
    pub fn live(&self) -> watch::Receiver<usize> {
        self.live.subscribe()
    }

    /// Holds a link to every address of the gateway until the stop.
    pub async fn hold(self: Arc<Self>) {
        let mut held: HashMap<SocketAddr, CancellationToken> = HashMap::new();
        loop {
            match self.addresses().await {
                Ok(addresses) => self.follow(&mut held, &addresses),
                Err(reason) => {
                    tracing::warn!(%reason, "the gateway's name did not resolve; keeping the links held")
                }
            }
            tokio::select! {
                () = self.shutdown.stopping() => return,
                () = tokio::time::sleep(self.settings.resolve) => {}
            }
        }
    }

    /// The addresses the gateway's name resolves to now.
    async fn addresses(&self) -> Result<Vec<SocketAddr>, &'static str> {
        let gateway = &self.settings.gateway;
        let lookup = tokio::net::lookup_host((gateway.host(), gateway.port()));
        match tokio::time::timeout(self.settings.handshake, lookup).await {
            Ok(Ok(addresses)) => Ok(addresses.collect()),
            Ok(Err(_)) => Err("the lookup failed"),
            Err(_) => Err("the lookup took too long"),
        }
    }

    /// Closes the links of addresses gone and opens one for each new
    /// address, up to the most allowed.
    fn follow(
        self: &Arc<Self>,
        held: &mut HashMap<SocketAddr, CancellationToken>,
        addresses: &[SocketAddr],
    ) {
        held.retain(|address, stop| {
            let kept = addresses.contains(address);
            if !kept {
                stop.cancel();
            }
            kept
        });
        for address in addresses {
            if held.len() >= self.settings.links {
                return;
            }
            let Some(stop) = newly_held(held, *address) else {
                continue;
            };
            let links = Arc::clone(self);
            let address = *address;
            self.shutdown
                .spawn_until_stopped(async move { links.keep_open(address, stop).await });
        }
    }

    /// Keeps the link to `address` open until `stop`.
    async fn keep_open(&self, address: SocketAddr, stop: CancellationToken) {
        let mut backoff = Backoff::new(self.settings.backoff_max);
        loop {
            let Some(credentials) = self.usable_credentials(&stop).await else {
                return;
            };
            let opened_at = Instant::now();
            let ended = tokio::select! {
                () = stop.cancelled() => return,
                ended = self.hold_once(address, &credentials) => ended,
            };
            log_end(address, &ended);
            if opened_at.elapsed() > STEADY {
                backoff.reset();
            }
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(backoff.wait()) => {}
            }
        }
    }

    /// The certificate to open a link with, once one has not run out, or
    /// `None` at `stop`.
    async fn usable_credentials(&self, stop: &CancellationToken) -> Option<Credentials> {
        let mut credentials = self.credentials.clone();
        loop {
            let current = credentials.borrow_and_update().clone();
            if current.hold_at(OffsetDateTime::now_utc()) {
                return Some(current);
            }
            tracing::warn!("the certificate has run out; no link opens until it is renewed");
            let changed = tokio::select! {
                () = stop.cancelled() => return None,
                changed = credentials.changed() => changed,
            };
            changed.ok()?;
        }
    }

    /// Opens one link to `address` and serves it until it ends.
    async fn hold_once(
        &self,
        address: SocketAddr,
        credentials: &Credentials,
    ) -> Result<(), LinkError> {
        let stream = opened(address, &self.name, credentials, self.settings.handshake).await?;
        let _live = Live::counted(&self.live);
        tracing::info!(%address, "linked to the gateway");
        serve(stream, Arc::clone(&self.relay), self.settings.streams)
            .await
            .map_err(LinkError::Http)
    }
}

/// A TLS connection to the gateway at `address`, its certificate checked
/// for `name` against the connector authority, speaking HTTP/2, within
/// `timeout`.
///
/// # Errors
///
/// [`LinkError`] when it cannot be reached, the handshake fails or takes
/// too long, or HTTP/2 was not agreed.
pub async fn opened(
    address: SocketAddr,
    name: &ServerName<'static>,
    credentials: &Credentials,
    timeout: Duration,
) -> Result<TlsStream<TcpStream>, LinkError> {
    let connecting = async {
        let tcp = TcpStream::connect(address)
            .await
            .map_err(LinkError::Connect)?;
        tcp.set_nodelay(true).map_err(LinkError::Connect)?;
        TlsConnector::from(Arc::clone(&credentials.config))
            .connect(name.clone(), tcp)
            .await
            .map_err(LinkError::Handshake)
    };
    let tls = tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| LinkError::TimedOut)??;
    if tls.get_ref().1.alpn_protocol() != Some(HTTP2) {
        return Err(LinkError::NotHttp2);
    }
    Ok(tls)
}

/// The stop for a link newly held for `address`, or `None` when it is held
/// already.
fn newly_held(
    held: &mut HashMap<SocketAddr, CancellationToken>,
    address: SocketAddr,
) -> Option<CancellationToken> {
    if held.contains_key(&address) {
        return None;
    }
    let stop = CancellationToken::new();
    held.insert(address, stop.clone());
    Some(stop)
}

/// Logs how a link ended.
fn log_end(address: SocketAddr, ended: &Result<(), LinkError>) {
    match ended {
        Ok(()) => tracing::info!(%address, "the link to the gateway closed"),
        Err(error) => tracing::warn!(%address, %error, "the link to the gateway ended"),
    }
}

/// One open link, counted while it lasts.
struct Live<'a>(&'a watch::Sender<usize>);

impl<'a> Live<'a> {
    fn counted(live: &'a watch::Sender<usize>) -> Self {
        live.send_modify(|count| *count = count.saturating_add(1));
        Self(live)
    }
}

impl Drop for Live<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count = count.saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{Method, Request, StatusCode};
    use http_body_util::Empty;
    use hyper::client::conn::http2 as client;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use ianua_domain::shared::security::secret::Secret;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::server::WebPkiClientVerifier;
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};
    use uuid::Uuid;

    use super::*;
    use crate::dial::{Dialer, SystemResolver};
    use crate::state::Issued;
    use crate::targets::AllowList;

    /// An authority, and what it signs.
    struct Authority {
        pem: String,
        der: CertificateDer<'static>,
        issuer: Issuer<'static, KeyPair>,
    }

    fn install_provider() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    fn authority() -> Authority {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let certificate = params.self_signed(&key).unwrap();
        Authority {
            pem: certificate.pem(),
            der: certificate.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    /// A leaf for `name`, for `purpose`, signed by `authority`, with its key.
    fn leaf(
        authority: &Authority,
        name: &str,
        purpose: ExtendedKeyUsagePurpose,
    ) -> (String, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.extended_key_usages = vec![purpose];
        (
            params.signed_by(&key, &authority.issuer).unwrap().pem(),
            key,
        )
    }

    fn certificate_der(pem: &str) -> CertificateDer<'static> {
        rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
    }

    /// A gateway's connector listener serving a certificate `serving` signed
    /// and taking connectors `trusting` signed.
    fn gateway_acceptor(serving: &Authority, trusting: &Authority) -> TlsAcceptor {
        let (certificate, key) = leaf(serving, "127.0.0.1", ExtendedKeyUsagePurpose::ServerAuth);
        let mut roots = RootCertStore::empty();
        roots.add(trusting.der.clone()).unwrap();
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let mut config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![certificate_der(&certificate)],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
        config.alpn_protocols = vec![HTTP2.to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }

    /// What a connector the platform's `authority` enrolled opens links
    /// with.
    fn credentials(authority: &Authority) -> Credentials {
        let (certificate, key) = leaf(authority, "connector", ExtendedKeyUsagePurpose::ClientAuth);
        let issued = Issued {
            id: Uuid::now_v7(),
            certificate_pem: certificate,
            authority_pem: authority.pem.clone(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            renew_after: OffsetDateTime::now_utc() + time::Duration::minutes(30),
        };
        Credentials::of(&issued, &Secret::new(key.serialize_pem())).unwrap()
    }

    fn name() -> ServerName<'static> {
        ServerName::try_from("127.0.0.1".to_owned()).unwrap()
    }

    /// Acme's connector links to the gateway. The gateway sends a
    /// connection to the wiki down the link and gets the wiki's bytes.
    #[tokio::test]
    async fn the_gateway_reaches_a_listed_target_down_the_link() {
        install_provider();
        let platform = authority();
        let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = gateway.local_addr().unwrap().port();
        let wiki = pong_wiki().await;
        let shutdown = Shutdown::new(Duration::from_secs(1));
        let (_keep, held) = watch::channel(credentials(&platform));
        let links = links_to(port, &wiki, held, &shutdown);
        tokio::spawn(Arc::clone(&links).hold());

        let heard = ping_down_the_link(&gateway, &platform, &wiki).await;

        assert_eq!(&heard, b"pong");
        assert_eq!(*links.live().borrow(), 1);
        shutdown.stop();
    }

    /// A wiki on a free port that answers four bytes with `pong`, and its
    /// address.
    async fn pong_wiki() -> String {
        let wiki = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = wiki.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut socket, _) = wiki.accept().await.unwrap();
            let mut heard = [0_u8; 4];
            socket.read_exact(&mut heard).await.unwrap();
            socket.write_all(b"pong").await.unwrap();
        });
        address
    }

    /// Links to the gateway on `port` with the certificate `held`,
    /// relaying only to `target`.
    fn links_to(
        port: u16,
        target: &str,
        held: watch::Receiver<Credentials>,
        shutdown: &Shutdown,
    ) -> Arc<Links<SystemResolver>> {
        let dialer = Dialer {
            resolver: SystemResolver,
            targets: AllowList::parse([target]).unwrap(),
            timeout: Duration::from_secs(2),
        };
        let relay = Relay::new(dialer, Duration::from_secs(5), 8, shutdown.clone());
        let links = Links::new(LinkParts {
            settings: LinkSettings {
                gateway: format!("127.0.0.1:{port}").parse().unwrap(),
                links: 2,
                streams: 8,
                handshake: Duration::from_secs(5),
                resolve: Duration::from_secs(30),
                backoff_max: Duration::from_millis(50),
            },
            relay: Arc::new(relay),
            credentials: held,
            shutdown: shutdown.clone(),
        });
        Arc::new(links.unwrap())
    }

    /// What `target` answers `ping` with, sent by the gateway on
    /// `gateway` down the first link the connector opens to it.
    async fn ping_down_the_link(
        gateway: &TcpListener,
        platform: &Authority,
        target: &str,
    ) -> [u8; 4] {
        let (tcp, _) = gateway.accept().await.unwrap();
        let tls = gateway_acceptor(platform, platform)
            .accept(tcp)
            .await
            .unwrap();
        let (mut sender, connection) = client::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(target)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let answer = sender.send_request(request).await.unwrap();
        assert_eq!(answer.status(), StatusCode::OK);
        let mut tunnel = TokioIo::new(hyper::upgrade::on(answer).await.unwrap());
        tunnel.write_all(b"ping").await.unwrap();
        let mut heard = [0_u8; 4];
        tunnel.read_exact(&mut heard).await.unwrap();
        heard
    }

    /// A gateway certificate signed by another authority fails the TLS
    /// handshake even when the listener trusts the connector's certificate.
    #[tokio::test]
    async fn a_gateway_from_another_authority_is_refused() {
        install_provider();
        let platform = authority();
        let mallorys = authority();
        let impostor = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = impostor.local_addr().unwrap();
        let acceptor = gateway_acceptor(&mallorys, &platform);
        tokio::spawn(async move {
            let (tcp, _) = impostor.accept().await.unwrap();
            let _ = acceptor.accept(tcp).await;
        });

        let opened = opened(
            address,
            &name(),
            &credentials(&platform),
            Duration::from_secs(5),
        )
        .await;

        assert!(matches!(opened, Err(LinkError::Handshake(_))));
    }

    /// A gateway that answers nothing is given up on after the handshake
    /// timeout.
    #[tokio::test]
    async fn a_silent_gateway_times_out() {
        install_provider();
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = silent.local_addr().unwrap();

        let opened = opened(
            address,
            &name(),
            &credentials(&authority()),
            Duration::from_millis(100),
        )
        .await;

        assert!(matches!(opened, Err(LinkError::TimedOut)));
        drop(silent);
    }
}
