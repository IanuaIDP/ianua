//! Sending an audit record to a syslog collector over TLS (RFC 5425): one
//! RFC 5424 message, its JSON record as the text, framed by its length.
//!
//! There is no HTTP client to screen names here, so the sender resolves
//! the collector's host itself, keeps only the addresses the deployment may
//! reach, and connects to those alone, so a name pointed inward is never
//! dialled. The certificate is checked against the public roots, and an
//! extra authority where the deployment set one up, the name included.
//! The whole send, resolving, connecting, the handshake and the write, is
//! held to one timeout.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::http::calls::bounded;
use crate::http::client::{DeliveryReach, NameLookup, addresses_of};
use crate::http::logs::streams::event::RecordJson;

/// The priority of every record: facility 13, log audit, at severity 6,
/// informational (RFC 5424, 6.2.1).
const PRIORITY: u8 = 110;

/// The longest message id RFC 5424 allows.
const MSGID_MOST: usize = 32;

/// The name the platform's records are sent from.
const APP_NAME: &str = "ianua";

/// Sends records to syslog collectors over TLS.
#[derive(Clone)]
pub(super) struct SyslogSender {
    tls: TlsConnector,
    lookup: NameLookup,
    networks: UpstreamNetworks,
    timeout: Duration,
}

impl fmt::Debug for SyslogSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyslogSender")
            .field("networks", &self.networks)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl SyslogSender {
    /// A sender trusting what `reach` trusts, looking names up as it says,
    /// reaching a collector only when it is public or in `networks`, each
    /// send held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when TLS cannot be set up.
    pub(super) fn new(
        networks: UpstreamNetworks,
        timeout: Duration,
        reach: &DeliveryReach,
    ) -> Result<Self, DomainError> {
        Self::trusting(reach.tls_roots()?, reach.lookup(), networks, timeout)
    }

    /// A sender trusting `roots` alone, looking names up as `lookup` says.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when TLS cannot be set up.
    pub(super) fn trusting(
        roots: RootCertStore,
        lookup: NameLookup,
        networks: UpstreamNetworks,
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(DomainError::infra)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
            lookup,
            networks,
            timeout: bounded(timeout),
        })
    }

    /// Sends `record` to the collector at `host` on `port`.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when the host resolves only to addresses
    ///   the deployment may not reach.
    /// - `DomainError::Infrastructure` when it cannot be resolved, reached
    ///   or shaken hands with, or the send does not finish in time.
    pub(super) async fn send(
        &self,
        host: &str,
        port: u16,
        record: &AuditRecord,
    ) -> Result<(), DomainError> {
        let frame = framed(&message(record)?);
        tokio::time::timeout(self.timeout, self.deliver(host, port, &frame))
            .await
            .map_err(|_| DomainError::infra_msg("the syslog collector did not answer in time"))?
    }

    /// Resolves, connects, shakes hands and writes `frame`.
    async fn deliver(&self, host: &str, port: u16, frame: &[u8]) -> Result<(), DomainError> {
        let addresses = self.permitted(host, port).await?;
        let name = ServerName::try_from(host.to_owned()).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-syslog-host-is-not-a",
                "the syslog host is not a name a certificate can hold"
            ))
        })?;
        let tcp = TcpStream::connect(addresses.as_slice())
            .await
            .map_err(DomainError::infra)?;
        let mut tls = self
            .tls
            .connect(name, tcp)
            .await
            .map_err(DomainError::infra)?;
        tls.write_all(frame).await.map_err(DomainError::infra)?;
        tls.flush().await.map_err(DomainError::infra)?;
        tls.shutdown().await.map_err(DomainError::infra)
    }

    /// The addresses `host` resolves to that the deployment may reach.
    async fn permitted(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DomainError> {
        let permitted: Vec<SocketAddr> = addresses_of(&self.lookup, host)
            .await
            .map_err(DomainError::infra)?
            .into_iter()
            .filter(|ip| self.networks.permits(*ip))
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        if permitted.is_empty() {
            return Err(DomainError::invalid(message!(
                "infra-the-syslog-host-resolves-to-no",
                "the syslog host resolves to no address this deployment may reach"
            )));
        }
        Ok(permitted)
    }
}

/// `record` as one RFC 5424 message: the priority, the version, its time,
/// the platform's name, its event type as the message id, and the record's
/// JSON as the text.
fn message(record: &AuditRecord) -> Result<Vec<u8>, DomainError> {
    let json = RecordJson::of(record)?;
    let time = record
        .occurred_at
        .format(&Rfc3339)
        .map_err(DomainError::infra)?;
    let msgid: String = json.event_type().chars().take(MSGID_MOST).collect();
    let mut message =
        format!("<{PRIORITY}>1 {time} {APP_NAME} {APP_NAME} - {msgid} - ").into_bytes();
    serde_json::to_writer(&mut message, &json).map_err(DomainError::infra)?;
    Ok(message)
}

/// `message` framed by octet counting: its length in bytes, a space, then
/// the message (RFC 6587, 3.4.1, as RFC 5425 requires).
fn framed(message: &[u8]) -> Vec<u8> {
    let mut frame = format!("{} ", message.len()).into_bytes();
    frame.extend_from_slice(message);
    frame
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;
    use crate::http::calls::tests::loopback;
    use crate::http::logs::streams::event::tests::record;

    /// A collector on loopback with a certificate for `localhost`, reading
    /// one connection to its end, and the roots that trust it.
    async fn collector() -> (u16, RootCertStore, tokio::task::JoinHandle<Vec<u8>>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let reading = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut read = Vec::new();
            let _ = tls.read_to_end(&mut read).await;
            read
        });
        (port, roots, reading)
    }

    /// A collector receives the record as one length-framed RFC 5424
    /// message over TLS, its JSON as the text.
    #[tokio::test]
    async fn a_collector_receives_one_framed_message() {
        let (port, roots, reading) = collector().await;
        let sender =
            SyslogSender::trusting(roots, NameLookup::Host, loopback(), Duration::from_secs(5))
                .unwrap();
        let record = record();

        sender.send("localhost", port, &record).await.unwrap();

        let received = String::from_utf8(reading.await.unwrap()).unwrap();
        let (length, message) = received.split_once(' ').unwrap();
        assert_eq!(length.parse::<usize>().unwrap(), message.len());
        assert!(message.starts_with("<110>1 2023-11-14T22:13:20Z ianua ianua - "));
        assert!(message.contains(record.event_type.as_str()));
    }

    /// A syslog host resolving to disallowed loopback addresses returns a
    /// validation error.
    #[tokio::test]
    async fn a_collector_resolving_inside_is_refused() {
        let sender = SyslogSender::trusting(
            RootCertStore::empty(),
            NameLookup::Host,
            UpstreamNetworks::public_only(),
            Duration::from_secs(5),
        )
        .unwrap();

        let result = sender.send("localhost", 6514, &record()).await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A collector certificate absent from the trusted roots makes the send
    /// return an infrastructure error.
    #[tokio::test]
    async fn an_untrusted_certificate_is_refused() {
        let (port, _, _reading) = collector().await;
        let sender = SyslogSender::trusting(
            RootCertStore::empty(),
            NameLookup::Host,
            loopback(),
            Duration::from_secs(5),
        )
        .unwrap();

        let result = sender.send("localhost", port, &record()).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A collector that accepts TCP but leaves the TLS handshake unanswered
    /// beyond the timeout makes the send return an infrastructure error.
    #[tokio::test]
    async fn a_silent_collector_is_given_up() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _held = tokio::spawn(async move {
            let accepted = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(accepted);
        });
        let sender = SyslogSender::trusting(
            RootCertStore::empty(),
            NameLookup::Host,
            loopback(),
            Duration::from_millis(200),
        )
        .unwrap();

        let result = sender.send("localhost", port, &record()).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }
}
