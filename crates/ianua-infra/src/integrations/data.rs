//! Protected data: the connection a step's call reaches a stream route
//! through, opened at the gateway's workflow listener with the run's pass.
//!
//! The worker dials `GATEWAY_WORKFLOW_URL`, over mutual TLS with the
//! internal authority's certificates where it serves them, and sends one
//! HTTP/1.1 `CONNECT` carrying the pass in `Proxy-Authorization`. The
//! gateway names the run's person, asks the stream route's access of them,
//! dials the route's backend, and answers `200`; from then on the
//! connection is the backend's. Nothing but the gateway's own address is
//! ever dialled, and every step of the opening is held to a time limit.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::data::{DataStream, Opener};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use url::Url;

use crate::http::client::InternalLink;

/// The most a `CONNECT`'s answer may hold before its blank line.
const MOST_ANSWER_BYTES: usize = 8 * 1024;

/// Where Protected data connections are opened, and how.
#[derive(Clone)]
pub struct DataLink {
    url: Url,
    tls: Option<LinkTls>,
    timeout: Duration,
}

/// The TLS a connection to the listener speaks, and the name its
/// certificate is checked for.
#[derive(Clone)]
struct LinkTls {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}

impl DataLink {
    /// Connections opened at `url`, the gateway's workflow listener,
    /// protected as `link` says, each opening held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address names no host
    /// and port, or the certificates do not read.
    pub fn new(url: Url, link: &InternalLink, timeout: Duration) -> Result<Self, DomainError> {
        let tls = match link {
            InternalLink::Mutual {
                authority,
                identity,
            } => Some(LinkTls {
                config: client_config(authority.as_str(), identity)?,
                name: server_name(&url)?,
            }),
            InternalLink::PlainInDevelopment => None,
        };
        Ok(Self { url, tls, timeout })
    }

    /// Connections through the gateway to the stream route `pass` names,
    /// for one call.
    #[must_use]
    pub fn opener(&self, pass: Secret) -> InstalledOpener {
        InstalledOpener {
            link: self.clone(),
            pass,
        }
    }

    /// A connection through the gateway to the stream route `pass` names.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the gateway cannot be
    /// reached, the handshake fails, the gateway refuses the `CONNECT`, or
    /// any step takes too long. The pass is never part of the error.
    pub async fn open(&self, pass: &Secret) -> Result<Box<dyn DataStream>, DomainError> {
        tokio::time::timeout(self.timeout, self.opened(pass))
            .await
            .map_err(|_| {
                DomainError::infra_msg("the gateway did not open the connection in time")
            })?
    }

    /// The connection, opened without a time limit of its own.
    async fn opened(&self, pass: &Secret) -> Result<Box<dyn DataStream>, DomainError> {
        let authority = authority_of(&self.url)?;
        let tcp = TcpStream::connect(&authority)
            .await
            .map_err(DomainError::infra)?;
        let Some(link) = &self.tls else {
            return through(tcp, &authority, pass).await;
        };
        let tls = TlsConnector::from(Arc::clone(&link.config))
            .connect(link.name.clone(), tcp)
            .await
            .map_err(DomainError::infra)?;
        through(tls, &authority, pass).await
    }
}

/// Connections to the stream route one call's pass names.
pub struct InstalledOpener {
    link: DataLink,
    pass: Secret,
}

#[async_trait]
impl Opener for InstalledOpener {
    async fn open(&self) -> Result<Box<dyn DataStream>, DomainError> {
        self.link.open(&self.pass).await
    }
}

/// `stream` once the gateway answered its `CONNECT` with `200`.
async fn through<S>(
    mut stream: S,
    authority: &str,
    pass: &Secret,
) -> Result<Box<dyn DataStream>, DomainError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        pass.expose()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(DomainError::infra)?;
    stream.flush().await.map_err(DomainError::infra)?;
    let answer = answer_head(&mut stream).await?;
    ensure_opened(&answer)?;
    Ok(Box::new(stream))
}

/// The answer's head, read one byte at a time up to its blank line, so
/// nothing of what follows it is taken.
async fn answer_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, DomainError> {
    let mut head = Vec::with_capacity(128);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MOST_ANSWER_BYTES {
            return Err(DomainError::infra_msg("the gateway's answer has no end"));
        }
        let byte = stream.read_u8().await.map_err(DomainError::infra)?;
        head.push(byte);
    }
    Ok(head)
}

/// Refuses an answer that is not `200`.
fn ensure_opened(head: &[u8]) -> Result<(), DomainError> {
    let status = head
        .split(|byte| *byte == b' ')
        .nth(1)
        .and_then(|code| std::str::from_utf8(code).ok());
    match status {
        Some("200") => Ok(()),
        Some(code) => Err(DomainError::infra_msg(format!(
            "the gateway refused the connection with {code}"
        ))),
        None => Err(DomainError::infra_msg("the gateway's answer has no status")),
    }
}

/// `url`'s `host:port`.
fn authority_of(url: &Url) -> Result<String, DomainError> {
    let host = url
        .host_str()
        .ok_or_else(|| DomainError::infra_msg("the workflow listener's address names no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| DomainError::infra_msg("the workflow listener's address names no port"))?;
    Ok(format!("{host}:{port}"))
}

/// The name the listener's certificate is checked for: `url`'s host.
fn server_name(url: &Url) -> Result<ServerName<'static>, DomainError> {
    let host = url
        .host_str()
        .ok_or_else(|| DomainError::infra_msg("the workflow listener's address names no host"))?;
    ServerName::try_from(host.trim_matches(['[', ']']).to_owned()).map_err(DomainError::infra)
}

/// TLS trusting `authority` alone and presenting `identity`, the worker's
/// certificate and key as PEM.
fn client_config(authority: &str, identity: &Secret) -> Result<Arc<ClientConfig>, DomainError> {
    let mut roots = RootCertStore::empty();
    for anchor in CertificateDer::pem_slice_iter(authority.as_bytes()) {
        roots
            .add(anchor.map_err(DomainError::infra)?)
            .map_err(DomainError::infra)?;
    }
    let chain = CertificateDer::pem_slice_iter(identity.expose().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(DomainError::infra)?;
    let key =
        PrivateKeyDer::from_pem_slice(identity.expose().as_bytes()).map_err(DomainError::infra)?;
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(DomainError::infra)?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(DomainError::infra)?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    /// The gateway answers `200`: the connection is handed on, and nothing
    /// written after the answer's blank line was taken from it.
    #[tokio::test]
    async fn an_opened_connection_is_handed_on_untouched() {
        let (client, mut gateway) = duplex(4096);
        let answering = tokio::spawn(async move {
            let head = answer_head(&mut gateway).await.unwrap();
            gateway
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nN")
                .await
                .unwrap();
            head
        });

        let mut opened = through(client, "gateway:8083", &Secret::new("a.run.pass"))
            .await
            .unwrap();
        let mut first = [0_u8; 1];
        opened.read_exact(&mut first).await.unwrap();

        let head = String::from_utf8(answering.await.unwrap()).unwrap();
        assert!(head.starts_with("CONNECT gateway:8083 HTTP/1.1\r\n"));
        assert!(head.contains("Proxy-Authorization: Bearer a.run.pass\r\n"));
        assert_eq!(&first, b"N");
    }

    /// A gateway refusal fails the CONNECT opening with its status in the error
    /// and the run's pass omitted.
    #[tokio::test]
    async fn a_refused_connect_is_an_error_without_the_pass() {
        let (client, mut gateway) = duplex(4096);
        tokio::spawn(async move {
            answer_head(&mut gateway).await.unwrap();
            gateway
                .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        });

        let refused = through(client, "gateway:8083", &Secret::new("a.run.pass")).await;

        let error = format!("{:?}", refused.err().unwrap());
        assert!(error.contains("403"), "{error}");
        assert!(!error.contains("a.run.pass"));
    }
}
