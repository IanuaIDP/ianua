//! Where a SAML provider publishes its metadata: an HTTPS server on
//! loopback, standing at a public-looking name the stack's name server
//! answers, under a private authority the stack is told to trust
//! (`SAML_METADATA_CA_FILE`). The document it serves can be replaced at any
//! time, as a provider publishes its next key.

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair};
use tempfile::NamedTempFile;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::oidc::tls_config;
use crate::stack::Stack;
use crate::wire::Status;

/// The public-looking name the metadata stands at.
const HOST: &str = "metadata.identity.acme.example";

/// The path the document is served at.
const PATH: &str = "/saml/metadata";

/// The document being served, shared with the listener.
type Published = Arc<RwLock<String>>;

/// The metadata server, stopped on drop.
pub struct MetadataHost {
    published: Published,
    port: u16,
    authority: NamedTempFile,
    serving: JoinHandle<()>,
}

impl std::fmt::Debug for MetadataHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetadataHost")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl MetadataHost {
    /// A server on a fresh loopback port, serving nothing yet, with a
    /// self-signed certificate for its name written to a file the stack
    /// trusts.
    ///
    /// # Panics
    ///
    /// When the listener, certificate, TLS configuration or authority file
    /// cannot be made.
    /// Metadata scenarios require this listener, certificate and trust file before they run.
    #[allow(clippy::expect_used)]
    pub async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("a metadata port");
        let port = listener.local_addr().expect("an address").port();
        let key = KeyPair::generate().expect("a server key");
        let certificate = CertificateParams::new(vec![HOST.to_owned()])
            .expect("parameters")
            .self_signed(&key)
            .expect("a server certificate");
        let server = tls_config(&key, &certificate);
        let authority = NamedTempFile::new().expect("an authority file");
        std::fs::write(authority.path(), certificate.pem()).expect("write the authority");
        let published = Published::default();
        let serving = tokio::spawn(serve(
            listener,
            TlsAcceptor::from(Arc::new(server)),
            Arc::clone(&published),
        ));
        Self {
            published,
            port,
            authority,
            serving,
        }
    }

    /// The authority file the stack trusts the server's certificate by.
    ///
    /// # Panics
    ///
    /// When the temporary file's path is not UTF-8.
    /// The fixture's temporary path must be usable by the stack's text configuration.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn authority_file(&self) -> &str {
        self.authority.path().to_str().expect("a UTF-8 path")
    }

    /// The document's address, once `stack`'s name server points the
    /// server's name at loopback.
    #[must_use]
    pub fn listed(&self, stack: &Stack) -> String {
        stack.name_server().write_a(HOST, Ipv4Addr::LOCALHOST);
        format!("https://{HOST}:{}{PATH}", self.port)
    }

    /// Serves `document` from now on.
    pub fn publish(&self, document: String) {
        *self
            .published
            .write()
            .unwrap_or_else(PoisonError::into_inner) = document;
    }
}

impl Drop for MetadataHost {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// One connection at a time, each closed after its answer and bounded in
/// time.
async fn serve(listener: TcpListener, tls: TlsAcceptor, published: Published) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let published = Arc::clone(&published);
        let connection = async {
            let Ok(stream) = tls.accept(stream).await else {
                return;
            };
            let service = service_fn(move |request| respond(request, Arc::clone(&published)));
            let _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        };
        let _ = tokio::time::timeout(Duration::from_secs(10), connection).await;
    }
}

/// The published document at its path, nothing anywhere else.
async fn respond(
    request: Request<Incoming>,
    published: Published,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let document = published
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let (status, body) = match (request.uri().path(), document.is_empty()) {
        (PATH, false) => (Status::OK, document),
        _ => (Status::NOT_FOUND, String::new()),
    };
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/samlmetadata+xml"),
    );
    Ok(response)
}
