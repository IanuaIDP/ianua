//! The clients the agent's requests leave through: one to the gateway and
//! one to the platform's API, each trusting only what its destination's
//! certificate may chain to.
//!
//! The gateway inside the cluster serves a certificate of the platform's
//! internal authority, which vouches for nothing else, so the gateway's
//! client trusts that authority alone when one is named. The API is
//! reached at its own address and checked against the public roots.

use std::sync::Arc;
use std::time::Duration;

use hyper_rustls::{FixedServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use ianua_domain::shared::errors::DomainError;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::handler::RunnerBody;

/// One client the agent's requests leave through.
pub(crate) type Outbound = Client<HttpsConnector<HttpConnector>, RunnerBody>;

/// What a destination's certificate may chain to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Trust {
    /// The public roots, for the name the address holds.
    Public,
    /// Only the internal authority.
    Only(InternalAuthority),
}

/// The internal authority a destination's certificate chains to, and the
/// name it is checked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InternalAuthority {
    /// The authority's certificate, as PEM text.
    pub certificate: String,
    /// The name the destination's certificate is for, when its address
    /// names none: a runner reaches the gateway by the address of its
    /// Service, with no name lookup its pod may make. None checks the
    /// address's own host.
    pub name: Option<String>,
}

/// The clients the agent's requests leave through, one per destination.
#[derive(Clone)]
pub(crate) struct Outbounds {
    /// To the gateway: every request carrying a key-bound token.
    pub gateway: Outbound,
    /// To the platform's API: the message relay.
    pub platform: Outbound,
}

/// A client trusting `trust`, over TLS or in the clear as each address
/// says, with idle connections kept for `idle`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the authority holds no
/// certificate that reads, or TLS cannot be set up.
pub(crate) fn outbound(idle: Duration, trust: &Trust) -> Result<Outbound, DomainError> {
    let builder = hyper_rustls::HttpsConnectorBuilder::new();
    let schemes = match trust {
        Trust::Public => builder
            .with_provider_and_webpki_roots(ring::default_provider())
            .map_err(DomainError::infra)?
            .https_or_http(),
        Trust::Only(authority) => {
            let schemes = builder
                .with_tls_config(only(&authority.certificate)?)
                .https_or_http();
            match &authority.name {
                Some(name) => schemes
                    .with_server_name_resolver(FixedServerNameResolver::new(server_name(name)?)),
                None => schemes,
            }
        }
    };
    let connector = schemes.enable_http1().enable_http2().build();
    Ok(Client::builder(TokioExecutor::new())
        .pool_idle_timeout(idle)
        .pool_timer(TokioTimer::new())
        .build(connector))
}

/// TLS trusting only the authority `authority` holds.
fn only(authority: &str) -> Result<ClientConfig, DomainError> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(DomainError::infra)?
            .with_root_certificates(roots(authority)?)
            .with_no_client_auth(),
    )
}

/// `name` as the name a certificate is checked for.
fn server_name(name: &str) -> Result<ServerName<'static>, DomainError> {
    ServerName::try_from(name.to_owned()).map_err(DomainError::infra)
}

/// The certificates `authority` holds, as the only roots.
fn roots(authority: &str) -> Result<RootCertStore, DomainError> {
    let anchors = CertificateDer::pem_slice_iter(authority.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(DomainError::infra)?;
    if anchors.is_empty() {
        return Err(DomainError::infra(NoAuthority));
    }
    let mut store = RootCertStore::empty();
    for anchor in anchors {
        store.add(anchor).map_err(DomainError::infra)?;
    }
    Ok(store)
}

/// The authority's file held no certificate.
#[derive(Debug, thiserror::Error)]
#[error("the gateway's authority holds no certificate")]
struct NoAuthority;

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::SocketAddr;

    use bytes::Bytes;
    use http::{Request, Response, StatusCode};
    use http_body_util::{BodyExt as _, Empty};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use ianua_infra::crypto::{InternalListener, LinkValidity, issue_internal_pki};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::PrivateKeyDer;

    use super::*;

    /// A listener on loopback serving `chain` with `key` over TLS, as the
    /// gateway's runner listener does, answering every request `200`.
    async fn serving(chain: &str, key: &str) -> SocketAddr {
        let acceptor = acceptor(chain, key);
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = socket.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let answer = service_fn(|_| async {
                        Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), answer)
                        .await;
                });
            }
        });
        address
    }

    /// Builds the HTTP/1 TLS identity served by the test destination.
    fn acceptor(chain: &str, key: &str) -> TlsAcceptor {
        let certificates = CertificateDer::pem_slice_iter(chain.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }

    fn request(address: SocketAddr) -> Request<RunnerBody> {
        let empty = Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync();
        Request::get(format!("https://{address}/"))
            .body(empty)
            .unwrap()
    }

    /// The gateway client accepts its internal authority's certificate;
    /// the API client trusting public roots refuses that same listener.
    #[tokio::test]
    async fn the_gateway_is_trusted_through_its_authority_alone() {
        let listeners = [InternalListener {
            name: "runner-listener",
            host: "127.0.0.1",
        }];
        let pki = issue_internal_pki(&listeners, &["unused"], LinkValidity::default()).unwrap();
        let leaf = &pki.servers[0].keyed;
        let address = serving(&leaf.certificate_pem, leaf.private_key_pem.expose()).await;
        let idle = Duration::from_secs(5);
        let authority = InternalAuthority {
            certificate: pki.authority.certificate_pem.clone(),
            name: None,
        };
        let gateway = outbound(idle, &Trust::Only(authority)).unwrap();
        let platform = outbound(idle, &Trust::Public).unwrap();

        let trusted = gateway.request(request(address)).await;
        let public = platform.request(request(address)).await;

        assert_eq!(trusted.unwrap().status(), StatusCode::OK);
        assert!(public.is_err(), "the public roots refuse the certificate");
    }

    /// Reaching a gateway by address succeeds with its certificate's
    /// configured name and fails when checked against the bare address.
    #[tokio::test]
    async fn a_gateway_reached_by_address_is_checked_for_its_name() {
        let listeners = [InternalListener {
            name: "runner-listener",
            host: "ianua-zero-internal",
        }];
        let pki = issue_internal_pki(&listeners, &["unused"], LinkValidity::default()).unwrap();
        let leaf = &pki.servers[0].keyed;
        let address = serving(&leaf.certificate_pem, leaf.private_key_pem.expose()).await;
        let idle = Duration::from_secs(5);
        let trusting = |name: Option<&str>| {
            let authority = InternalAuthority {
                certificate: pki.authority.certificate_pem.clone(),
                name: name.map(str::to_owned),
            };
            outbound(idle, &Trust::Only(authority)).unwrap()
        };

        let named = trusting(Some("ianua-zero-internal"))
            .request(request(address))
            .await;
        let bare = trusting(None).request(request(address)).await;

        assert_eq!(named.unwrap().status(), StatusCode::OK);
        assert!(bare.is_err(), "the certificate names no address");
    }

    /// Building a gateway client fails when its authority text contains
    /// no certificate.
    #[test]
    fn an_authority_without_a_certificate_is_refused() {
        let built = outbound(
            Duration::from_secs(5),
            &Trust::Only(InternalAuthority {
                certificate: "not a certificate".to_owned(),
                name: None,
            }),
        );

        assert!(built.is_err());
    }

    /// A client trusting the public roots builds.
    #[test]
    fn a_client_of_the_public_roots_builds() {
        assert!(outbound(Duration::from_secs(5), &Trust::Public).is_ok());
    }
}
