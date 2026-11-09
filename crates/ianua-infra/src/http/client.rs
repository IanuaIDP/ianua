//! The clients every outbound call is made with: bounded in time, never
//! following a redirect, and, for an address a tenant chose, screened
//! after it resolves.
//!
//! A webhook target, a model provider's endpoint and an identity
//! provider's token endpoint are all instructions to make a request from
//! inside the deployment's network. Screening a URL when it is registered
//! catches only an IP written out: a name is resolved later, and whoever
//! controls the name controls what it resolves to by then. So the
//! [`screened`] client's resolver drops every address the deployment may
//! not reach, at each connection, and a name left with none fails. A
//! redirect is a fresh address nothing screened, so it is never followed.
//! Nor does a screened call go through a proxy the environment names, such
//! as `HTTPS_PROXY`: the proxy would resolve the tenant's name itself, and
//! no address would be screened at all. A screened client may look names
//! up through the recursive resolvers the deployment names rather than
//! the host's, and may trust one private authority instead of the public
//! roots; it screens what they answer all the same.
//!
//! Webhooks, signal pushes, audit streams, message pushes and notification
//! posts all take the one client [`DeliveryReach`] builds. Left unset it
//! is the [`screened`] client exactly, with public roots and the host's
//! names; a deployment that sets one up for its tests also trusts one
//! authority and asks its named resolvers, and nothing about it changes
//! which addresses are screened out.
//!
//! A call to an address the platform itself chose, such as a cloud
//! provider's or a payment provider's API, goes through a [`fixed`] client:
//! bounded in time, no redirects, no screening of names it was configured
//! with.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use der::Encode as _;
use hickory_resolver::TokioResolver;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::CertificatePem;
use ianua_integration::ServiceReach;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::crypto::certificates::pem::certificate_in;
use crate::dns::{LookupBounds, address_resolver};

/// How long any outbound call may take before it is given up, unless its
/// caller chose a shorter time.
pub(crate) const LONGEST_CALL: Duration = Duration::from_secs(30);

/// A client for addresses a tenant chose: every name it resolves is
/// screened against `networks`, no proxy is used, and each call is held to
/// `timeout`.
///
/// A URL naming an IP address is never resolved, so the caller refuses an
/// address `networks` does not permit with [`ensure_reachable`] before it
/// calls.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built.
pub fn screened(
    timeout: Duration,
    networks: UpstreamNetworks,
) -> Result<reqwest::Client, DomainError> {
    screened_through(timeout, networks, NameLookup::Host, Trust::PublicRoots)
}

/// Where a screened client looks up the names it calls.
#[derive(Clone, Default)]
pub enum NameLookup {
    /// As the host does.
    #[default]
    Host,
    /// Through the recursive resolvers the deployment names.
    Resolvers(Arc<TokioResolver>),
}

impl NameLookup {
    /// Through the resolvers at `nameservers`, or as the host does when
    /// there are none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the resolver cannot be
    /// built.
    pub fn asking(nameservers: &[SocketAddr]) -> Result<Self, DomainError> {
        if nameservers.is_empty() {
            return Ok(Self::Host);
        }
        let resolver = address_resolver(nameservers, LookupBounds::default())?;
        Ok(Self::Resolvers(Arc::new(resolver)))
    }
}

/// Which authorities a screened client trusts.
#[derive(Clone)]
pub enum Trust {
    /// Built-in certificate authorities trusted for ordinary HTTPS services.
    PublicRoots,
    /// This root alone, so no public authority can stand in for it.
    Only(reqwest::Certificate),
    /// The built-in authorities and this root beside them.
    Also(reqwest::Certificate),
}

impl Trust {
    /// The private authority `authority` alone.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it holds no certificate
    /// that can be read.
    pub fn only_authority(authority: &CertificatePem) -> Result<Self, DomainError> {
        root_of(authority).map(Self::Only)
    }
}

/// The certificate in `authority`, as a root a client trusts.
fn root_of(authority: &CertificatePem) -> Result<reqwest::Certificate, DomainError> {
    reqwest::Certificate::from_der(&der_of(authority)?).map_err(DomainError::infra)
}

/// The DER bytes of the certificate in `authority`.
fn der_of(authority: &CertificatePem) -> Result<Vec<u8>, DomainError> {
    let certificate = certificate_in(authority.as_str()).map_err(DomainError::infra)?;
    certificate.to_der().map_err(DomainError::infra)
}

/// How a webhook, signal push, audit stream, message push or notification
/// post reaches the address a tenant chose, written once so every one of
/// them behaves alike.
///
/// Left as [`Default`], Tess's webhook to `https://hooks.acme.example` is
/// looked up by the host and trusted only by a public certificate, which
/// is every deployment running in production. A scenario proving what
/// Acme's server really receives sets one up with
/// [`also_trusting`](Self::also_trusting), naming its own authority and
/// name server; the address is then screened by `UPSTREAM_NETWORKS` as
/// before, so a private or loopback address is reached only where that
/// setting lists it.
#[derive(Clone, Default)]
pub struct DeliveryReach {
    lookup: NameLookup,
    extra_root: Option<Arc<[u8]>>,
}

impl std::fmt::Debug for DeliveryReach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryReach")
            .field("extra_root", &self.extra_root.is_some())
            .finish_non_exhaustive()
    }
}

impl DeliveryReach {
    /// Reach that looks names up as `lookup` says and trusts `authority`
    /// beside the public roots.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `authority` holds no
    /// certificate that can be read.
    pub fn also_trusting(
        lookup: NameLookup,
        authority: &CertificatePem,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            lookup,
            extra_root: Some(der_of(authority)?.into()),
        })
    }

    /// The screened client these deliveries post through, each call held
    /// to `timeout` and every name screened against `networks`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be built.
    pub(crate) fn client(
        &self,
        timeout: Duration,
        networks: UpstreamNetworks,
    ) -> Result<reqwest::Client, DomainError> {
        screened_through(timeout, networks, self.lookup.clone(), self.trust()?)
    }

    /// How names are looked up, for a sender that dials them itself.
    pub(crate) fn lookup(&self) -> NameLookup {
        self.lookup.clone()
    }

    /// The certificate roots a TLS sender trusts: the public ones, and the
    /// extra one when one was set up.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the extra root is not a
    /// certificate rustls can read.
    pub(crate) fn tls_roots(&self) -> Result<RootCertStore, DomainError> {
        let mut roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let Some(extra) = &self.extra_root else {
            return Ok(roots);
        };
        roots
            .add(CertificateDer::from(extra.to_vec()))
            .map_err(DomainError::infra)?;
        Ok(roots)
    }

    /// What an integration needs to reach its service the same way: names
    /// screened by `networks` when this reach names its own authority, the
    /// ordinary client otherwise.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the extra root is not a
    /// certificate that can be read.
    pub fn service_reach(&self, networks: UpstreamNetworks) -> Result<ServiceReach, DomainError> {
        let Some(extra) = &self.extra_root else {
            return Ok(ServiceReach::default());
        };
        let screening = ScreeningResolver {
            networks,
            lookup: self.lookup.clone(),
        };
        let root = reqwest::Certificate::from_der(extra).map_err(DomainError::infra)?;
        Ok(ServiceReach::through(Arc::new(screening), root))
    }

    /// Which authorities this reach's client trusts.
    fn trust(&self) -> Result<Trust, DomainError> {
        let Some(extra) = &self.extra_root else {
            return Ok(Trust::PublicRoots);
        };
        reqwest::Certificate::from_der(extra)
            .map(Trust::Also)
            .map_err(DomainError::infra)
    }
}

/// How calls to a listener of the platform's own inside the deployment's
/// network are protected: the gateway's workflow listener, or the API's
/// relay listener.
#[derive(Debug, Clone)]
pub enum InternalLink {
    /// Mutual TLS: the listener's certificate must chain to `authority`,
    /// and every call presents `identity`, the caller's certificate and key
    /// as PEM.
    Mutual {
        /// The internal authority.
        authority: CertificatePem,
        /// The caller's certificate and key.
        identity: Secret,
    },
    /// Plain HTTP, outside production.
    PlainInDevelopment,
}

impl InternalLink {
    /// The client calls go through, each held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the certificates do not
    /// read or the client cannot be built.
    pub fn client(&self, timeout: Duration) -> Result<reqwest::Client, DomainError> {
        match self {
            Self::Mutual {
                authority,
                identity,
            } => mutual(timeout, authority, identity),
            Self::PlainInDevelopment => fixed(timeout),
        }
    }
}

/// A client for a listener of the platform's own inside the deployment's
/// network, over mutual TLS: trusting `authority` alone, presenting
/// `identity`, a certificate and its key as PEM, each call held to
/// `timeout`, following no redirect.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the authority or the identity
/// does not read, or the client cannot be built.
pub fn mutual(
    timeout: Duration,
    authority: &CertificatePem,
    identity: &Secret,
) -> Result<reqwest::Client, DomainError> {
    let identity =
        reqwest::Identity::from_pem(identity.expose().as_bytes()).map_err(DomainError::infra)?;
    reqwest::Client::builder()
        .timeout(timeout.min(LONGEST_CALL))
        .connect_timeout(timeout.min(LONGEST_CALL))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(root_of(authority)?)
        .identity(identity)
        .build()
        .map_err(DomainError::infra)
}

/// A client for addresses a tenant chose, screened as [`screened`] is,
/// looking names up as `lookup` says and trusting as `trust` says.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built.
pub(crate) fn screened_through(
    timeout: Duration,
    networks: UpstreamNetworks,
    lookup: NameLookup,
    trust: Trust,
) -> Result<reqwest::Client, DomainError> {
    let builder = reqwest::Client::builder()
        .timeout(timeout.min(LONGEST_CALL))
        .connect_timeout(timeout.min(LONGEST_CALL))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(Arc::new(ScreeningResolver { networks, lookup }));
    let builder = match trust {
        Trust::PublicRoots => builder,
        Trust::Only(root) => builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(root),
        Trust::Also(root) => builder.add_root_certificate(root),
    };
    builder.build().map_err(DomainError::infra)
}

/// A client for addresses the platform itself chose, each call held to
/// `timeout`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built.
pub fn fixed(timeout: Duration) -> Result<reqwest::Client, DomainError> {
    reqwest::Client::builder()
        .timeout(timeout.min(LONGEST_CALL))
        .connect_timeout(timeout.min(LONGEST_CALL))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(DomainError::infra)
}

/// A client for an address a tenant chose that serves a certificate from
/// their own authority: screened as [`screened`] is, and trusting `root`
/// alone, so no public authority can stand in for theirs.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built.
pub(crate) fn screened_trusting(
    timeout: Duration,
    networks: UpstreamNetworks,
    root: reqwest::Certificate,
) -> Result<reqwest::Client, DomainError> {
    screened_through(timeout, networks, NameLookup::Host, Trust::Only(root))
}

/// Refuses `url` when it names an IP address `networks` does not permit.
/// A name is screened when it resolves, by the [`screened`] client.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the URL names no host, or an IP
/// address the deployment may not reach.
pub fn ensure_reachable(url: &url::Url, networks: &UpstreamNetworks) -> Result<(), DomainError> {
    let ip = match url.host() {
        None => {
            return Err(DomainError::invalid(message!(
                "infra-the-address-names-no-host",
                "the address names no host"
            )));
        }
        Some(url::Host::Domain(_)) => return Ok(()),
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
    };
    if !networks.permits(ip) {
        return Err(DomainError::invalid(message!(
            "infra-the-address-is-one-this-deployment",
            "the address is one this deployment may not reach"
        )));
    }
    Ok(())
}

pub use ianua_integration::answer::body_within;

/// Resolves names as `lookup` says, then keeps only the addresses
/// `networks` permits. A name left with none fails to resolve.
struct ScreeningResolver {
    networks: UpstreamNetworks,
    lookup: NameLookup,
}

impl reqwest::dns::Resolve for ScreeningResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let networks = self.networks.clone();
        let lookup = self.lookup.clone();
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let permitted: Vec<SocketAddr> = addresses_of(&lookup, &host)
                .await?
                .into_iter()
                .filter(|ip| networks.permits(*ip))
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();
            if permitted.is_empty() {
                return Err(ScreenedOut { host }.into());
            }
            Ok(Box::new(permitted.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The addresses `host` resolves to, looked up as `lookup` says; through
/// the deployment's resolvers as a fully qualified name, so no search
/// domain is tried in its place.
///
/// # Errors
///
/// When the lookup fails.
pub(crate) async fn addresses_of(lookup: &NameLookup, host: &str) -> std::io::Result<Vec<IpAddr>> {
    match lookup {
        NameLookup::Host => Ok(tokio::net::lookup_host((host, 0))
            .await?
            .map(|address| address.ip())
            .collect()),
        NameLookup::Resolvers(resolver) => Ok(resolver
            .lookup_ip(format!("{}.", host.trim_end_matches('.')))
            .await
            .map_err(std::io::Error::other)?
            .iter()
            .collect()),
    }
}

/// A name the [`screened`] client would not connect to: every address it
/// resolves to is one the deployment may not reach.
#[derive(Debug, thiserror::Error)]
#[error("{host} resolves to no address this deployment may reach")]
struct ScreenedOut {
    host: String,
}

/// Whether `error` is the [`screened`] client refusing a name that resolves
/// only to addresses the deployment may not reach, rather than the network
/// failing. A port reports the first as a refused address and the second as
/// a failed call.
pub(crate) fn refused_by_screen(error: &reqwest::Error) -> bool {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = cause {
        if current.is::<ScreenedOut>() {
            return true;
        }
        cause = current.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::CidrRange;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// The loopback networks, which the mock servers listen on.
    fn loopback() -> UpstreamNetworks {
        UpstreamNetworks::new(vec![
            CidrRange::new("127.0.0.0/8").unwrap(),
            CidrRange::new("::1/128").unwrap(),
        ])
    }

    /// The mock's address by name, so the request goes through the resolver.
    fn by_name(server: &MockServer, route: &str) -> String {
        format!("{}{route}", server.uri().replace("127.0.0.1", "localhost"))
    }

    async fn answering(route: &str, response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// A hostname resolving only to disallowed loopback addresses produces
    /// a screening refusal, and the server receives no request.
    #[tokio::test]
    async fn a_name_resolving_inside_the_deployment_is_not_reached() {
        let server = answering("/ok", ResponseTemplate::new(200)).await;
        let client = screened(Duration::from_secs(5), UpstreamNetworks::public_only()).unwrap();

        let result = client.get(by_name(&server, "/ok")).send().await;

        assert!(result.as_ref().is_err_and(refused_by_screen));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A name that does not resolve at all is a failed call, not a refused
    /// address, so a port does not tell an administrator their endpoint is
    /// internal when it is only down.
    #[tokio::test]
    async fn a_name_that_does_not_resolve_is_not_read_as_refused() {
        let client = screened(Duration::from_secs(5), UpstreamNetworks::public_only()).unwrap();

        let result = client.get("http://nowhere.invalid/").send().await;

        assert!(
            result
                .as_ref()
                .is_err_and(|error| !refused_by_screen(error))
        );
    }

    /// A self-hosted deployment lists its own network, and is reached there.
    #[tokio::test]
    async fn a_network_the_deployment_lists_is_reached() {
        let server = answering("/ok", ResponseTemplate::new(200)).await;
        let client = screened(Duration::from_secs(5), loopback()).unwrap();

        let response = client.get(by_name(&server, "/ok")).send().await.unwrap();

        assert_eq!(response.status().as_u16(), 200);
    }

    /// A redirect to the metadata address returns the original HTTP 302
    /// response.
    #[tokio::test]
    async fn a_redirect_is_never_followed() {
        let server = answering(
            "/start",
            ResponseTemplate::new(302)
                .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
        )
        .await;
        let client = screened(Duration::from_secs(5), loopback()).unwrap();

        let response = client.get(by_name(&server, "/start")).send().await.unwrap();

        assert_eq!(response.status().as_u16(), 302);
    }

    /// Address validation refuses a literal metadata IP while accepting a
    /// hostname for later resolution screening.
    #[test]
    fn an_address_written_out_is_screened_too() {
        let metadata = url::Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        let named = url::Url::parse("https://hooks.example.com/in").unwrap();

        assert!(ensure_reachable(&metadata, &UpstreamNetworks::public_only()).is_err());
        assert!(ensure_reachable(&named, &UpstreamNetworks::public_only()).is_ok());
    }

    /// The full name of [`a_call_made_under_a_proxy_in_the_environment`],
    /// which the test harness is asked to run alone.
    const UNDER_A_PROXY: &str = "http::client::tests::a_call_made_under_a_proxy_in_the_environment";

    /// A child test process configured with HTTP proxy variables fails to
    /// resolve its target directly, and the proxy receives no request.
    #[tokio::test]
    async fn a_proxy_in_the_environment_is_never_used() {
        let proxy = answering("/ok", ResponseTemplate::new(200)).await;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", UNDER_A_PROXY, "--ignored"])
            .env("HTTP_PROXY", proxy.uri())
            .env("http_proxy", proxy.uri())
            .env_remove("NO_PROXY")
            .env_remove("no_proxy");

        let ran = tokio::task::spawn_blocking(move || child.output())
            .await
            .unwrap()
            .unwrap();

        assert!(ran.status.success(), "{ran:?}");
        assert!(
            String::from_utf8_lossy(&ran.stdout).contains("1 passed"),
            "{ran:?}"
        );
        assert!(proxy.received_requests().await.unwrap().is_empty());
    }

    /// The call [`a_proxy_in_the_environment_is_never_used`] makes under a
    /// proxy: a name that resolves nowhere fails, rather than going to the
    /// proxy to be resolved there.
    #[tokio::test]
    #[ignore = "run by a_proxy_in_the_environment_is_never_used with a proxy named"]
    async fn a_call_made_under_a_proxy_in_the_environment() {
        let client = screened(Duration::from_secs(5), UpstreamNetworks::public_only()).unwrap();

        let result = client.get("http://hooks.example.test/ok").send().await;

        assert!(result.is_err());
    }

    /// Reading a response body larger than the supplied byte limit returns
    /// an error.
    #[tokio::test]
    async fn a_body_past_its_limit_is_refused() {
        let server = answering(
            "/big",
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 2048]),
        )
        .await;
        let client = screened(Duration::from_secs(5), loopback()).unwrap();
        let response = client.get(by_name(&server, "/big")).send().await.unwrap();

        let read = body_within(response, 1024).await;

        assert!(read.is_err());
    }

    /// A TLS server on loopback, under a certificate for `localhost` that
    /// no public authority signed, answering every request with `200`.
    struct PrivateServer {
        port: u16,
        authority: CertificatePem,
        serving: tokio::task::JoinHandle<()>,
    }

    impl Drop for PrivateServer {
        fn drop(&mut self) {
            self.serving.abort();
        }
    }

    impl PrivateServer {
        async fn start() -> Self {
            let key = rcgen::KeyPair::generate().unwrap();
            let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let chain = vec![certificate.der().clone()];
            let private =
                tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
            let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
            let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, private.into())
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let serving = tokio::spawn(serve_tls(listener, acceptor));
            Self {
                port,
                authority: CertificatePem::new(certificate.pem()).unwrap(),
                serving,
            }
        }

        fn url(&self) -> String {
            format!("https://localhost:{}/", self.port)
        }
    }

    /// Answers each connection `200` after it reads the request's first
    /// bytes.
    async fn serve_tls(listener: tokio::net::TcpListener, acceptor: tokio_rustls::TlsAcceptor) {
        while let Ok((stream, _)) = listener.accept().await {
            let Ok(mut tls) = acceptor.accept(stream).await else {
                continue;
            };
            let mut request = [0_u8; 1024];
            let _ = tls.read(&mut request).await;
            let answer = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            let _ = tls.write_all(answer).await;
            let _ = tls.shutdown().await;
        }
    }

    /// With no reach set up, a call to a server under a private authority
    /// fails at the handshake, exactly as a screened client always did.
    #[tokio::test]
    async fn an_unset_reach_trusts_only_the_public_roots() {
        let server = PrivateServer::start().await;
        let client = DeliveryReach::default()
            .client(Duration::from_secs(5), loopback())
            .unwrap();

        let result = client.get(server.url()).send().await;

        assert!(
            result
                .as_ref()
                .is_err_and(|error| !refused_by_screen(error))
        );
    }

    /// With no reach set up, a name resolving to loopback is screened out
    /// on a deployment that did not list loopback.
    #[tokio::test]
    async fn an_unset_reach_screens_names_as_screened_does() {
        let server = answering("/ok", ResponseTemplate::new(200)).await;
        let client = DeliveryReach::default()
            .client(Duration::from_secs(5), UpstreamNetworks::public_only())
            .unwrap();

        let result = client.get(by_name(&server, "/ok")).send().await;

        assert!(result.as_ref().is_err_and(refused_by_screen));
    }

    /// With the deployment's own authority set up, Acme's receiver under
    /// it is reached.
    #[tokio::test]
    async fn an_extra_authority_is_trusted_beside_the_public_roots() {
        let server = PrivateServer::start().await;
        let reach = DeliveryReach::also_trusting(NameLookup::Host, &server.authority).unwrap();
        let client = reach.client(Duration::from_secs(5), loopback()).unwrap();

        let response = client.get(server.url()).send().await.unwrap();

        assert_eq!(response.status().as_u16(), 200);
    }

    /// Trusting an extra authority widens no address: a name resolving to
    /// loopback is still screened out where loopback is not listed.
    #[tokio::test]
    async fn an_extra_authority_reaches_no_new_address() {
        let server = PrivateServer::start().await;
        let reach = DeliveryReach::also_trusting(NameLookup::Host, &server.authority).unwrap();
        let client = reach
            .client(Duration::from_secs(5), UpstreamNetworks::public_only())
            .unwrap();

        let result = client.get(server.url()).send().await;

        assert!(result.as_ref().is_err_and(refused_by_screen));
    }

    /// A TLS sender's roots are the public ones until an extra one is set
    /// up, which then stands beside them.
    #[tokio::test]
    async fn an_extra_authority_is_added_to_the_tls_roots() {
        let server = PrivateServer::start().await;
        let unset = DeliveryReach::default().tls_roots().unwrap();
        let reach = DeliveryReach::also_trusting(NameLookup::Host, &server.authority).unwrap();

        let set = reach.tls_roots().unwrap();

        assert_eq!(unset.len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert_eq!(set.len(), unset.len() + 1);
    }

    /// An unset reach leaves an integration on its ordinary client: a
    /// server under a private authority still fails the handshake.
    #[tokio::test]
    async fn an_unset_reach_changes_nothing_for_an_integration() {
        let server = PrivateServer::start().await;
        let reach = DeliveryReach::default()
            .service_reach(UpstreamNetworks::public_only())
            .unwrap();
        let client = ianua_integration::client_reaching(Duration::from_secs(5), &reach).unwrap();

        let result = client.get(server.url()).send().await;

        assert!(result.is_err());
    }

    /// A reach set up lets an integration reach a service under the extra
    /// authority, its name screened against the deployment's networks.
    #[tokio::test]
    async fn a_set_reach_carries_the_authority_to_an_integration() {
        let server = PrivateServer::start().await;
        let reach = DeliveryReach::also_trusting(NameLookup::Host, &server.authority)
            .unwrap()
            .service_reach(loopback())
            .unwrap();
        let client = ianua_integration::client_reaching(Duration::from_secs(5), &reach).unwrap();

        let response = client.get(server.url()).send().await.unwrap();

        assert_eq!(response.status().as_u16(), 200);
    }
}
