//! The pooled HTTP clients requests leave the gateway on.
//!
//! Most services share one client and so one connection pool. A backend
//! that speaks HTTP/2 on a plaintext connection is reached through a
//! second shared client that speaks it from the first byte: a pooled
//! client's protocol is fixed when it is built, and sending the HTTP/2
//! preface to an HTTP/1 backend breaks the connection. A service with TLS
//! settings of its own gets a client of its own, since trust and the
//! client certificate belong to the connection, and so does a service
//! reached through a tenant's connector, since its connections are opened
//! down that connector's links rather than from the gateway.
//!
//! Every client the gateway dials from resolves through the screen, opens
//! connections within the connect timeout, and keeps idle connections for
//! a bounded time.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_rustls::{FixedServerNameResolver, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use ianua_domain::domains::routing::backend::upstream::{PlaintextHttp2, Upstream};
use ianua_domain::domains::routing::connector::scope::UpstreamReach;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::TenantId;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use super::dial::Dial;
use super::error::PoolError;
use super::screen::ScreenedResolver;
use super::settings::ForwardSettings;
use super::tls::{self, ClientKey};
use crate::connectors::{ConnectorLinks, LinkDialer};

/// An error a request body may fail with.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A request body as the gateway forwards it.
///
/// One type whatever wrapped the body on its way in, a size limit or a
/// prefix the pipeline read, so every pool sends the same kind of request.
/// Boxing costs one allocation per request and buffers nothing.
pub(crate) type RequestBody = BoxBody<Bytes, BoxError>;

/// A pooled client, dialling through the screen or down a connector's
/// links.
pub(super) type UpstreamClient = Client<HttpsConnector<Dial>, RequestBody>;

/// How a client agrees on HTTP/2 with a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Http2 {
    /// Over TLS by ALPN; HTTP/1 otherwise.
    Negotiated,
    /// From the first byte, for a plaintext backend declared to speak it.
    PriorKnowledge,
}

impl Http2 {
    /// How `upstream`'s backends agree on HTTP/2 when it sets no TLS of its
    /// own.
    fn of(upstream: &Upstream) -> Self {
        match PlaintextHttp2::from(upstream.speaks_plaintext_http2()) {
            PlaintextHttp2::Spoken => Self::PriorKnowledge,
            PlaintextHttp2::NotSpoken => Self::Negotiated,
        }
    }
}

/// The clients every service's pool sends with.
pub(crate) struct Clients {
    standard: UpstreamClient,
    prior_knowledge: UpstreamClient,
    factory: Factory,
    links: Arc<ConnectorLinks>,
}

impl Clients {
    /// The shared clients, held to `settings`, reaching services behind a
    /// connector down the links `links` holds.
    ///
    /// # Errors
    ///
    /// - [`PoolError::Tls`] when the TLS provider refuses its own defaults,
    ///   which happens at start or not at all.
    pub(crate) fn new(
        settings: &ForwardSettings,
        links: Arc<ConnectorLinks>,
    ) -> Result<Self, PoolError> {
        let factory = Factory {
            networks: Arc::new(settings.networks.clone()),
            connect_timeout: settings.connect_timeout,
            idle_timeout: settings.pool_idle_timeout,
            max_idle: settings.pool_max_idle_per_backend,
        };
        let standard = factory.build(ClientTransport {
            config: tls::public_roots()?,
            server_name: None,
            http2: Http2::Negotiated,
            dial: factory.direct(),
        });
        let prior_knowledge = factory.build(ClientTransport {
            config: tls::public_roots()?,
            server_name: None,
            http2: Http2::PriorKnowledge,
            dial: factory.direct(),
        });
        Ok(Self {
            standard,
            prior_knowledge,
            factory,
            links,
        })
    }

    /// The networks every client dialling from the gateway is held to.
    pub(super) fn networks(&self) -> Arc<UpstreamNetworks> {
        Arc::clone(&self.factory.networks)
    }

    /// The client `tenant`'s `upstream`'s backends are reached with,
    /// presenting `key` when the upstream asks for a client certificate.
    ///
    /// # Errors
    ///
    /// Any [`PoolError`] its TLS settings raise.
    pub(super) fn for_upstream(
        &self,
        tenant: TenantId,
        upstream: &Upstream,
        key: Option<&ClientKey>,
    ) -> Result<UpstreamClient, PoolError> {
        let Some(settings) = upstream.tls() else {
            return self.without_own_tls(tenant, upstream);
        };
        let config = tls::client_config(settings, key)?;
        let server_name = tls::server_name(settings)?;
        Ok(self.factory.build(ClientTransport {
            config,
            server_name,
            http2: Http2::Negotiated,
            dial: self.dial_for(tenant, upstream),
        }))
    }

    /// The client for an upstream with no TLS settings of its own: a shared
    /// one when the gateway dials it, one of its own when a connector does.
    fn without_own_tls(
        &self,
        tenant: TenantId,
        upstream: &Upstream,
    ) -> Result<UpstreamClient, PoolError> {
        let UpstreamReach::Connector(_) = upstream.reach() else {
            return Ok(self.shared(upstream));
        };
        Ok(self.factory.build(ClientTransport {
            config: tls::public_roots()?,
            server_name: None,
            http2: Http2::of(upstream),
            dial: self.dial_for(tenant, upstream),
        }))
    }

    /// Where `tenant`'s `upstream`'s connections are opened.
    fn dial_for(&self, tenant: TenantId, upstream: &Upstream) -> Dial {
        match upstream.reach() {
            UpstreamReach::Direct => self.factory.direct(),
            UpstreamReach::Connector(connector) => Dial::Linked(LinkDialer::new(
                Arc::clone(&self.links),
                tenant,
                connector,
                self.links.open_timeout(),
            )),
        }
    }

    /// The shared client for an upstream the gateway dials with no TLS
    /// settings of its own.
    fn shared(&self, upstream: &Upstream) -> UpstreamClient {
        match Http2::of(upstream) {
            Http2::PriorKnowledge => self.prior_knowledge.clone(),
            Http2::Negotiated => self.standard.clone(),
        }
    }
}

/// What every client is built with.
struct Factory {
    networks: Arc<UpstreamNetworks>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_idle: usize,
}

/// The TLS identity, protocol and dial path fixed for one pooled client.
struct ClientTransport {
    config: ClientConfig,
    server_name: Option<ServerName<'static>>,
    http2: Http2,
    dial: Dial,
}

impl Factory {
    /// A client speaking TLS as `config` says, checking certificates
    /// against `server_name` when one is given, opening connections as
    /// `dial` does.
    fn build(&self, transport: ClientTransport) -> UpstreamClient {
        let schemes = HttpsConnectorBuilder::new()
            .with_tls_config(transport.config)
            .https_or_http();
        let schemes = match transport.server_name {
            Some(name) => schemes.with_server_name_resolver(FixedServerNameResolver::new(name)),
            None => schemes,
        };
        let connector = schemes
            .enable_http1()
            .enable_http2()
            .wrap_connector(transport.dial);
        Client::builder(TokioExecutor::new())
            .pool_idle_timeout(self.idle_timeout)
            .pool_timer(TokioTimer::new())
            .pool_max_idle_per_host(self.max_idle)
            .http2_only(transport.http2 == Http2::PriorKnowledge)
            .build(connector)
    }

    /// Dialling from the gateway over TCP, resolving through the screen.
    fn direct(&self) -> Dial {
        let resolver = ScreenedResolver::new(Arc::clone(&self.networks));
        let mut http = HttpConnector::new_with_resolver(resolver);
        http.enforce_http(false);
        http.set_connect_timeout(Some(self.connect_timeout));
        http.set_nodelay(true);
        Dial::Direct(http)
    }
}

/// A request body with nothing in it.
pub(super) fn empty_body() -> RequestBody {
    Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed()
}
