//! One request as the stages read it, beyond its pipeline context.
//!
//! The application's stage ports hand a stage only its settings and the
//! context. What the stages read besides (the admitted request line, the
//! headers left once the proxy's own were stripped, the body prefix the
//! pipeline asked for, the facts of the connection, the route it matched)
//! the handler gathers here once, and every group reads from this one view.

use std::sync::Arc;

use http::HeaderMap;
use ianua_app::auditor::RequestAuditor;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::stages::stage::{DecoyLifetime, ReconWindow};
use ianua_domain::domains::routing::route::Route;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::listen::ConnectionFacts;
use crate::request::{Admitted, BodyRead, ListenerRole, Scheme, SessionCookies};

/// One request, as the handler read it before the pipeline runs.
///
/// It holds no `Debug`: the headers and the body carry cookies and
/// credentials.
pub(crate) struct RequestFacts {
    /// The tenant the request's host resolved to.
    pub tenant: ScopedTenant,
    /// The request's auditor, which agent actions are recorded through.
    pub auditor: RequestAuditor,
    /// The route it matched, from the gateway's table.
    pub route: Arc<Route<ResolvedTenant>>,
    /// The host, method and canonical path the gateway admitted, the path
    /// the route matched on.
    pub admitted: Admitted,
    /// The raw query string, without its `?`, when the URL had one.
    pub query: Option<String>,
    /// The request's headers, once the proxy's own were stripped.
    pub headers: HeaderMap,
    /// What the gateway read of the body before deciding.
    pub body: BodyRead,
    /// What the route's pattern captured from the path, by name.
    pub captured: Vec<(String, String)>,
    /// Which session cookie the request's host and route let the gateway
    /// read.
    pub cookies: SessionCookies,
    /// What the connection it came on proved.
    pub connection: ConnectionFacts,
    /// How the client reached the listener it came on, from the gateway's
    /// configuration: the scheme a `DPoP` proof's address must name. It is
    /// https on the public listener whenever TLS ends at the gateway or at
    /// a trusted ingress, and on the runner listener whenever it serves
    /// TLS.
    pub scheme: Scheme,
    /// Which listener it came on: on the workflow listener a run pass is
    /// the only credential read.
    pub listener: ListenerRole,
    /// How long a client asking for this path is blocked, when the path is
    /// a decoy of any of the tenant's pipelines, from the domain's
    /// `Pipeline::decoy_lifetime_across`.
    pub decoy: Option<DecoyLifetime>,
    /// The tenant's recon window, from the domain's
    /// `Pipeline::recon_window_across`. `None` when no pipeline of the
    /// tenant scores recon.
    pub recon_window: Option<ReconWindow>,
}

impl RequestFacts {
    /// The query string, without its `?`, when the URL had one.
    #[must_use]
    pub(crate) fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// The body prefix the pipeline asked for, or `None` when none was
    /// read.
    #[must_use]
    pub(crate) fn captured_body(&self) -> Option<CapturedBody<'_>> {
        match &self.body {
            BodyRead::Unread => None,
            BodyRead::Read { prefix, extent } => Some(CapturedBody::new(prefix, *extent)),
        }
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use http::Request;
    use ianua_app::test_support::proxy::test_pipeline;
    use ianua_app::test_support::routing::{RouteShape, pinned_upstream, route_of, service_named};
    use ianua_app::test_support::{FakeEventDispatcher, test_auditor, test_ctx};
    use ianua_domain::domains::proxy::request::forwarded::ClientScheme;
    use ianua_domain::domains::routing::route::Route;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::Fact;

    use super::RequestFacts;
    use crate::listen::{ClientCertificate, ConnectionFacts, ConnectionParts};
    use crate::request::{BodyRead, ListenerRole, Scheme, SessionCookies, admit};

    /// The address every test request comes from.
    pub(crate) const CLIENT: &str = "203.0.113.7:51000";

    /// A public route on `/app` of the acme test tenant.
    pub(crate) fn app_route() -> Route<ResolvedTenant> {
        let service = service_named("app", pinned_upstream("https://backend:8080", "app"));
        route_of(
            RouteShape::public("app", "/app"),
            &service,
            &test_pipeline(),
        )
    }

    /// A connection from [`CLIENT`] whose handshake made `certificate` of
    /// the client's certificate.
    pub(crate) fn connection(certificate: ClientCertificate) -> ConnectionFacts {
        let client: SocketAddr = CLIENT.parse().unwrap();
        ConnectionFacts::new(ConnectionParts {
            client,
            peer: client,
            scheme: ClientScheme::Https,
            server_name: Fact::Unknown,
            client_certificate: certificate,
            ja4: Fact::Unknown,
        })
    }

    impl RequestFacts {
        /// `request`, as the handler hands it to the stages: admitted, for
        /// the acme test tenant on [`app_route`], its body unread, over a
        /// connection that asked for no certificate, its actions recorded
        /// nowhere anyone looks.
        pub(crate) fn sent(request: Request<()>) -> Self {
            let (mut parts, ()) = request.into_parts();
            let admitted = admit(&mut parts).unwrap();
            Self {
                tenant: test_ctx().tenant(),
                auditor: test_auditor(Arc::new(FakeEventDispatcher::new())),
                route: Arc::new(app_route()),
                admitted,
                query: parts.uri.query().map(str::to_owned),
                headers: parts.headers,
                body: BodyRead::Unread,
                captured: Vec::new(),
                cookies: SessionCookies::Platform,
                connection: connection(ClientCertificate::NotAsked),
                scheme: Scheme::Https,
                listener: ListenerRole::ByHost,
                decoy: None,
                recon_window: None,
            }
        }
    }
}
