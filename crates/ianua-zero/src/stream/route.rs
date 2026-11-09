//! One served stream route: what its listener asks and records for each
//! connection or flow.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ianua_app::use_cases::routing::stream_routes::{
    IdentifiedStreamCaller, StreamCallerEvidence, StreamConnection, StreamConnectionCaller,
    StreamCredential,
};
use ianua_domain::domains::routing::stream::{StreamBackend, StreamProtocol, StreamRoute};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{DomainName, TenantId};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::admission::{Admission, Gate, Shut};
use super::backend::{self, Backends, DialFailure};
use super::splice::{SpliceCounts, SpliceOutcome};
use crate::listen::{StreamHandshake, StreamTls, TerminatedStream};
use crate::observability::{StreamDecision, StreamLog, StreamRecord};

/// How often a signed-in tunnel's caller is asked about again while it
/// stays open, and how long that may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TunnelChecks {
    /// How often the token is checked again and the route asked again.
    pub every: Duration,
    /// How long one check may take before the tunnel is closed for it.
    pub timeout: Duration,
}

impl Default for TunnelChecks {
    /// Every 30 seconds, each within 5.
    fn default() -> Self {
        Self {
            every: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
        }
    }
}

/// What every served route shares: the application's answers, the
/// networks a backend may be in, the TLS ended on the ports that end it,
/// how tunnels are checked again, and where the records go.
pub(super) struct Shared {
    /// The application's answers.
    pub(super) admission: Admission,
    /// The networks a backend may be in besides public addresses.
    pub(super) networks: UpstreamNetworks,
    /// Ends TLS on the ports that end it; without it those are not served.
    pub(super) tls: Option<Arc<StreamTls>>,
    /// How a signed-in tunnel is checked again while it stays open.
    pub(super) tunnel_checks: TunnelChecks,
    /// Where each connection's record is written, when the deployment
    /// writes them.
    pub(super) records: Option<Arc<StreamLog>>,
}

/// A route as its listener serves it.
pub(super) struct ServedRoute {
    tenant: TenantId,
    route: StreamRoute<ResolvedTenant>,
    backends: Backends,
    shared: Arc<Shared>,
}

/// A backend connection, and the authority it was opened to.
pub(super) struct Dialled {
    /// The connection.
    pub(super) stream: TcpStream,
    /// Where it goes, as `host:port`.
    pub(super) authority: String,
}

impl ServedRoute {
    /// `tenant`'s `route`, served with what `shared` holds.
    pub(super) fn new(
        tenant: TenantId,
        route: StreamRoute<ResolvedTenant>,
        shared: Arc<Shared>,
    ) -> Self {
        let backends = Backends::new(route.backends().to_vec());
        Self {
            tenant,
            route,
            backends,
            shared,
        }
    }

    /// How the gateway speaks on the port.
    pub(super) fn protocol(&self) -> StreamProtocol {
        self.route.protocol()
    }

    /// The longest a backend may take to answer.
    pub(super) fn connect_limit(&self) -> Duration {
        self.route.timeouts().connect_secs().std_duration()
    }

    /// The longest a stream may carry nothing.
    pub(super) fn idle_limit(&self) -> Duration {
        self.route.timeouts().idle_secs().std_duration()
    }

    /// How a signed-in tunnel is checked again while it stays open.
    pub(super) fn tunnel_checks(&self) -> TunnelChecks {
        self.shared.tunnel_checks
    }

    /// The networks a backend may be in besides public addresses.
    pub(super) fn networks(&self) -> &UpstreamNetworks {
        &self.shared.networks
    }

    /// The next backend's `host:port`, or `None` for a route with none.
    pub(super) fn next_authority(&self) -> Option<String> {
        self.backends.pick().map(StreamBackend::authority)
    }

    /// Ends TLS on `stream`, asking what `asked` says, for the tenant whose
    /// port this is.
    ///
    /// # Errors
    ///
    /// - [`Shut::Handshake`] when the handshake is refused, or no TLS is
    ///   ended on stream ports at all.
    pub(super) async fn terminate<S>(
        &self,
        stream: S,
        asked: StreamHandshake,
    ) -> Result<TerminatedStream<S>, Shut>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Some(tls) = &self.shared.tls else {
            return Err(Shut::Handshake("tls_not_served"));
        };
        tls.terminate(stream, self.tenant, asked)
            .await
            .map_err(|refused| Shut::Handshake(refused.as_str()))
    }

    /// Who `credential`, presented on a handshake for `server_name`, names
    /// on this route.
    ///
    /// # Errors
    ///
    /// - The [`Shut`] the application's answer, or its silence, comes to.
    pub(super) async fn identify(
        &self,
        server_name: DomainName,
        credential: StreamCredential,
    ) -> Result<IdentifiedStreamCaller, Shut> {
        let evidence = StreamCallerEvidence {
            stream_route_id: *self.route.id(),
            server_name,
            credential,
        };
        self.shared
            .admission
            .identifies(self.tenant, evidence)
            .await
    }

    /// Whether `caller`, on a connection whose handshake named
    /// `server_name`, may go through. The application checks the route's
    /// server-name restriction and who it lets in.
    pub(super) async fn gate(
        &self,
        server_name: Option<DomainName>,
        caller: StreamConnectionCaller,
    ) -> Gate {
        let connection = StreamConnection {
            stream_route_id: *self.route.id(),
            server_name,
            caller,
        };
        self.shared.admission.admits(self.tenant, connection).await
    }

    /// A connection to the next backend, within the route's connect limit.
    ///
    /// # Errors
    ///
    /// - The [`DialFailure`] that stopped it.
    pub(super) async fn dial(&self) -> Result<Dialled, DialFailure> {
        let authority = self.next_authority().ok_or(DialFailure::NoBackend)?;
        let stream = backend::dial(&authority, self.networks(), self.connect_limit()).await?;
        Ok(Dialled { stream, authority })
    }

    /// The record of one connection from `peer`, accepted now.
    pub(super) fn record(&self, peer: SocketAddr) -> ConnectionRecord<'_> {
        ConnectionRecord {
            route: self,
            peer,
            server_name: None,
            caller: None,
            started: Instant::now(),
        }
    }

    /// Records that the route's listener is not relaying, for `shut`.
    pub(super) fn record_listener_shut(&self, shut: Shut) {
        tracing::warn!(
            tenant_id = %self.tenant,
            stream_route_id = %self.route.id(),
            listen_port = self.route.listen_port().get(),
            decision = "deny",
            reason = shut.as_str(),
            "stream route not relaying"
        );
    }

    /// Records that a connection or flow was turned away because the route
    /// carries all it may at once.
    pub(super) fn record_at_capacity(&self, peer: SocketAddr) {
        tracing::warn!(
            tenant_id = %self.tenant,
            stream_route_id = %self.route.id(),
            listen_port = self.route.listen_port().get(),
            peer = %peer,
            decision = "deny",
            reason = "at_capacity",
            "stream refused"
        );
    }
}

/// The one record a connection leaves: the route, who was on it, the
/// decision and why, never the bytes.
pub(super) struct ConnectionRecord<'a> {
    route: &'a ServedRoute,
    peer: SocketAddr,
    server_name: Option<DomainName>,
    caller: Option<StreamConnectionCaller>,
    started: Instant,
}

/// How a connection ended, as its record says it.
struct Ending<'a> {
    decision: StreamDecision,
    reason: &'static str,
    backend: Option<&'a str>,
    counts: SpliceCounts,
}

impl ConnectionRecord<'_> {
    /// Notes the name the connection's handshake asked for.
    pub(super) fn record_server_name(&mut self, server_name: Option<DomainName>) {
        self.server_name = server_name;
    }

    /// Notes who was named on the connection.
    pub(super) fn record_caller(&mut self, caller: StreamConnectionCaller) {
        self.caller = Some(caller);
    }

    /// The name the connection's handshake asked for.
    pub(super) fn server_name(&self) -> Option<DomainName> {
        self.server_name.clone()
    }

    /// The connection was closed before a byte of it was forwarded.
    pub(super) fn report_refusal(self, shut: Shut) {
        tracing::info!(
            tenant_id = %self.route.tenant,
            stream_route_id = %self.route.route.id(),
            listen_port = self.route.route.listen_port().get(),
            peer = %self.peer,
            server_name = self.shown_name(),
            decision = "deny",
            reason = shut.as_str(),
            "stream refused"
        );
        self.write(&Ending {
            decision: StreamDecision::Denied,
            reason: shut.as_str(),
            backend: None,
            counts: SpliceCounts::default(),
        });
    }

    /// The connection was admitted and its backend could not be reached.
    pub(super) fn unreachable(self, failure: &DialFailure) {
        tracing::warn!(
            tenant_id = %self.route.tenant,
            stream_route_id = %self.route.route.id(),
            listen_port = self.route.route.listen_port().get(),
            peer = %self.peer,
            server_name = self.shown_name(),
            decision = "allow",
            reason = failure.as_str(),
            error = %failure,
            "stream admitted but its backend was not reached"
        );
        self.write(&Ending {
            decision: StreamDecision::Allowed,
            reason: failure.as_str(),
            backend: None,
            counts: SpliceCounts::default(),
        });
    }

    /// The connection was spliced to `authority` and has ended.
    pub(super) fn report_close(
        self,
        authority: &str,
        outcome: SpliceOutcome,
        counts: SpliceCounts,
    ) {
        tracing::info!(
            tenant_id = %self.route.tenant,
            stream_route_id = %self.route.route.id(),
            listen_port = self.route.route.listen_port().get(),
            peer = %self.peer,
            server_name = self.shown_name(),
            backend = authority,
            decision = "allow",
            outcome = outcome.as_str(),
            bytes_to_backend = counts.to_backend,
            bytes_to_client = counts.to_client,
            "stream closed"
        );
        self.write(&Ending {
            decision: StreamDecision::Allowed,
            reason: outcome.as_str(),
            backend: Some(authority),
            counts,
        });
    }

    /// The name the handshake asked for, as the log shows it.
    fn shown_name(&self) -> &str {
        self.server_name.as_ref().map_or("-", DomainName::as_str)
    }

    /// Queues the connection's record, when the deployment writes them.
    fn write(self, ending: &Ending<'_>) {
        let Some(records) = &self.route.shared.records else {
            return;
        };
        records.record(StreamRecord {
            tenant_id: self.route.tenant,
            stream_route_id: *self.route.route.id(),
            listen_port: self.route.route.listen_port(),
            client: self.peer.ip(),
            server_name: self.server_name,
            caller: self.caller,
            decision: ending.decision,
            reason: ending.reason,
            backend: ending.backend.map(str::to_owned),
            bytes_to_backend: ending.counts.to_backend,
            bytes_to_client: ending.counts.to_client,
            duration_ms: u32::try_from(self.started.elapsed().as_millis()).unwrap_or(u32::MAX),
            occurred_at: OffsetDateTime::now_utc(),
        });
    }
}
