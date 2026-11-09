//! Keeping the bound ports equal to the routes the directory lists.
//!
//! At layer 4 the port is the routing key, so a route appearing means a
//! socket opening and a route going means one closing. Reconciling is by
//! port: a route whose listener-relevant settings are unchanged keeps its
//! socket and the streams on it, so renaming a route, or changing who it
//! lets in, drops nothing. Who it lets in is read again on every
//! connection anyway.
//!
//! The follower asks for a reload through [`StreamReload`]; the supervisor
//! does not poll on its own. A reload that cannot read the directory keeps
//! every port as it is, since reading nothing is no evidence that every
//! route was deleted.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::authentication::PresentedTokens;
use ianua_app::ports::routing::{StreamRouteDirectory, StreamRouteStore};
use ianua_app::use_cases::routing::stream_routes::{
    AdmitStreamConnectionUseCase, IdentifyStreamCallerUseCase,
};
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::stream::{
    ListenPort, StreamBackend, StreamPolicy, StreamProtocol, StreamRoute, StreamTimeouts,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{StreamRouteId, TenantId};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use super::admission::Admission;
use super::listener::{Carry, TcpPort};
use super::route::{ServedRoute, Shared, TunnelChecks};
use super::udp::UdpPort;
use super::workflow::DataEntry;
use crate::listen::{StreamHandshake, StreamTls};
use crate::observability::StreamLog;

/// The longest a reload waits for the directory.
const DIRECTORY_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest a closing listener is waited for to free its port.
const RELEASE_WAIT: Duration = Duration::from_secs(5);

/// The most connections one route carries at once, unless set otherwise.
///
/// A listener is a hole anyone can knock on. Without a ceiling one route
/// could use up the process's file descriptors and take the HTTP side down
/// with it; refusing the excess keeps the failure on that route.
const CONNECTIONS_PER_ROUTE: usize = 512;

/// The most UDP clients one route tracks at once, unless set otherwise.
const FLOWS_PER_ROUTE: usize = 4_096;

/// Where the supervisor learns the routes and asks about connections.
pub(crate) struct StreamSources {
    /// Every active stream route across the deployment.
    pub directory: Arc<dyn StreamRouteDirectory>,
    /// Decides every connection.
    pub admission: Arc<AdmitStreamConnectionUseCase>,
    /// Names the caller a certificate or a tunnel token stands for.
    pub identify: Arc<IdentifyStreamCallerUseCase>,
    /// Ends TLS on the ports that end it. Without it, those routes and
    /// the signed-in tunnels are left unbound.
    pub tls: Option<Arc<StreamTls>>,
    /// Where each connection's record is written, when the deployment
    /// writes them.
    pub records: Option<Arc<StreamLog>>,
}

/// How the stream listeners are bound and bounded.
#[derive(Debug, Clone)]
pub(crate) struct StreamSettings {
    /// The address every route's port is bound on.
    pub listen_on: IpAddr,
    /// The networks a backend may be in besides public addresses, checked
    /// on every connection after the backend's name resolves.
    pub networks: UpstreamNetworks,
    /// The most connections one TCP or passthrough route carries at once.
    pub connections_per_route: usize,
    /// The most clients one UDP route tracks at once.
    pub flows_per_route: usize,
    /// How a signed-in tunnel's token is checked again while it lasts.
    pub tunnel_checks: TunnelChecks,
}

impl Default for StreamSettings {
    /// Every address, public backends only, 512 connections and 4,096 UDP
    /// clients per route, a tunnel's token checked every 30 seconds.
    fn default() -> Self {
        Self {
            listen_on: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            networks: UpstreamNetworks::public_only(),
            connections_per_route: CONNECTIONS_PER_ROUTE,
            flows_per_route: FLOWS_PER_ROUTE,
            tunnel_checks: TunnelChecks::default(),
        }
    }
}

/// What one reload changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Reconciled {
    /// Ports newly listening, a changed route's included.
    pub opened: usize,
    /// Ports closed, a changed route's included.
    pub closed: usize,
    /// Ports that could not be bound, almost always held by another
    /// process. Not retried until the next reload.
    pub failed: usize,
    /// Routes left unbound: ones that end TLS, signed-in tunnels included,
    /// when the gateway was given nothing to end TLS with, and any whose
    /// protocol cannot carry what its policy checks.
    pub unserved: usize,
}

/// Why a reload changed nothing.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReloadError {
    /// The directory failed.
    #[error("the stream routes could not be read")]
    Directory(#[source] DomainError),
    /// The directory did not answer in time.
    #[error("the stream routes were not read in time")]
    TimedOut,
}

/// Asks the running supervisor to read the routes again.
///
/// The follower calls [`request`](Self::request) whenever stream routes may
/// have changed, a lost feed and its full reload included. Requests made
/// while one is waiting are taken together.
#[derive(Debug, Clone)]
pub(crate) struct StreamReload {
    requests: mpsc::Sender<()>,
}

impl StreamReload {
    /// Asks for a reload, without waiting for it.
    pub(crate) fn request(&self) {
        match self.requests.try_send(()) {
            Ok(()) | Err(TrySendError::Full(())) => {}
            Err(TrySendError::Closed(())) => {
                tracing::warn!("the stream listeners have stopped; a reload was not taken");
            }
        }
    }
}

/// The ports listening, and how to change them.
pub(crate) struct StreamSupervisor {
    directory: Arc<dyn StreamRouteDirectory>,
    shared: Arc<Shared>,
    listen_on: IpAddr,
    connections_per_route: usize,
    flows_per_route: usize,
    bound: HashMap<ListenPort, Bound>,
    listening: watch::Sender<Vec<SocketAddr>>,
    tasks: JoinSet<()>,
    root: CancellationToken,
}

/// The addresses the stream routes' ports listen on, as of the last
/// reconcile. Every holder sees the same addresses; a route that appears
/// or goes changes them.
#[derive(Debug, Clone)]
pub struct StreamPorts(watch::Receiver<Vec<SocketAddr>>);

impl StreamPorts {
    /// The addresses bound now, in no particular order.
    #[must_use]
    pub fn bound(&self) -> Vec<SocketAddr> {
        self.0.borrow().clone()
    }

    /// Waits until the bound addresses change, and answers them then; or
    /// `None` once the stream listeners have stopped.
    pub async fn changed(&mut self) -> Option<Vec<SocketAddr>> {
        self.0.changed().await.ok()?;
        Some(self.0.borrow_and_update().clone())
    }
}

/// One listening port.
struct Bound {
    fingerprint: Fingerprint,
    address: SocketAddr,
    stop: CancellationToken,
    released: oneshot::Receiver<()>,
}

impl Bound {
    /// Stops the listener and waits, for a while, for its port to be free.
    /// Streams already carried run on until they end.
    async fn release(self) {
        self.stop.cancel();
        let _ = tokio::time::timeout(RELEASE_WAIT, self.released).await;
    }
}

/// Everything about a route its listener depends on.
///
/// Not who it lets in, which every connection asks the application about,
/// and not its name. Anything that changes what the socket does is here,
/// or a tightened route would apply to new ports and not to the one
/// already listening.
#[derive(PartialEq)]
struct Fingerprint {
    tenant: TenantId,
    route: StreamRouteId,
    protocol: StreamProtocol,
    policy: StreamPolicy,
    sni: RouteHosts,
    backends: Vec<StreamBackend>,
    timeouts: StreamTimeouts,
}

impl Fingerprint {
    fn of(tenant: TenantId, route: &StreamRoute<ResolvedTenant>) -> Self {
        Self {
            tenant,
            route: *route.id(),
            protocol: route.protocol(),
            policy: route.policy(),
            sni: route.sni().clone(),
            backends: route.backends().to_vec(),
            timeouts: route.timeouts(),
        }
    }
}

/// How a served route listens.
enum Listening {
    /// Accepting TCP connections, carried as this says.
    Stream(Carry),
    /// Receiving UDP datagrams.
    Datagrams,
}

/// Why a route is left unbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unserved {
    /// It ends TLS, and the gateway was given nothing to end it with.
    NoTls,
    /// Its protocol cannot carry what its policy checks, which the domain
    /// never lets a route be.
    Undeliverable,
}

impl Unserved {
    fn as_str(self) -> &'static str {
        match self {
            Self::NoTls => "tls_not_served",
            Self::Undeliverable => "undeliverable",
        }
    }
}

/// Whether the gateway ends TLS on stream ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsOnPorts {
    /// It does.
    Ended,
    /// It was given nothing to end TLS with.
    NotEnded,
}

/// How `route` listens, or why it is not served.
///
/// The match is on the pair, exhaustively, so a new protocol or policy is
/// a compile error here rather than a route that is listed and silently
/// carries nothing.
fn listening_for(
    route: &StreamRoute<ResolvedTenant>,
    tls: TlsOnPorts,
) -> Result<Listening, Unserved> {
    let carry = match (route.protocol(), route.policy()) {
        (StreamProtocol::Tcp | StreamProtocol::TlsPassthrough, StreamPolicy::Public) => {
            return Ok(Listening::Stream(Carry::Raw));
        }
        (StreamProtocol::Udp, StreamPolicy::Public) => return Ok(Listening::Datagrams),
        (StreamProtocol::TlsTerminate, StreamPolicy::Public) => {
            Carry::Terminated(StreamHandshake::Terminate)
        }
        (StreamProtocol::TlsTerminate, StreamPolicy::MutualTls) => {
            Carry::Terminated(StreamHandshake::MutualTls)
        }
        (StreamProtocol::Tcp, StreamPolicy::Tunnel) => Carry::Tunnel,
        (
            StreamProtocol::Tcp | StreamProtocol::TlsPassthrough | StreamProtocol::Udp,
            StreamPolicy::MutualTls,
        )
        | (
            StreamProtocol::TlsTerminate | StreamProtocol::TlsPassthrough | StreamProtocol::Udp,
            StreamPolicy::Tunnel,
        ) => return Err(Unserved::Undeliverable),
    };
    match tls {
        TlsOnPorts::Ended => Ok(Listening::Stream(carry)),
        TlsOnPorts::NotEnded => Err(Unserved::NoTls),
    }
}

/// Why a wanted route did not get a listener.
enum OpenFailure {
    Unserved(Unserved),
    Bind(io::Error),
}

/// The routes the directory lists, by port.
type Wanted = HashMap<ListenPort, (TenantId, StreamRoute<ResolvedTenant>)>;

/// What opening the missing ports came to.
#[derive(Default)]
struct Opened {
    opened: usize,
    failed: usize,
    unserved: usize,
}

/// The route and lifetime signals handed to a newly bound port.
struct PortStart {
    address: SocketAddr,
    served: Arc<ServedRoute>,
    stop: CancellationToken,
    released: oneshot::Sender<()>,
}

impl StreamSupervisor {
    /// A supervisor with nothing bound, reading routes from `sources` and
    /// binding them as `settings` says.
    #[must_use]
    pub(crate) fn new(sources: StreamSources, settings: StreamSettings) -> Self {
        let StreamSettings {
            listen_on,
            networks,
            connections_per_route,
            flows_per_route,
            tunnel_checks,
        } = settings;
        let shared = Shared {
            admission: Admission::new(sources.admission, sources.identify),
            networks,
            tls: sources.tls,
            tunnel_checks,
            records: sources.records,
        };
        Self {
            directory: sources.directory,
            shared: Arc::new(shared),
            listen_on,
            connections_per_route,
            flows_per_route,
            bound: HashMap::new(),
            listening: watch::Sender::new(Vec::new()),
            tasks: JoinSet::new(),
            root: CancellationToken::new(),
        }
    }

    /// The workflow listener's way into stream routes, deciding with the
    /// same answers, networks, checks and records as every route's port,
    /// reading routes from `routes` and passes' claims through `passes`.
    #[must_use]
    pub(crate) fn data_entry(
        &self,
        routes: Arc<dyn StreamRouteStore>,
        passes: Arc<dyn PresentedTokens>,
    ) -> DataEntry {
        DataEntry::new(Arc::clone(&self.shared), routes, passes)
    }

    /// The addresses the routes' ports listen on, kept current as routes
    /// come and go.
    #[must_use]
    pub(crate) fn ports(&self) -> StreamPorts {
        StreamPorts(self.listening.subscribe())
    }

    /// How many ports are listening.
    #[must_use]
    pub(crate) fn bound_ports(&self) -> usize {
        self.bound.len()
    }

    /// Starts serving under `shutdown`: binds the routes now, again on
    /// every request made through the returned [`StreamReload`], and on
    /// stop frees every port and waits for the streams in flight, for as
    /// long as the shutdown's grace allows.
    #[must_use]
    pub(crate) fn start(self, shutdown: &Shutdown) -> StreamReload {
        let (requests, received) = mpsc::channel(1);
        shutdown.spawn("stream listeners", self.run(shutdown.stopping(), received));
        StreamReload { requests }
    }

    /// Brings the bound ports in line with the directory.
    ///
    /// A port that fails to bind is counted and logged, never retried in a
    /// loop: the usual cause is another process holding it, which trying
    /// again at once will not change.
    ///
    /// # Errors
    ///
    /// - [`ReloadError::Directory`] or [`ReloadError::TimedOut`] when the
    ///   routes cannot be read. Every port is left as it was.
    pub(crate) async fn reconcile(&mut self) -> Result<Reconciled, ReloadError> {
        let wanted = self.wanted().await?;
        let closed = self.close_stale(&wanted).await;
        let opened = self.open_missing(wanted).await;
        Ok(Reconciled {
            opened: opened.opened,
            closed,
            failed: opened.failed,
            unserved: opened.unserved,
        })
    }

    /// The routes the directory lists, by port.
    async fn wanted(&self) -> Result<Wanted, ReloadError> {
        let listed = tokio::time::timeout(DIRECTORY_TIMEOUT, self.directory.active_routes())
            .await
            .map_err(|_| ReloadError::TimedOut)?
            .map_err(ReloadError::Directory)?;
        Ok(listed
            .into_iter()
            .map(|(tenant, route)| (route.listen_port(), (tenant, route)))
            .collect())
    }

    /// Closes every port whose route is gone or changed, and says how many.
    async fn close_stale(&mut self, wanted: &Wanted) -> usize {
        let stale: Vec<ListenPort> = self
            .bound
            .iter()
            .filter(|(port, bound)| !still_wanted(wanted, **port, &bound.fingerprint))
            .map(|(port, _)| *port)
            .collect();
        for port in &stale {
            let Some(bound) = self.bound.remove(port) else {
                continue;
            };
            bound.release().await;
        }
        stale.len()
    }

    /// Opens a port for every wanted route not listening yet.
    async fn open_missing(&mut self, wanted: Wanted) -> Opened {
        let missing: Vec<_> = wanted
            .into_iter()
            .filter(|(port, _)| !self.bound.contains_key(port))
            .collect();
        let mut opened = Opened::default();
        for (port, (tenant, route)) in missing {
            match self.open(port, tenant, route).await {
                Ok(bound) => {
                    self.bound.insert(port, bound);
                    opened.opened += 1;
                }
                Err(OpenFailure::Unserved(why)) => {
                    record_unserved(tenant, port, why);
                    opened.unserved += 1;
                }
                Err(OpenFailure::Bind(error)) => {
                    record_unbound(tenant, port, &error);
                    opened.failed += 1;
                }
            }
        }
        opened
    }

    /// Binds `tenant`'s `route` on `port` and starts serving it.
    async fn open(
        &mut self,
        port: ListenPort,
        tenant: TenantId,
        route: StreamRoute<ResolvedTenant>,
    ) -> Result<Bound, OpenFailure> {
        let listening =
            listening_for(&route, self.tls_on_ports()).map_err(OpenFailure::Unserved)?;
        let fingerprint = Fingerprint::of(tenant, &route);
        let address = SocketAddr::new(self.listen_on, port.get());
        let served = Arc::new(ServedRoute::new(tenant, route, Arc::clone(&self.shared)));
        let stop = self.root.child_token();
        let (released, on_release) = oneshot::channel();
        let address = self
            .start_port(
                listening,
                PortStart {
                    address,
                    served,
                    stop: stop.clone(),
                    released,
                },
            )
            .await
            .map_err(OpenFailure::Bind)?;
        Ok(Bound {
            fingerprint,
            address,
            stop,
            released: on_release,
        })
    }

    /// Binds the selected transport and tracks its task until the listener releases it.
    async fn start_port(
        &mut self,
        listening: Listening,
        start: PortStart,
    ) -> io::Result<SocketAddr> {
        let PortStart {
            address,
            served,
            stop,
            released,
        } = start;
        match listening {
            Listening::Stream(carry) => {
                let listener = TcpListener::bind(address).await?;
                let bound = listener.local_addr()?;
                let tcp = TcpPort::new(listener, served, carry, self.connections_per_route);
                self.tasks.spawn(tcp.serve(stop, released));
                Ok(bound)
            }
            Listening::Datagrams => {
                let socket = UdpSocket::bind(address).await?;
                let bound = socket.local_addr()?;
                let udp = UdpPort::new(socket, served, self.flows_per_route);
                self.tasks.spawn(udp.serve(stop, released));
                Ok(bound)
            }
        }
    }

    /// Whether TLS is ended on stream ports.
    fn tls_on_ports(&self) -> TlsOnPorts {
        match self.shared.tls {
            Some(_) => TlsOnPorts::Ended,
            None => TlsOnPorts::NotEnded,
        }
    }

    /// Serves until `stopping`, reloading on every request.
    async fn run(
        mut self,
        stopping: WaitForCancellationFutureOwned,
        mut requests: mpsc::Receiver<()>,
    ) {
        self.reload().await;
        tokio::pin!(stopping);
        loop {
            tokio::select! {
                () = &mut stopping => break,
                Some(()) = requests.recv() => self.reload().await,
            }
        }
        self.stop_all().await;
    }

    /// Reconciles, and records what changed or why nothing did.
    async fn reload(&mut self) {
        match self.reconcile().await {
            Ok(summary) if summary == Reconciled::default() => {}
            Ok(summary) => tracing::info!(
                opened = summary.opened,
                closed = summary.closed,
                failed = summary.failed,
                unserved = summary.unserved,
                listening = self.bound_ports(),
                "stream routes reconciled"
            ),
            Err(error) => tracing::error!(
                %error,
                listening = self.bound_ports(),
                "stream routes not read; the ports already bound stay"
            ),
        }
        while self.tasks.try_join_next().is_some() {}
        self.publish_bound();
    }

    /// Tells every [`StreamPorts`] holder the addresses bound now.
    fn publish_bound(&self) {
        let addresses: Vec<SocketAddr> = self.bound.values().map(|bound| bound.address).collect();
        self.listening.send_replace(addresses);
    }

    /// Frees every port and waits for the streams in flight to end.
    async fn stop_all(mut self) {
        tracing::info!(ports = self.bound_ports(), "closing stream route listeners");
        self.root.cancel();
        while self.tasks.join_next().await.is_some() {}
    }
}

/// Whether the route listed on `port` is still the one bound there.
fn still_wanted(wanted: &Wanted, port: ListenPort, bound: &Fingerprint) -> bool {
    wanted
        .get(&port)
        .is_some_and(|(tenant, route)| Fingerprint::of(*tenant, route) == *bound)
}

/// Records a route left unbound, and why.
fn record_unserved(tenant: TenantId, port: ListenPort, why: Unserved) {
    tracing::warn!(
        tenant_id = %tenant,
        listen_port = port.get(),
        reason = why.as_str(),
        "stream route not bound"
    );
}

/// Records a port that could not be bound.
fn record_unbound(tenant: TenantId, port: ListenPort, error: &io::Error) {
    tracing::error!(
        tenant_id = %tenant,
        listen_port = port.get(),
        %error,
        "stream route port not bound"
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use ianua_app::ports::authentication::{
        AppSessionClaim, AppSessionToken, ClaimedPass, ClaimedToken, ExpectedSession,
        ExpectedToken, IssuedUnder, PersonToken, PresentedTokens, RunPassToken, TenantToken,
        TokenFault, TokenReading,
    };
    use ianua_app::ports::authorization::AccessRecords;
    use ianua_app::ports::routing::{PolicyDecision, StreamRouteStore};
    use ianua_app::tenancy::ScopedTenant;
    use ianua_app::test_support::authentication::FakeAppSessionCheck;
    use ianua_app::test_support::authorization::FakeAccessRecordStore;
    use ianua_app::test_support::identity::FakeUserStore;
    use ianua_app::test_support::routing::{
        FakePolicyDecisionPoint, FakeStreamRouteStore, routing_admin, routing_label,
    };
    use ianua_app::test_support::test_ctx;
    use ianua_app::use_cases::proxy::credentials::{
        AuthenticatePorts, AuthenticateUseCase, PersonPorts,
    };
    use ianua_app::use_cases::routing::stream_routes::{
        AdmitStreamConnectionPorts, IdentifyStreamCallerPorts,
    };
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::stream::CreateStreamRouteParams;
    use ianua_domain::domains::routing::stream::access::StreamAccess;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Fact, Issuer, Seconds, ServiceId, SessionId, UserId};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::listen::stream_tls_fixtures::{Authority, Ports, authority, ports, server_name};

    /// The name the tenant's stream ports answer on in these tests.
    const NAME: &str = "db.acme.test";

    /// Reads every bearer token as a person's, until told it expired.
    struct Expiring {
        person: UserId,
        expired: AtomicBool,
    }

    impl Expiring {
        fn token(&self) -> TenantToken {
            TenantToken::Person(PersonToken {
                user_id: self.person,
                scopes: Vec::new(),
                assurance: Fact::Known(AssuranceLevel::Aal2),
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
                issued_under: IssuedUnder::AppSession(AppSessionClaim {
                    session_id: SessionId::new(),
                    user_id: self.person,
                    service_id: ServiceId::new(),
                    idle_timeout: None,
                    signed_in_from: Fact::Unknown,
                }),
                claims: Vec::new(),
            })
        }
    }

    #[async_trait]
    impl PresentedTokens for Expiring {
        fn claimed(&self, _: &Secret) -> Option<ClaimedToken> {
            None
        }

        async fn read_bearer(
            &self,
            _: &ScopedTenant,
            _: &Secret,
            _: ExpectedToken<'_>,
        ) -> Result<TokenReading<TenantToken>, DomainError> {
            if self.expired.load(Ordering::SeqCst) {
                return Ok(TokenReading::Refused(TokenFault::Expired));
            }
            Ok(TokenReading::Read(self.token()))
        }

        async fn read_app_session(
            &self,
            _: &ScopedTenant,
            _: &Secret,
            _: ExpectedSession<'_>,
        ) -> Result<TokenReading<AppSessionToken>, DomainError> {
            Ok(TokenReading::Refused(TokenFault::Invalid))
        }

        fn claimed_pass(&self, _: &Secret) -> Option<ClaimedPass> {
            None
        }

        async fn read_run_pass(
            &self,
            _: &ScopedTenant,
            _: &Secret,
            _: &Issuer,
        ) -> Result<TokenReading<RunPassToken>, DomainError> {
            Ok(TokenReading::Refused(TokenFault::Invalid))
        }
    }

    #[derive(Default)]
    struct FakeDirectory {
        routes: Mutex<Vec<(TenantId, StreamRoute<ResolvedTenant>)>>,
        failing: AtomicBool,
    }

    #[async_trait]
    impl StreamRouteDirectory for FakeDirectory {
        async fn active_routes(
            &self,
        ) -> Result<Vec<(TenantId, StreamRoute<ResolvedTenant>)>, DomainError> {
            if self.failing.load(Ordering::SeqCst) {
                return Err(DomainError::infra_msg("the directory is unreachable"));
            }
            Ok(self.routes.lock().expect("the lock").clone())
        }
    }

    struct World {
        directory: Arc<FakeDirectory>,
        store: Arc<FakeStreamRouteStore>,
        tenant: TenantId,
        tokens: Arc<Expiring>,
        tls: Option<Ports>,
    }

    impl World {
        fn new() -> Self {
            Self::of(TenantId::new())
        }

        fn of(tenant: TenantId) -> Self {
            Self {
                directory: Arc::new(FakeDirectory::default()),
                store: Arc::new(FakeStreamRouteStore::empty()),
                tenant,
                tokens: Arc::new(Expiring {
                    person: UserId::new(),
                    expired: AtomicBool::new(false),
                }),
                tls: None,
            }
        }

        /// The world of the tenant every app test acts in, whose stream
        /// ports end TLS for [`NAME`].
        fn ending_tls() -> Self {
            let tenant = test_ctx().tenant_id();
            Self {
                tls: Some(ports(tenant, NAME, "db.globex.test")),
                ..Self::of(tenant)
            }
        }

        /// The TLS this world's ports end.
        fn tls(&self) -> &Ports {
            self.tls.as_ref().expect("this world ends TLS")
        }

        fn supervisor(&self, settings: StreamSettings) -> StreamSupervisor {
            let sources = StreamSources {
                directory: Arc::<FakeDirectory>::clone(&self.directory),
                admission: Arc::new(self.admission()),
                identify: Arc::new(self.identify()),
                tls: self.tls.as_ref().map(|ports| Arc::clone(&ports.tls)),
                records: None,
            };
            StreamSupervisor::new(sources, settings)
        }

        fn admission(&self) -> AdmitStreamConnectionUseCase {
            AdmitStreamConnectionUseCase::new(AdmitStreamConnectionPorts {
                stream_route_store: Arc::<FakeStreamRouteStore>::clone(&self.store),
                policy_decisions: Arc::new(FakePolicyDecisionPoint::deciding(
                    PolicyDecision::Permit,
                )),
            })
        }

        /// Names callers the way the gateway does: certificates no
        /// consumer holds as unnamed, tokens as [`Expiring`] reads them,
        /// for a person who may sign in.
        fn identify(&self) -> IdentifyStreamCallerUseCase {
            let users = FakeUserStore::with_user(self.tokens.person, "ann@acme.test");
            let records = FakeAccessRecordStore::holding(self.tenant, AccessRecords::default());
            let credentials = AuthenticateUseCase::new(AuthenticatePorts {
                tokens: Arc::<Expiring>::clone(&self.tokens),
                access_records: Arc::new(records),
                people: PersonPorts {
                    user_store: Arc::new(users),
                    app_sessions: Arc::new(FakeAppSessionCheck(AtomicBool::new(true))),
                    ..PersonPorts::fakes()
                },
                ..AuthenticatePorts::fakes()
            });
            IdentifyStreamCallerUseCase::new(IdentifyStreamCallerPorts {
                stream_route_store: Arc::<FakeStreamRouteStore>::clone(&self.store),
                credentials: Arc::new(credentials),
                ..IdentifyStreamCallerPorts::fakes()
            })
        }

        /// Lists `route` in the directory, and keeps `stored` as the
        /// tenant's record of it.
        async fn publish(
            &self,
            route: StreamRoute<ResolvedTenant>,
            stored: StreamRoute<ResolvedTenant>,
        ) {
            self.store
                .save(&ScopedTenant::for_test(self.tenant), &stored)
                .await
                .expect("the route is saved");
            self.directory
                .routes
                .lock()
                .expect("the lock")
                .push((self.tenant, route));
        }

        async fn open(&self, route: StreamRoute<ResolvedTenant>) {
            self.publish(route.clone(), route).await;
        }

        fn withdraw_all(&self) {
            self.directory.routes.lock().expect("the lock").clear();
        }
    }

    fn local(connections: usize, flows: usize) -> StreamSettings {
        StreamSettings {
            listen_on: IpAddr::V4(Ipv4Addr::LOCALHOST),
            networks: UpstreamNetworks::parse_list("127.0.0.0/8").expect("a valid range"),
            connections_per_route: connections,
            flows_per_route: flows,
            tunnel_checks: TunnelChecks {
                every: Duration::from_millis(50),
                timeout: Duration::from_secs(1),
            },
        }
    }

    fn route(
        port: u16,
        backend_port: u16,
        protocol: StreamProtocol,
        policy: StreamPolicy,
    ) -> StreamRoute<ResolvedTenant> {
        StreamRoute::create(
            CreateStreamRouteParams {
                name: routing_label(&format!("stream-{port}")),
                protocol,
                listen_port: ListenPort::new(port).expect("a valid port"),
                sni: RouteHosts::Any,
                policy,
                access: StreamAccess::AnyHolder,
                backends: vec![
                    StreamBackend::new("127.0.0.1", backend_port, 1).expect("a backend"),
                ],
                timeouts: StreamTimeouts::new(Seconds::new(1), Seconds::new(60))
                    .expect("valid timeouts"),
            },
            &routing_admin(),
        )
        .expect("a routing admin opens the port")
    }

    /// The signed-in tunnel on `port` to the local `backend_port`, for
    /// people who are signed in.
    fn people_tunnel(port: u16, backend_port: u16) -> StreamRoute<ResolvedTenant> {
        let mut tunnel = public_tcp(port, backend_port);
        tunnel
            .change_admission(
                StreamPolicy::Tunnel,
                StreamAccess::People(RoutePolicy::Authenticated),
                &routing_admin(),
            )
            .expect("a routing admin moves the port behind the tunnel");
        tunnel
    }

    fn public_tcp(port: u16, backend_port: u16) -> StreamRoute<ResolvedTenant> {
        route(
            port,
            backend_port,
            StreamProtocol::Tcp,
            StreamPolicy::Public,
        )
    }

    async fn free_port() -> u16 {
        let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        probe.local_addr().expect("address").port()
    }

    async fn echo_backend() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reading, mut writing) = stream.split();
                    let _ = tokio::io::copy(&mut reading, &mut writing).await;
                });
            }
        });
        port
    }

    /// A backend that counts the connections it accepts.
    async fn counting_backend() -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counting = Arc::clone(&accepted);
        tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                counting.fetch_add(1, Ordering::SeqCst);
            }
        });
        (port, accepted)
    }

    async fn silent_backend() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        port
    }

    async fn eventually(mut check: impl FnMut() -> bool) -> bool {
        for _ in 0..200 {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    fn listening(port: u16) -> bool {
        std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
    }

    /// Whether the gateway closed the connection, by an end of stream or a
    /// reset, without sending anything.
    async fn closed_by_gateway(client: &mut TcpStream) -> bool {
        let mut seen = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut seen)).await;
        read.is_ok() && seen.is_empty()
    }

    #[tokio::test]
    async fn an_admitted_connection_reaches_its_backend() {
        let world = World::new();
        let port = free_port().await;
        world.open(public_tcp(port, echo_backend().await)).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let mut client = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        client.write_all(b"ping").await.expect("write");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.expect("read");

        assert_eq!(&echoed, b"ping");
    }

    /// Ann disabled the port; the directory has not caught up yet. The
    /// application refuses the connection, and the gateway closes it
    /// without reaching the backend.
    #[tokio::test]
    async fn a_refused_admission_closes_the_connection() {
        let world = World::new();
        let port = free_port().await;
        let (backend_port, reached) = counting_backend().await;
        let listed = public_tcp(port, backend_port);
        let mut disabled = listed.clone();
        disabled.disable(&routing_admin()).expect("disabled");
        world.publish(listed, disabled).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let mut client = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");

        assert!(closed_by_gateway(&mut client).await);
        assert_eq!(reached.load(Ordering::SeqCst), 0);
    }

    /// The tenant's record of the route is gone. No route, no admission:
    /// the connection is closed.
    #[tokio::test]
    async fn a_route_the_application_does_not_know_closes_the_connection() {
        let world = World::new();
        let port = free_port().await;
        let backend = echo_backend().await;
        world
            .directory
            .routes
            .lock()
            .expect("the lock")
            .push((world.tenant, public_tcp(port, backend)));
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let mut client = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");

        assert!(closed_by_gateway(&mut client).await);
    }

    #[tokio::test]
    async fn a_connection_past_the_ceiling_is_closed() {
        let world = World::new();
        let port = free_port().await;
        world.open(public_tcp(port, silent_backend().await)).await;
        let mut supervisor = world.supervisor(local(1, 8));
        supervisor.reconcile().await.expect("reconciled");

        let mut first = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        first.write_all(b"hold").await.expect("write");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut second = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");

        assert!(closed_by_gateway(&mut second).await);
    }

    #[tokio::test]
    async fn a_removed_route_stops_its_listener() {
        let world = World::new();
        let port = free_port().await;
        world.open(public_tcp(port, echo_backend().await)).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        world.withdraw_all();
        let summary = supervisor.reconcile().await.expect("reconciled");

        assert_eq!(summary.closed, 1);
        assert_eq!(supervisor.bound_ports(), 0);
        assert!(
            eventually(|| !listening(port)).await,
            "the port stayed open"
        );
    }

    #[tokio::test]
    async fn an_unchanged_route_keeps_its_listener() {
        let world = World::new();
        let port = free_port().await;
        world.open(public_tcp(port, echo_backend().await)).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let summary = supervisor.reconcile().await.expect("reconciled");

        assert_eq!(summary, Reconciled::default());
        assert_eq!(supervisor.bound_ports(), 1);
    }

    #[tokio::test]
    async fn a_route_moved_to_another_backend_is_bound_again() {
        let world = World::new();
        let port = free_port().await;
        let first = public_tcp(port, echo_backend().await);
        world.open(first.clone()).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let mut moved = first;
        let elsewhere =
            StreamBackend::new("127.0.0.1", echo_backend().await, 1).expect("a backend");
        moved
            .replace_backends(vec![elsewhere], &routing_admin())
            .expect("moved");
        world.withdraw_all();
        world
            .directory
            .routes
            .lock()
            .expect("the lock")
            .push((world.tenant, moved));
        let summary = supervisor.reconcile().await.expect("reconciled");

        assert_eq!((summary.closed, summary.opened), (1, 1));
        assert_eq!(supervisor.bound_ports(), 1);
    }

    /// A port that checks client certificates cannot be served by a gateway
    /// given nothing to end TLS with, so it stays shut rather than open to
    /// anyone.
    #[tokio::test]
    async fn a_client_certificate_route_is_not_bound_without_tls() {
        let world = World::new();
        let port = free_port().await;
        let mutual = route(
            port,
            5432,
            StreamProtocol::TlsTerminate,
            StreamPolicy::MutualTls,
        );
        world.open(mutual).await;
        let mut supervisor = world.supervisor(local(8, 8));

        let summary = supervisor.reconcile().await.expect("reconciled");

        assert_eq!(summary.unserved, 1);
        assert!(!listening(port));
    }

    type ClientTls = tokio_rustls::client::TlsStream<TcpStream>;

    /// A client of the world's TLS, connected to `port` and through its
    /// handshake, presenting `presenting`'s certificate when given.
    async fn tls_client(
        world: &World,
        port: u16,
        presenting: Option<&Authority>,
        protocols: &[&[u8]],
    ) -> std::io::Result<ClientTls> {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
        let connector = world.tls().client(presenting, protocols);
        connector.connect(server_name(NAME), tcp).await
    }

    /// Opens the tunnel on `port`, with `token` when given, and answers
    /// with the connection and the response head the gateway sent.
    async fn open_tunnel(world: &World, port: u16, token: Option<&str>) -> (ClientTls, String) {
        let mut tls = tls_client(world, port, None, &[b"http/1.1"])
            .await
            .expect("the handshake");
        let authorization = token
            .map(|token| format!("Proxy-Authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        let request = format!("CONNECT db:5432 HTTP/1.1\r\nHost: db:5432\r\n{authorization}\r\n");
        tls.write_all(request.as_bytes())
            .await
            .expect("the CONNECT is sent");
        let head = response_head(&mut tls).await;
        (tls, head)
    }

    /// The response head the gateway sent, up to its blank line.
    async fn response_head(tls: &mut ClientTls) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let read = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut byte)).await;
            let Ok(Ok(1)) = read else {
                break;
            };
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    /// The billing device presents a certificate from Acme's authority on
    /// the mutual-TLS port. It is named, admitted and spliced through.
    #[tokio::test]
    async fn a_certificate_from_the_tenants_authority_reaches_the_backend() {
        let world = World::ending_tls();
        let acme = authority("acme CA");
        world.tls().trust(&acme);
        let port = free_port().await;
        let backend = echo_backend().await;
        world
            .open(route(
                port,
                backend,
                StreamProtocol::TlsTerminate,
                StreamPolicy::MutualTls,
            ))
            .await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let mut client = tls_client(&world, port, Some(&acme), &[])
            .await
            .expect("the handshake");
        client.write_all(b"ping").await.expect("write");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.expect("read");

        assert_eq!(&echoed, b"ping");
    }

    /// A certificate from an untrusted authority on Acme's mutual-TLS port
    /// returns no application bytes and opens no backend connection.
    #[tokio::test]
    async fn a_refused_certificate_never_reaches_the_backend() {
        let world = World::ending_tls();
        world.tls().trust(&authority("acme CA"));
        let port = free_port().await;
        let (backend_port, reached) = counting_backend().await;
        world
            .open(route(
                port,
                backend_port,
                StreamProtocol::TlsTerminate,
                StreamPolicy::MutualTls,
            ))
            .await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let mallory = authority("mallory CA");
        let mut seen = Vec::new();
        if let Ok(mut client) = tls_client(&world, port, Some(&mallory), &[]).await {
            let _ = client.write_all(b"ping").await;
            let wait = Duration::from_secs(2);
            let _ = tokio::time::timeout(wait, client.read_to_end(&mut seen)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(seen.is_empty());
        assert_eq!(reached.load(Ordering::SeqCst), 0);
    }

    /// Ann opens the signed-in tunnel with her token. The gateway answers
    /// `200`, and the stream inside reaches the backend.
    #[tokio::test]
    async fn a_signed_in_tunnel_reaches_its_backend() {
        let world = World::ending_tls();
        let port = free_port().await;
        world.open(people_tunnel(port, echo_backend().await)).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let (mut tunnel, head) = open_tunnel(&world, port, Some("anns.token")).await;
        tunnel.write_all(b"ping").await.expect("write");
        let mut echoed = [0u8; 4];
        tunnel.read_exact(&mut echoed).await.expect("read");

        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(&echoed, b"ping");
    }

    /// After a tunnel carries bytes, marking its token expired makes the
    /// connection end within the deadline without returning more bytes.
    #[tokio::test]
    async fn a_token_that_expires_mid_tunnel_closes_it() {
        let world = World::ending_tls();
        let port = free_port().await;
        world.open(people_tunnel(port, echo_backend().await)).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");
        let (mut tunnel, _) = open_tunnel(&world, port, Some("anns.token")).await;
        tunnel.write_all(b"ping").await.expect("write");
        let mut echoed = [0u8; 4];
        tunnel.read_exact(&mut echoed).await.expect("read");

        world.tokens.expired.store(true, Ordering::SeqCst);
        let mut rest = Vec::new();
        let wait = Duration::from_secs(5);
        let closed = tokio::time::timeout(wait, tunnel.read_to_end(&mut rest)).await;

        assert!(
            closed.is_ok(),
            "the tunnel stayed open after its token expired"
        );
        assert!(rest.is_empty());
    }

    /// Opening a tunnel without a token returns 407 and opens no backend
    /// connection.
    #[tokio::test]
    async fn a_tunnel_without_a_token_is_asked_for_one() {
        let world = World::ending_tls();
        let port = free_port().await;
        let (backend_port, reached) = counting_backend().await;
        world.open(people_tunnel(port, backend_port)).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let (_, head) = open_tunnel(&world, port, None).await;

        assert!(head.starts_with("HTTP/1.1 407"), "{head}");
        assert_eq!(reached.load(Ordering::SeqCst), 0);
    }

    /// Opening a tunnel with a token already marked expired returns 403
    /// and opens no backend connection.
    #[tokio::test]
    async fn a_tunnel_with_an_expired_token_is_refused() {
        let world = World::ending_tls();
        world.tokens.expired.store(true, Ordering::SeqCst);
        let port = free_port().await;
        let (backend_port, reached) = counting_backend().await;
        world.open(people_tunnel(port, backend_port)).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        let (_, head) = open_tunnel(&world, port, Some("anns.token")).await;

        assert!(head.starts_with("HTTP/1.1 403"), "{head}");
        assert_eq!(reached.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_failing_directory_keeps_the_ports_bound() {
        let world = World::new();
        let port = free_port().await;
        world.open(public_tcp(port, echo_backend().await)).await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        world.directory.failing.store(true, Ordering::SeqCst);
        let reloaded = supervisor.reconcile().await;

        assert!(matches!(reloaded, Err(ReloadError::Directory(_))));
        assert_eq!(supervisor.bound_ports(), 1);
    }

    #[tokio::test]
    async fn a_port_held_elsewhere_is_counted_and_the_rest_still_bind() {
        let world = World::new();
        let taken = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let taken_port = taken.local_addr().expect("address").port();
        let free = free_port().await;
        let backend = echo_backend().await;
        world.open(public_tcp(taken_port, backend)).await;
        world.open(public_tcp(free, backend)).await;
        let mut supervisor = world.supervisor(local(8, 8));

        let summary = supervisor.reconcile().await.expect("reconciled");

        assert_eq!((summary.failed, summary.opened), (1, 1));
    }

    #[tokio::test]
    async fn a_reload_request_binds_a_new_route_and_a_stop_frees_every_port() {
        let world = World::new();
        let shutdown = Shutdown::new(Duration::from_secs(2));
        let reload = world.supervisor(local(8, 8)).start(&shutdown);
        let port = free_port().await;

        world.open(public_tcp(port, echo_backend().await)).await;
        reload.request();
        assert!(
            eventually(|| listening(port)).await,
            "the reload bound nothing"
        );

        shutdown.stop();
        shutdown.join().await.expect("the listeners stop");
        assert!(!listening(port), "the port stayed open after the stop");
    }

    async fn udp_echo_backend() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("address").port();
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
                let _ = socket.send_to(&buffer[..len], from).await;
            }
        });
        port
    }

    async fn free_udp_port() -> u16 {
        let probe = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        probe.local_addr().expect("address").port()
    }

    async fn round_trip(port: u16) -> Option<Vec<u8>> {
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        client.connect(("127.0.0.1", port)).await.expect("connect");
        let mut buffer = [0u8; 512];
        for _ in 0..20 {
            client.send(b"ping").await.expect("send");
            let answered =
                tokio::time::timeout(Duration::from_millis(100), client.recv(&mut buffer)).await;
            if let Ok(Ok(len)) = answered {
                return Some(buffer[..len].to_vec());
            }
        }
        None
    }

    #[tokio::test]
    async fn a_datagram_reaches_its_backend_and_the_reply_comes_back() {
        let world = World::new();
        let port = free_udp_port().await;
        let backend = udp_echo_backend().await;
        world
            .open(route(
                port,
                backend,
                StreamProtocol::Udp,
                StreamPolicy::Public,
            ))
            .await;
        let mut supervisor = world.supervisor(local(8, 8));
        supervisor.reconcile().await.expect("reconciled");

        assert_eq!(round_trip(port).await.as_deref(), Some(&b"ping"[..]));
    }

    #[tokio::test]
    async fn a_client_past_the_flow_bound_is_not_relayed() {
        let world = World::new();
        let port = free_udp_port().await;
        let backend = udp_echo_backend().await;
        world
            .open(route(
                port,
                backend,
                StreamProtocol::Udp,
                StreamPolicy::Public,
            ))
            .await;
        let mut supervisor = world.supervisor(local(8, 1));
        supervisor.reconcile().await.expect("reconciled");

        let first = round_trip(port).await;
        let second = round_trip(port).await;

        assert!(first.is_some());
        assert_eq!(second, None);
    }
}
