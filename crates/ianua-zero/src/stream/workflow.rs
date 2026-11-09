//! The workflow listener's way into a stream route: a Protected data
//! step's `CONNECT`, carrying its run's pass in `Proxy-Authorization`,
//! reaches the one stream route the pass names as the person its run acts
//! for, and is spliced to its backend.
//!
//! It is decided exactly as a signed-in tunnel on the route's own port is:
//! the application names the pass's person, taking the pass only for the
//! stream route it was made for while that route is open to workflows, and
//! the route's access is asked of them. Only then is the backend dialled
//! and the `200` sent. Where the `CONNECT` asks to go is not read: the pass
//! names the route, and the route names its backends. The tunnel closes
//! when the pass lapses, a minute after it was made, or when a check finds
//! the person no longer let through, and it leaves one record like every
//! stream connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::header::PROXY_AUTHENTICATE;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use ianua_app::ports::authentication::{PassReach, PresentedTokens};
use ianua_app::ports::routing::StreamRouteStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_cases::routing::stream_routes::{
    IdentifiedStreamCaller, StreamCallerRefusal, StreamCredential, StreamRefusal,
};
use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DomainName, StreamRouteId, TenantId};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::admission::{Gate, Shut};
use super::backend::DialFailure;
use super::route::{ConnectionRecord, Dialled, ServedRoute, Shared};
use super::splice::{SpliceOutcome, expiring, splice};
use super::tunnel::bearer_of;

/// The most workflow tunnels open at once, across every tenant.
const MOST_TUNNELS: usize = 64;

/// The longest reading a stream route and deciding a `CONNECT` may take.
const DECIDE_TIMEOUT: Duration = Duration::from_secs(10);

/// The name a workflow's connection is checked under: it ends no TLS of a
/// tenant's, so it asks for no server name of one, and a stream route that
/// answers only some names lets it in under none of them.
const WORKFLOW_SERVER_NAME: &str = "workflows.ianua.invalid";

/// The workflow listener's way into stream routes.
pub(crate) struct DataEntry {
    shared: Arc<Shared>,
    routes: Arc<dyn StreamRouteStore>,
    passes: Arc<dyn PresentedTokens>,
    permits: Arc<Semaphore>,
}

/// Why a workflow tunnel was not opened.
enum NotOpened {
    /// It was refused, for this reason.
    Shut(Shut),
    /// It was admitted and its backend could not be reached.
    Unreachable(DialFailure),
}

impl From<Shut> for NotOpened {
    fn from(shut: Shut) -> Self {
        Self::Shut(shut)
    }
}

/// A `CONNECT` the route admitted: its route, its backend, and whom the
/// pass names.
struct Admitted {
    served: ServedRoute,
    backend: Dialled,
    named: IdentifiedStreamCaller,
    pass: Secret,
    permit: OwnedSemaphorePermit,
}

impl DataEntry {
    /// The entry deciding with what `shared` holds, reading stream routes
    /// from `routes` and passes' claims through `passes`.
    pub(super) fn new(
        shared: Arc<Shared>,
        routes: Arc<dyn StreamRouteStore>,
        passes: Arc<dyn PresentedTokens>,
    ) -> Self {
        Self {
            shared,
            routes,
            passes,
            permits: Arc::new(Semaphore::new(MOST_TUNNELS)),
        }
    }

    /// The answer to `request`, a `CONNECT` from `peer` on the workflow
    /// listener. Once it is admitted the tunnel is spliced on a task of its
    /// own, as the client switches.
    pub(crate) async fn connect(
        &self,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> Response<Empty<Bytes>> {
        let decided = tokio::time::timeout(DECIDE_TIMEOUT, self.decide(&request, peer)).await;
        let admitted = match decided {
            Ok(Ok(admitted)) => admitted,
            Ok(Err(status)) => return refusal(status),
            Err(_) => return refusal(StatusCode::SERVICE_UNAVAILABLE),
        };
        let upgrade = hyper::upgrade::on(request);
        tokio::spawn(async move {
            let Ok(switched) = upgrade.await else {
                tracing::debug!("a workflow tunnel's client did not switch");
                return;
            };
            carry(admitted, TokioIo::new(switched), peer).await;
        });
        Response::new(Empty::new())
    }

    /// Whether `request` opens a tunnel, or the status it is refused with.
    async fn decide(
        &self,
        request: &Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<Admitted, StatusCode> {
        if request.method() != Method::CONNECT {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }
        let pass = bearer_of(request.headers()).ok_or(StatusCode::PROXY_AUTHENTICATION_REQUIRED)?;
        let claimed = self
            .passes
            .claimed_pass(&pass)
            .ok_or(StatusCode::PROXY_AUTHENTICATION_REQUIRED)?;
        let PassReach::StreamRoute(stream_route_id) = claimed.reaches else {
            return Err(StatusCode::FORBIDDEN);
        };
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let route = self.route(claimed.tenant_id, &stream_route_id).await?;
        let served = ServedRoute::new(claimed.tenant_id, route, Arc::clone(&self.shared));
        let (named, backend) = admit_and_dial(&served, peer, pass.clone()).await?;
        Ok(Admitted {
            served,
            backend,
            named,
            pass,
            permit,
        })
    }

    /// The active stream route `id` of `tenant`, or the status a missing,
    /// disabled or unreadable one is refused with.
    async fn route(
        &self,
        tenant: TenantId,
        id: &StreamRouteId,
    ) -> Result<StreamRoute<ResolvedTenant>, StatusCode> {
        let scoped = ScopedTenant::from_verified_credential(tenant);
        let read = self.routes.find_by_id(&scoped, id).await;
        let route = read.map_err(|error| {
            tracing::warn!(%error, "a stream route could not be read for a workflow");
            StatusCode::SERVICE_UNAVAILABLE
        })?;
        route
            .filter(StreamRoute::is_active)
            .ok_or(StatusCode::FORBIDDEN)
    }
}

/// Records an admission or dial failure before returning its public status.
async fn admit_and_dial(
    served: &ServedRoute,
    peer: SocketAddr,
    pass: Secret,
) -> Result<(IdentifiedStreamCaller, Dialled), StatusCode> {
    let mut record = served.record(peer);
    match admitted(served, &mut record, pass).await {
        Ok(admitted) => Ok(admitted),
        Err(NotOpened::Shut(shut)) => {
            record.report_refusal(shut);
            Err(status_of(shut))
        }
        Err(NotOpened::Unreachable(failure)) => {
            record.unreachable(&failure);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

/// The person `pass` names on `served`, once its access lets them in, and
/// a connection to its backend.
async fn admitted(
    served: &ServedRoute,
    record: &mut ConnectionRecord<'_>,
    pass: Secret,
) -> Result<(IdentifiedStreamCaller, Dialled), NotOpened> {
    let named = served
        .identify(workflow_server_name()?, StreamCredential::RunPass(pass))
        .await?;
    record.record_caller(named.caller.clone());
    if let Gate::Closed(shut) = served.gate(None, named.caller.clone()).await {
        return Err(shut.into());
    }
    let backend = served.dial().await.map_err(NotOpened::Unreachable)?;
    Ok((named, backend))
}

/// Splices an admitted tunnel for as long as its pass and the route still
/// let its person through, and records how it ended.
async fn carry(
    admitted: Admitted,
    mut client: TokioIo<hyper::upgrade::Upgraded>,
    peer: SocketAddr,
) {
    let Admitted {
        served,
        mut backend,
        named,
        pass,
        permit,
    } = admitted;
    let mut record = served.record(peer);
    record.record_caller(named.caller.clone());
    let held = held(&served, &pass, &named);
    let (outcome, counts) =
        splice(&mut client, &mut backend.stream, served.idle_limit(), held).await;
    record.report_close(&backend.authority, outcome, counts);
    drop(permit);
}

/// What holds an open workflow tunnel: it ends when the pass lapses, or
/// when a check finds its person no longer let through.
async fn held(
    served: &ServedRoute,
    pass: &Secret,
    named: &IdentifiedStreamCaller,
) -> SpliceOutcome {
    tokio::select! {
        ended = expiring(named.expiry) => ended,
        () = wait_for_caller_loss(served, pass, named) => SpliceOutcome::CallerLost,
    }
}

/// Resolves once a check of the tunnel's person does not clearly hold.
async fn wait_for_caller_loss(served: &ServedRoute, pass: &Secret, named: &IdentifiedStreamCaller) {
    let checks = served.tunnel_checks();
    let mut ticks = tokio::time::interval(checks.every.max(Duration::from_millis(10)));
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let checked = tokio::time::timeout(checks.timeout, still_holds(served, pass, named)).await;
        if !matches!(checked, Ok(true)) {
            return;
        }
    }
}

/// Whether `pass` still names the tunnel's person, and the route still
/// lets them through.
async fn still_holds(served: &ServedRoute, pass: &Secret, named: &IdentifiedStreamCaller) -> bool {
    let Ok(server_name) = workflow_server_name() else {
        return false;
    };
    let credential = StreamCredential::RunPass(pass.clone());
    let Ok(again) = served.identify(server_name, credential).await else {
        return false;
    };
    if again.caller != named.caller {
        return false;
    }
    served.gate(None, again.caller).await == Gate::Open
}

/// The name a workflow's connection is checked under.
fn workflow_server_name() -> Result<DomainName, Shut> {
    DomainName::new(WORKFLOW_SERVER_NAME).map_err(|_| Shut::Undecided)
}

/// The status a refused `CONNECT` is answered with: no more than whether
/// to try again, the reason left in the record.
fn status_of(shut: Shut) -> StatusCode {
    match shut {
        Shut::NotNamed(StreamCallerRefusal::Unavailable)
        | Shut::Refused(StreamRefusal::NoDecision)
        | Shut::Undecided
        | Shut::Late => StatusCode::SERVICE_UNAVAILABLE,
        Shut::NoToken => StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        Shut::NoTunnelRequest => StatusCode::METHOD_NOT_ALLOWED,
        Shut::NotNamed(_) | Shut::Refused(_) | Shut::RouteUnknown | Shut::Handshake(_) => {
            StatusCode::FORBIDDEN
        }
    }
}

/// The answer to a refused `CONNECT`.
fn refusal(status: StatusCode) -> Response<Empty<Bytes>> {
    let mut response = Response::new(Empty::new());
    *response.status_mut() = status;
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response
            .headers_mut()
            .insert(PROXY_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}
