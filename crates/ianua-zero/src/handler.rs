//! What the public listener does with each request: one flat walk from
//! the request as it arrived to the answer the client gets.
//!
//! 1. Admit it: strip every header the proxy owns, read its host, method
//!    and path one way only.
//! 2. Hold its host to the connection it came on: another name than the
//!    handshake's is `421`.
//! 3. Resolve the tenant from the host: an unknown or contested host is
//!    `404`, never a default tenant. On the workflow listener the tenant
//!    and route are the ones a run pass names, checked under the tenant's
//!    keys first, and no host is looked at.
//! 4. Answer the tenant's published assertion keys, its app sign-in
//!    addresses and the hops of its services' own cookies itself.
//! 5. Find the route: no route is `404`, a route that cannot run safely is
//!    refused, never passed to the next.
//! 6. Read as much of the body as the pipeline asks, and no more.
//! 7. Run the route's pipeline through the stage dispatcher. Anything short
//!    of the Policy stage granting the request is a refusal.
//! 8. Sign who the caller is for the upstream: no key, no forward.
//! 9. Forward, streaming both bodies, and run the response stages on what
//!    comes back.
//!
//! Every step that cannot decide refuses: the answer is drawn by the
//! error pages (HTML for a browser, JSON for a script, a gRPC status for a
//! gRPC call) with the request's reference and never its reason, which the
//! request's record keeps. No token, cookie or header value is ever logged
//! or put in a span.

mod arrival;
mod pipeline_store;
mod refuse;
mod resolution;
mod response;
mod run;
mod upstream;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt as _;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response};
use ianua_app::ports::authentication::{AppSignInBroker, PresentedTokens};
use ianua_app::ports::pages::PageRenderer;
use ianua_app::ports::runtime::{FleetCounters, RequestObserver};
use ianua_app::ports::shared::EventDispatcher;
use ianua_app::use_cases::agents::enforcement::CheckAgentAuthorityUseCase;
use ianua_app::use_cases::crypto::assertions::{GetPublishedUseCase, SignUseCase};
use ianua_app::use_cases::proxy::RecheckConnectionUseCase;
use ianua_domain::domains::proxy::request::body::{BodyReadSettings, ByteCap};
use ianua_domain::domains::proxy::request::forwarded::TrustedProxies;

use self::arrival::Arrival;
use self::refuse::Refused;
use crate::forward::{Forwarder, ServicePools};
use crate::listen::{BodyError, ConnectionFacts, Handler};
use crate::observability::RequestAudit;
use crate::pipeline::executor::StageDispatch;
use crate::request::{ListenerRole, Scheme};
use crate::resolve::Tables;
use crate::stream::DataEntry;

/// The body of every answer the gateway gives: a page or a body it drew,
/// or an upstream's answer streaming through.
pub(crate) type GatewayBody = UnsyncBoxBody<Bytes, BodyError>;

/// What one answered request came to, for its record.
pub(crate) enum Served {
    /// The upstream answered with this status, or a stage answered for it.
    Forwarded(Response<GatewayBody>, u16),
    /// The gateway answered itself: a sign-in address, a hop, the key set.
    Answered(Response<GatewayBody>),
    /// The request was refused.
    Refused(Refused),
}

impl Served {
    /// The status the client is answered with.
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::Forwarded(_, status) => *status,
            Self::Answered(answer) => answer.status().as_u16(),
            Self::Refused(refused) => refused.status().code(),
        }
    }
}

/// How long the parts of one request may take.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestBounds {
    /// How much of a body each reader reads, and the largest body taken
    /// where no stage sets one.
    pub bodies: BodyReadSettings,
    /// The largest answer the response stages other than the canary scan
    /// read.
    pub response_stages: ByteCap,
    /// How much of an answer the canary scan reads.
    pub canary_scan: ByteCap,
    /// The longest a client may take to send the part of its body the
    /// pipeline reads.
    pub body_read: Duration,
    /// The longest the pipeline may run on one request.
    pub pipeline: Duration,
    /// The longest one call out of the gateway may take: the assertion's
    /// signature, the published key set.
    pub call: Duration,
}

/// Everything the handler answers requests with, built once.
#[derive(Clone)]
pub(crate) struct GatewayParts {
    /// The tables the follower keeps current.
    pub tables: Arc<Tables>,
    /// The stage dispatcher.
    pub dispatch: Arc<StageDispatch>,
    /// One pool of backends per service.
    pub pools: Arc<ServicePools>,
    /// Sends an admitted request to its backend.
    pub forwarder: Arc<Forwarder>,
    /// Draws the error pages.
    pub pages: Arc<dyn PageRenderer>,
    /// Where each request is reported.
    pub observer: Arc<dyn RequestObserver>,
    /// The gateway's inbox, which agent actions are recorded through.
    pub events: Arc<dyn EventDispatcher>,
    /// Relays app sign-in to the API, when its address is set.
    pub sign_in: Option<Arc<dyn AppSignInBroker>>,
    /// The counters every gateway shares, holding the sign-in limits.
    pub counters: Arc<dyn FleetCounters>,
    /// Signs the identity an upstream is handed.
    pub sign_assertion: Arc<SignUseCase>,
    /// The tenant's published assertion keys.
    pub published_keys: Arc<GetPublishedUseCase>,
    /// Asked again while an agent's tunnel is open.
    pub agent_authority: Arc<CheckAgentAuthorityUseCase>,
    /// Asked again while a person's tunnel is open.
    pub recheck_connection: Arc<RecheckConnectionUseCase>,
    /// The proxies whose `X-Forwarded-For` is believed.
    pub trusted_proxies: TrustedProxies,
    /// How clients reach the listener this handler serves, as the address
    /// a `DPoP` proof names and the `X-Forwarded-Proto` upstreams are told.
    pub scheme: Scheme,
    /// How the listener this handler serves finds a request's app, and
    /// which credential it reads.
    pub listener: ListenerRole,
    /// Reads the tenant and route a run pass names on the workflow
    /// listener, and checks it under the tenant's keys before anything of
    /// the tenant runs.
    pub passes: Arc<dyn PresentedTokens>,
    /// How long the parts of one request may take.
    pub bounds: RequestBounds,
    /// The workflow listener's way into stream routes, for a Protected
    /// data step's `CONNECT`; none on every other listener, where a
    /// `CONNECT` reaches no stream route.
    pub data: Option<Arc<DataEntry>>,
}

/// The handler of the public listener.
#[derive(Clone)]
pub(crate) struct Gateway {
    parts: Arc<GatewayParts>,
}

/// The request metadata and pending audit needed to finish its response.
struct RequestReport<'a> {
    parts: &'a http::request::Parts,
    arrival: &'a Arrival,
    audit: RequestAudit,
}

impl Gateway {
    /// A handler answering with `parts`.
    #[must_use]
    pub(crate) fn new(parts: GatewayParts) -> Self {
        Self {
            parts: Arc::new(parts),
        }
    }

    /// The same handler for a listener clients reach by `scheme`, such as
    /// the runner listener: every `DPoP` proof on it must
    /// name an address of that scheme, as the runner saw it, or a
    /// key-bound token is refused.
    #[must_use]
    pub(crate) fn reached_by(&self, scheme: Scheme) -> Self {
        let mut parts = GatewayParts::clone(&self.parts);
        parts.scheme = scheme;
        Self::new(parts)
    }

    /// The same handler for the workflow listener, which Protected apps
    /// and Protected data steps call over the deployment's own network,
    /// reached by `scheme`: each request's app is the route its run pass
    /// names, never one its host picks, a `CONNECT` reaches the stream route
    /// its pass names through `data`, and the pass is the only credential
    /// read.
    #[must_use]
    pub(crate) fn for_workflows(&self, scheme: Scheme, data: Arc<DataEntry>) -> Self {
        let mut parts = GatewayParts::clone(&self.parts);
        parts.scheme = scheme;
        parts.listener = ListenerRole::ByRunPass;
        parts.data = Some(data);
        Self::new(parts)
    }

    /// The answer to `request`, which came on `connection`, recorded once.
    /// A `CONNECT` on the workflow listener is a Protected data step's, and
    /// goes into the stream route its pass names, recorded as every stream
    /// connection is.
    async fn answer(
        &self,
        request: Request<Incoming>,
        connection: Arc<ConnectionFacts>,
    ) -> Response<GatewayBody> {
        if let (Some(data), true) = (&self.parts.data, request.method() == Method::CONNECT) {
            return whole(data.connect(request, connection.peer()).await);
        }
        let (mut parts, body) = request.into_parts();
        let arrival = Arrival::read(&parts, &connection, &self.parts.trusted_proxies);
        let mut audit = self.start_audit(&arrival, &parts);
        let served = run::served(
            &self.parts,
            run::RequestOrigin {
                arrival: &arrival,
                connection: &connection,
            },
            run::RequestMessage {
                parts: &mut parts,
                body,
            },
            &mut audit,
        )
        .await;
        self.report(
            served,
            RequestReport {
                parts: &parts,
                arrival: &arrival,
                audit,
            },
        )
    }

    /// The audit record of a request that arrived as `arrival`, carrying its
    /// trace.
    fn start_audit(&self, arrival: &Arrival, parts: &http::request::Parts) -> RequestAudit {
        let mut audit =
            RequestAudit::start(arrival.recorded(parts), Arc::clone(&self.parts.observer));
        audit.record_trace(arrival.trace);
        audit
    }

    /// Records the final decision exactly once and renders refusals for this request.
    fn report(&self, served: Served, report: RequestReport<'_>) -> Response<GatewayBody> {
        let RequestReport {
            parts,
            arrival,
            audit,
        } = report;
        match served {
            Served::Forwarded(response, status) => {
                audit.report_allowed(status);
                response
            }
            Served::Answered(response) => {
                audit.report_allowed(response.status().as_u16());
                response
            }
            Served::Refused(refused) => {
                let response = refused.answer(
                    &parts.headers,
                    arrival.correlation_id,
                    self.parts.pages.as_ref(),
                );
                audit.report_refused(refused.into_record());
                response
            }
        }
    }
}

impl Handler for Gateway {
    type Body = GatewayBody;

    fn handle(
        &self,
        request: Request<Incoming>,
        connection: Arc<ConnectionFacts>,
    ) -> impl Future<Output = Response<Self::Body>> + Send {
        let gateway = self.clone();
        async move { gateway.answer(request, connection).await }
    }
}

/// `response`, whose body is whole, as the body every answer has.
pub(crate) fn whole<B>(response: Response<B>) -> Response<GatewayBody>
where
    B: hyper::body::Body<Data = Bytes, Error = std::convert::Infallible> + Send + 'static,
{
    response.map(|body| body.map_err(|never| match never {}).boxed_unsync())
}
