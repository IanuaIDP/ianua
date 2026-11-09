//! One outbound request from a service: where it asks to go read strictly,
//! the decision asked of the app, and then a tunnel or a relayed exchange
//! for what is let out.
//!
//! Deny by default: a target that does not read, a decision that fails or
//! does not come in time, a refusal, a destination that cannot be reached,
//! each is answered with a refusal of the egress gateway's own words, and
//! nothing leaves. Every decision is logged with the service, the target,
//! the tenant and policy that decided and the agent held to it; the
//! assertion a call carries is never logged and never reaches the
//! destination.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use ianua_app::auditor::RequestAuditor;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::routing::egress::{DecideRequest, DecideUseCase, EgressVerdict};
use ianua_boot::shutdown::Shutdown;
use ianua_boot::tunnel::splice;
use ianua_domain::domains::routing::egress::{EgressDecision, EgressTarget, ServiceIdentity};
use ianua_domain::shared::security::secret::Secret;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::dial::{Reach, Resolve};
use crate::target::{Asked, Form, asked_of};

/// What the egress gateway answers a service with.
pub(crate) type EgressBody = UnsyncBoxBody<Bytes, hyper::Error>;

/// An error an exchange may end with.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The header the gateway signs the agent's assertion into.
pub const ASSERTION_HEADER: &str = "x-ianua-assertion";

/// Headers that concern one hop only (RFC 9110 section 7.6.1), or the hop
/// to the egress gateway alone, never passed on to a destination.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    ASSERTION_HEADER,
];

/// The decision on each way out: the use case and the auditor its
/// refusals are recorded through.
pub struct Decision {
    /// Decides a way out.
    pub use_case: DecideUseCase,
    /// Records what an agent caused, through the data plane's inbox.
    pub auditor: RequestAuditor,
}

/// How long each part of a way out may take, and how many tunnels may be
/// open at once.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WayOutLimits {
    /// The longest the decision may take.
    pub decision: Duration,
    /// The longest a plain HTTP exchange may take, its answer included.
    pub request: Duration,
    /// How long a tunnel may carry nothing.
    pub idle: Duration,
    /// The most tunnels open at once.
    pub tunnels: usize,
}

/// The egress gateway: what it asks, where it may reach, and how much it
/// takes on.
pub struct Egress<R> {
    decision: Decision,
    reach: Reach<R>,
    limits: WayOutLimits,
    tunnels: Arc<Semaphore>,
    shutdown: Shutdown,
}

/// The authenticated service and socket named in a decision's log record.
struct RequestOrigin<'a> {
    service: &'a ServiceIdentity,
    peer: SocketAddr,
}

impl RequestOrigin<'_> {
    /// Combines the certificate identity, validated target and optional agent assertion.
    fn decision_request(&self, headers: &HeaderMap, target: &EgressTarget) -> DecideRequest {
        DecideRequest {
            service: self.service.clone(),
            target: target.clone(),
            assertion: assertion_of(headers),
        }
    }
}

/// The validated host and origin-form path of one plain HTTP destination.
struct RelayTarget<'a> {
    target: &'a EgressTarget,
    path: &'a str,
}

impl RelayTarget<'_> {
    /// Removes proxy credentials and replaces the absolute target with its origin form.
    fn request(&self, request: Request<Incoming>) -> Result<Request<Incoming>, BoxError> {
        let (mut parts, body) = request.into_parts();
        strip_for_destination(&mut parts.headers);
        parts
            .headers
            .insert(HOST, HeaderValue::from_str(&host_of(self.target))?);
        parts.uri = self.path.parse()?;
        Ok(Request::from_parts(parts, body))
    }
}

/// Why a way out was refused, in the egress gateway's own words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// The request names no target the gateway can judge.
    Malformed,
    /// The policy refused it.
    Denied,
    /// No decision could be had.
    Undecided,
    /// Every tunnel slot is taken.
    Busy,
    /// The destination could not be reached.
    Unreachable,
    /// The destination did not answer in time.
    TimedOut,
}

impl Refusal {
    /// The status and the words the service is answered with.
    fn answer(self) -> (StatusCode, &'static str) {
        match self {
            Self::Malformed => (StatusCode::BAD_REQUEST, "malformed target"),
            Self::Denied => (StatusCode::FORBIDDEN, "egress denied"),
            Self::Undecided | Self::Busy => (StatusCode::SERVICE_UNAVAILABLE, "egress unavailable"),
            Self::Unreachable => (StatusCode::BAD_GATEWAY, "destination unreachable"),
            Self::TimedOut => (StatusCode::GATEWAY_TIMEOUT, "destination timed out"),
        }
    }
}

impl<R: Resolve> Egress<R> {
    /// An egress gateway deciding with `decision`, reaching destinations
    /// as `reach` lets it, within `limits`, its tunnels stopped with
    /// `shutdown`.
    #[must_use]
    pub(crate) fn new(
        decision: Decision,
        reach: Reach<R>,
        limits: WayOutLimits,
        shutdown: Shutdown,
    ) -> Self {
        Self {
            decision,
            reach,
            tunnels: Arc::new(Semaphore::new(limits.tunnels)),
            limits,
            shutdown,
        }
    }

    /// Decides one request `service` sent from `peer` and carries it out.
    /// Never fails: every refusal is an answer.
    pub(crate) async fn handle(
        &self,
        request: Request<Incoming>,
        service: &ServiceIdentity,
        peer: SocketAddr,
    ) -> Response<EgressBody> {
        let Some(asked) = asked_of(&request) else {
            tracing::info!(%peer, service = service.as_str(), decision = "deny", reason = "malformed_target", "egress decided");
            return refused(Refusal::Malformed);
        };
        let origin = RequestOrigin { service, peer };
        if let Err(refusal) = self.authorize(&request, &origin, &asked.target).await {
            return refused(refusal);
        }
        let upstream = match self.reach.dial(&asked.target).await {
            Ok(upstream) => upstream,
            Err(error) => {
                tracing::warn!(%error, target = %asked.target, "an egress destination could not be reached");
                return refused(Refusal::Unreachable);
            }
        };
        self.carried(request, upstream, asked).await
    }

    /// The decision on `target` for `service`, logged, or the refusal.
    async fn authorize(
        &self,
        request: &Request<Incoming>,
        origin: &RequestOrigin<'_>,
        target: &EgressTarget,
    ) -> Result<(), Refusal> {
        let RequestOrigin { service, peer } = *origin;
        let asked = origin.decision_request(request.headers(), target);
        let decided = tokio::time::timeout(
            self.limits.decision,
            self.decision
                .use_case
                .execute(&(), &self.decision.auditor, asked),
        )
        .await;
        let verdict = match decided {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(error)) => {
                tracing::error!(%error, %peer, service = service.as_str(), %target, "no egress decision; refused");
                return Err(Refusal::Undecided);
            }
            Err(_) => {
                tracing::error!(%peer, service = service.as_str(), %target, "no egress decision in time; refused");
                return Err(Refusal::Undecided);
            }
        };
        log_decision(&verdict, service, peer, target);
        match verdict.decision {
            EgressDecision::Allow => Ok(()),
            EgressDecision::Deny(_) => Err(Refusal::Denied),
        }
    }

    /// Carries `request` out over `upstream`, as `asked` says.
    async fn carried(
        &self,
        request: Request<Incoming>,
        upstream: TcpStream,
        asked: Asked,
    ) -> Response<EgressBody> {
        match asked.form {
            Form::Tunnel => self.tunnelled(request, upstream),
            Form::Relay(path) => {
                self.relayed(
                    request,
                    upstream,
                    &RelayTarget {
                        target: &asked.target,
                        path: &path,
                    },
                )
                .await
            }
        }
    }

    /// Answers a `CONNECT` and joins the service to the destination once
    /// the connection is upgraded, holding a tunnel slot until it ends.
    fn tunnelled(
        &self,
        request: Request<Incoming>,
        mut upstream: TcpStream,
    ) -> Response<EgressBody> {
        let Ok(slot) = Arc::clone(&self.tunnels).try_acquire_owned() else {
            return refused(Refusal::Busy);
        };
        let idle = self.limits.idle;
        self.shutdown.spawn_until_stopped(async move {
            let _slot = slot;
            let Ok(upgraded) = hyper::upgrade::on(request).await else {
                return;
            };
            let mut service = TokioIo::new(upgraded);
            let ended = splice(&mut service, &mut upstream, idle).await;
            tracing::info!(ended = ended.as_str(), "egress tunnel ended");
        });
        Response::new(Empty::new().map_err(|never| match never {}).boxed_unsync())
    }

    /// Sends a plain HTTP request on to the destination in origin form and
    /// streams the answer back, the whole exchange held to its time.
    async fn relayed(
        &self,
        request: Request<Incoming>,
        upstream: TcpStream,
        destination: &RelayTarget<'_>,
    ) -> Response<EgressBody> {
        let target = destination.target;
        let lifetime = self.limits.request;
        let exchange = async {
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await?;
            self.shutdown.spawn_until_stopped(async move {
                let _ = tokio::time::timeout(lifetime, connection).await;
            });
            Ok::<_, BoxError>(sender.send_request(destination.request(request)?).await?)
        };
        match tokio::time::timeout(lifetime, exchange).await {
            Ok(Ok(answer)) => answer.map(BodyExt::boxed_unsync),
            Ok(Err(error)) => {
                tracing::warn!(%error, %target, "an egress exchange failed");
                refused(Refusal::Unreachable)
            }
            Err(_) => refused(Refusal::TimedOut),
        }
    }
}

/// The assertion `headers` carry, if they carry exactly one that is text.
fn assertion_of(headers: &HeaderMap) -> Option<Secret> {
    let mut values = headers.get_all(ASSERTION_HEADER).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    value.to_str().ok().map(Secret::new)
}

/// The `Host` a relayed request names: the port only when it is not 80.
fn host_of(target: &EgressTarget) -> String {
    match target.port() {
        80 => target.host().as_str().to_owned(),
        port => format!("{}:{port}", target.host().as_str()),
    }
}

/// Removes what concerns the hop to the egress gateway alone: the proxy's
/// own headers, every header `Connection` names, and the assertion, which
/// names an agent and is for the platform only.
fn strip_for_destination(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// The audit line for `verdict` on `service`'s way out to `target`.
fn log_decision(
    verdict: &EgressVerdict,
    service: &ServiceIdentity,
    peer: SocketAddr,
    target: &EgressTarget,
) {
    let (decision, reason) = match verdict.decision {
        EgressDecision::Allow => ("allow", "listed"),
        EgressDecision::Deny(denial) => ("deny", denial.as_str()),
    };
    tracing::info!(
        %peer,
        service = service.as_str(),
        %target,
        tenant_id = ?verdict.tenant_id,
        policy_id = ?verdict.policy_id,
        agent_id = ?verdict.agent_id,
        decision,
        reason,
        "egress decided"
    );
}

/// The answer for `refusal`, in the egress gateway's own words.
fn refused(refusal: Refusal) -> Response<EgressBody> {
    let (status, words) = refusal.answer();
    let mut response = Response::new(
        Full::new(Bytes::from_static(words.as_bytes()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests;
