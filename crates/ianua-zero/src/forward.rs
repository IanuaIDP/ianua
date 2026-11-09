//! The upstream side of the gateway: sending an admitted request to one of
//! its service's backends and streaming the answer back.
//!
//! By the time a request gets here every decision has been made. The
//! pipeline admitted it, the respond step set the headers the gateway owes
//! an upstream, and the route named the service. What is left is transport:
//! pick a backend that is taking traffic, open or reuse a connection to it,
//! hold every step to a time, and stream both bodies without reading either
//! whole. Nothing here adds identity to a request, and nothing here sends a
//! request twice: one that failed may already have changed something
//! upstream.
//!
//! Each service has one [`ServicePool`], shared by every route that names
//! it, so a backend set aside on one route is set aside on all of them. The
//! pool hears what real traffic finds through each backend's circuit
//! breaker, what the health probe finds through [`HealthChecks`], and, for
//! a service found by name, what the name resolves to now through
//! [`DiscoveryWatch`]. [`ServicePools`] keeps one pool per service as the
//! configuration changes. A service reached through a tenant's connector
//! gets a pool whose connections are opened down that connector's links
//! (see [`crate::connectors`]), held to the connector's scope instead of
//! the operator's networks; with no link here it is answered
//! [`ForwardError::ConnectorOffline`], never dialled from the gateway.
//!
//! The handler calls [`Forwarder::forward`] with the request and a
//! [`ForwardTarget`], and gets the upstream's response or the reason there
//! is none. A tunnel an agent opens is held to [`AgentTunnelAuthority`] and
//! one a person or consumer opens to [`HolderTunnelAuthority`]: asked again while it
//! stays open, it closes once the caller may no longer hold it.

mod authority;
mod balance;
mod body;
mod breaker;
mod client;
mod dial;
mod discovery;
mod error;
mod headers;
mod health;
mod outbound;
mod pool;
mod registry;
mod screen;
mod settings;
mod target;
mod tls;
mod upgrade;

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

pub(crate) use authority::{AgentTunnelAuthority, HolderTunnelAuthority, UncheckableTunnel};
#[cfg(test)]
use body::BodyError;
pub(crate) use body::ResponseBody;
pub(crate) use client::{BoxError, Clients, RequestBody};
pub(crate) use discovery::DiscoveryWatch;
pub(crate) use error::ForwardError;
pub(crate) use headers::asks_to_switch;
pub(crate) use health::HealthChecks;
use http::{Request, Response, StatusCode};
pub(crate) use pool::ServicePool;
pub(crate) use registry::ServicePools;
pub(crate) use settings::{DiscoverySettings, ForwardSettings, ProbeSettings, TunnelLimits};
pub(crate) use target::{AffinityKey, ForwardTarget, ResponseInspection, ResponseSpan};
pub(crate) use tls::{ClientKey, ClientKeys};
use tokio::sync::Semaphore;
pub(crate) use upgrade::{TunnelAuthority, UpgradeTerms};

use self::body::Timing;
use self::pool::Outcome;
use self::upgrade::Tunnels;

/// The shortest period any repeating timer here runs on. A period of zero
/// would spin, and the runtime refuses one.
const SHORTEST_PERIOD: Duration = Duration::from_millis(10);

/// Sends admitted requests to their service's backends.
pub(crate) struct Forwarder {
    response_deadline: Duration,
    long_lived_idle: Duration,
    tunnels: Tunnels,
}

impl Forwarder {
    /// A forwarder held to `settings`.
    #[must_use]
    pub(crate) fn new(settings: &ForwardSettings) -> Self {
        Self {
            response_deadline: settings.response_deadline,
            long_lived_idle: settings.long_lived_idle,
            tunnels: Tunnels::new(settings.tunnels),
        }
    }

    /// Sends `request` once to a backend, streaming its response without retrying.
    /// Removes connection-specific headers, uses the service's `Host` and target
    /// path with the request query, and limits the streamed request body.
    /// The caller must already have stripped untrusted identity headers and set
    /// trusted ones; forwarding adds none.
    ///
    /// Upgrades require `target.upgrade.rule` before contacting a backend. An accepted
    /// `101` joins the connections into a tunnel subject to gateway tunnel limits.
    /// Response bodies use the response deadline, or the idle limit for server-sent
    /// events and streams marked by `target.span`, plus any inspection limit.
    /// A streamed body exceeding these bounds ends in a [`BodyError`].
    ///
    /// # Errors
    ///
    /// - Forbidden or unsupported upgrades, or exhausted tunnel capacity.
    /// - No configured backend, or none healthy enough to take traffic.
    /// - A prohibited backend address or a backend/path that cannot form a request.
    /// - A backend unreachable or too slow to begin its response.
    /// - A declared/streamed request over its body limit, or a declared response over its inspection limit.
    pub(crate) async fn forward(
        &self,
        mut request: Request<RequestBody>,
        target: ForwardTarget,
    ) -> Result<Response<ResponseBody>, ForwardError> {
        let timing = Timing {
            deadline: tokio::time::Instant::now() + self.response_deadline,
            idle: self.long_lived_idle,
            span: target.span,
        };
        outbound::ensure_within(request.headers(), target.body_limit)?;
        let hop = upgrade::hop_for(request.headers(), target.upgrade.rule)?;
        let handshake = self.tunnels.handshake(&mut request, hop)?;
        let lease = target.pool.lease(target.affinity.as_ref())?;
        let outbound = outbound::request(request, &target, lease.url(), hop)?;
        let answered = target.pool.send(outbound).await;
        lease.record(Outcome::of(&answered));
        let response = answered?;
        let Some(handshake) =
            handshake.filter(|_| response.status() == StatusCode::SWITCHING_PROTOCOLS)
        else {
            return body::answer(response, lease, target.inspection, timing);
        };
        Ok(handshake.complete(response, lease, &target.upgrade))
    }
}

/// `duration`, or the shortest period a repeating timer may run on.
fn period(duration: Duration) -> Duration {
    duration.max(SHORTEST_PERIOD)
}

/// A semaphore of `permits`, held to the most the runtime can count.
fn semaphore(permits: NonZeroUsize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(permits.get().min(Semaphore::MAX_PERMITS)))
}

/// The value behind `mutex`, also when a thread panicked holding it: every
/// value kept behind one here is whole after each statement that writes it.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
