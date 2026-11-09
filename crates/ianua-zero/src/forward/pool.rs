//! One service's backends, and which of them takes the next request.
//!
//! A backend takes traffic unless its health probe says it is down or its
//! breaker has set it aside. The two signals are kept apart and meet only
//! here, so neither can overrule the other. When so few backends take
//! traffic that the service's panic share is crossed, health is set aside
//! instead and every backend is tried: the probe is then more likely wrong
//! than the backends, and refusing everything turns "maybe degraded" into
//! "certainly down". Health decides availability, never who is let in.
//!
//! A service with no backends at all is refused. Nothing stands in for a
//! backend that is not there.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use arc_swap::ArcSwap;
use http::{Request, Response};
use hyper::body::Incoming;
use ianua_domain::domains::routing::backend::balancing::LoadBalancing;
use ianua_domain::domains::routing::backend::circuit_breaker::CircuitBreaker;
use ianua_domain::domains::routing::backend::health_check::{ActiveHealthCheck, HealthCheckPolicy};
use ianua_domain::domains::routing::backend::upstream::{
    HostHeader, StickySession, Upstream, WeightedBackend,
};
use ianua_domain::domains::routing::connector::scope::UpstreamReach;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::HttpUrl;

use super::breaker::Breaker;
use super::client::{RequestBody, UpstreamClient, empty_body};
use super::error::ForwardError;
use super::registry::ServiceSpec;
use super::target::AffinityKey;
use super::{balance, outbound, screen};

/// One service's backends, shared by every route that names the service.
///
/// Its backends can change under it, when the service's name resolves to
/// others, without the routes that hold it being rebuilt; a backend that
/// stays keeps what its breaker and probe know about it.
pub(crate) struct ServicePool {
    upstream: Upstream,
    health: HealthCheckPolicy,
    client: UpstreamClient,
    networks: Arc<UpstreamNetworks>,
    members: ArcSwap<Vec<Arc<Member>>>,
    turn: AtomicUsize,
}

impl ServicePool {
    /// A pool for the service `spec` describes, sending with `client` to
    /// backends `networks` permits.
    pub(super) fn new(
        spec: &ServiceSpec<'_>,
        client: UpstreamClient,
        networks: Arc<UpstreamNetworks>,
    ) -> Self {
        let pool = Self {
            upstream: spec.upstream.clone(),
            health: spec.health.clone(),
            client,
            networks,
            members: ArcSwap::from_pointee(Vec::new()),
            turn: AtomicUsize::new(0),
        };
        pool.replace_backends(spec.upstream.effective_backends());
        pool
    }

    /// Whether this pool was built for exactly the service `spec`
    /// describes, so it can be kept across a reload.
    pub(super) fn serves(&self, spec: &ServiceSpec<'_>) -> bool {
        self.upstream == *spec.upstream && self.health == *spec.health
    }

    /// The upstream this pool was built for.
    pub(super) fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// How the service pins a caller's requests to one backend, when it
    /// does: the handler reads the key it names off the request.
    #[must_use]
    pub(crate) fn sticky_session(&self) -> Option<&StickySession> {
        self.upstream.sticky_session()
    }

    /// The service's probe settings, when it is probed.
    pub(super) fn active_check(&self) -> Option<&ActiveHealthCheck> {
        self.health.active()
    }

    /// Which `Host` the service's backends are sent.
    pub(super) fn host_header(&self) -> HostHeader {
        HostHeader::from(self.upstream.preserve_host())
    }

    /// The backends now in the pool.
    pub(super) fn backends(&self) -> Vec<WeightedBackend> {
        self.members
            .load()
            .iter()
            .map(|member| member.backend.clone())
            .collect()
    }

    /// The backends now in the pool, with what is known about each.
    pub(super) fn members(&self) -> Arc<Vec<Arc<Member>>> {
        self.members.load_full()
    }

    /// Puts `backends` in the pool in place of the ones there. A backend
    /// that stays, at the same weight, keeps its breaker and probe state.
    pub(super) fn replace_backends(&self, backends: Vec<WeightedBackend>) {
        let current = self.members.load_full();
        let rule = self.upstream.circuit_breaker();
        let next = backends
            .into_iter()
            .map(|backend| kept_or_new(&current, backend, rule))
            .collect();
        self.members.store(Arc::new(next));
    }

    /// A backend for the next request, pinned by `affinity` when the
    /// service pins callers.
    ///
    /// # Errors
    ///
    /// - [`ForwardError::NoBackends`] when the pool is empty.
    /// - [`ForwardError::NoHealthyBackend`] when no backend takes traffic.
    /// - [`ForwardError::AddressRefused`] when the one picked is at an
    ///   address the gateway may not reach.
    pub(super) fn lease(&self, affinity: Option<&AffinityKey>) -> Result<Lease, ForwardError> {
        let members = self.members.load();
        if members.is_empty() {
            return Err(ForwardError::NoBackends);
        }
        let candidates = self.candidates(members.as_slice(), Instant::now());
        let chosen = self
            .choose(&candidates, affinity)
            .and_then(|index| candidates.get(index).copied())
            .ok_or(ForwardError::NoHealthyBackend)?;
        if !self.may_dial(chosen.url()) {
            return Err(ForwardError::AddressRefused);
        }
        Ok(Lease::open(Arc::clone(chosen)))
    }

    /// Sends `request` and waits for the answer to start, at most the
    /// service's timeout.
    ///
    /// # Errors
    ///
    /// - [`ForwardError::TimedOut`] when no answer starts in time.
    /// - Any error [`ForwardError::of_send`] tells apart.
    pub(super) async fn send(
        &self,
        request: Request<RequestBody>,
    ) -> Result<Response<Incoming>, ForwardError> {
        let first_byte = self.upstream.timeout_secs().std_duration();
        let Ok(answered) = tokio::time::timeout(first_byte, self.client.request(request)).await
        else {
            return Err(ForwardError::TimedOut);
        };
        answered.map_err(ForwardError::of_send)
    }

    /// Asks `member` whether it is well, as `check` says: up only with a
    /// success status within the probe's timeout.
    pub(super) async fn probe(&self, member: &Member, check: &ActiveHealthCheck) -> Probed {
        if !self.may_dial(member.url()) {
            return Probed::Down;
        }
        let Ok(request) = probe_request(member.url(), check) else {
            return Probed::Down;
        };
        let timeout = check.timeout_secs().std_duration();
        match tokio::time::timeout(timeout, self.client.request(request)).await {
            Ok(Ok(response)) if response.status().is_success() => Probed::Up,
            Ok(_) | Err(_) => Probed::Down,
        }
    }

    /// Whether a connection may be opened to `url`. The gateway dials an
    /// address written out only where the networks permit it. A connector
    /// dials inside its tenant's network instead, where the operator's
    /// networks mean nothing: there the connector's scope is the bound,
    /// held by the dialer before each connection, and by the connector
    /// against its own list again.
    fn may_dial(&self, url: &HttpUrl) -> bool {
        match self.upstream.reach() {
            UpstreamReach::Direct => screen::permits_literal(url, &self.networks),
            UpstreamReach::Connector(_) => true,
        }
    }

    /// The members that may take the next request at `now`: those taking
    /// traffic, or all of them when too few are.
    fn candidates<'a>(&self, members: &'a [Arc<Member>], now: Instant) -> Vec<&'a Arc<Member>> {
        let taking: Vec<&Arc<Member>> = members
            .iter()
            .filter(|member| member.takes_traffic(now))
            .collect();
        let panicking = self
            .health
            .active()
            .is_some_and(|check| check.in_panic(taking.len(), members.len()));
        if panicking {
            return members.iter().collect();
        }
        taking
    }

    /// Which candidate takes the request, as the service balances.
    ///
    /// A key pins the caller unless the service sends each request to the
    /// least busy backend; a service that pins by a key the caller does
    /// not have takes turns.
    fn choose(&self, candidates: &[&Arc<Member>], affinity: Option<&AffinityKey>) -> Option<usize> {
        let turn = self.turn.fetch_add(1, Ordering::Relaxed);
        match (self.upstream.balancing(), affinity) {
            (LoadBalancing::LeastConnections, _) => {
                let in_flight: Vec<usize> = candidates.iter().map(|m| m.in_flight()).collect();
                balance::least_busy(&in_flight, turn)
            }
            (LoadBalancing::RoundRobin | LoadBalancing::ConsistentHash, Some(key)) => {
                let backends = candidates.iter().map(|m| (m.url().as_str(), m.weight()));
                balance::pinned(backends, key.as_str())
            }
            (LoadBalancing::RoundRobin | LoadBalancing::ConsistentHash, None) => {
                let weights: Vec<u32> = candidates.iter().map(|m| m.weight()).collect();
                balance::weighted_turn(&weights, turn)
            }
        }
    }
}

/// The member already in `current` for `backend`, or a new one.
fn kept_or_new(
    current: &[Arc<Member>],
    backend: WeightedBackend,
    rule: CircuitBreaker,
) -> Arc<Member> {
    current
        .iter()
        .find(|member| member.backend == backend)
        .map_or_else(|| Arc::new(Member::new(backend, rule)), Arc::clone)
}

/// A probe request for `url`.
fn probe_request(
    url: &HttpUrl,
    check: &ActiveHealthCheck,
) -> Result<Request<RequestBody>, http::Error> {
    let uri = outbound::uri_of(url, check.path().as_str())?;
    Request::get(uri).body(empty_body())
}

/// What the health probe last concluded about a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Probed {
    /// It passed its checks.
    Up,
    /// It failed them.
    Down,
}

/// One backend in a pool, and what is known about it.
pub(super) struct Member {
    backend: WeightedBackend,
    breaker: Breaker,
    probed_down: AtomicBool,
    in_flight: AtomicUsize,
}

impl Member {
    /// A backend nothing is known against yet.
    fn new(backend: WeightedBackend, rule: CircuitBreaker) -> Self {
        Self {
            backend,
            breaker: Breaker::new(rule),
            probed_down: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Where the backend answers.
    pub(super) fn url(&self) -> &HttpUrl {
        self.backend.url()
    }

    /// Records what the health probe concluded.
    pub(super) fn set_probed(&self, probed: Probed) {
        self.probed_down
            .store(probed == Probed::Down, Ordering::Release);
    }

    /// Whether the backend takes traffic at `now`.
    pub(super) fn takes_traffic(&self, now: Instant) -> bool {
        !self.probed_down.load(Ordering::Acquire) && self.breaker.allows_traffic(now)
    }

    /// The backend's share of the traffic.
    fn weight(&self) -> u32 {
        self.backend.weight()
    }

    /// Requests now open on the backend.
    fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }
}

/// How a request turned out, as far as its backend is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The backend answered. Its breaker closes.
    Answered,
    /// It could not be reached or did not answer in time.
    Failed,
    /// What happened was not the backend's doing, such as a body the
    /// client over-sent or an address the gateway refused.
    NotJudged,
}

impl Outcome {
    /// What `result` says about the backend.
    ///
    /// A `404`, a `403` or a `500` is the backend working: an application
    /// error is not a dead backend, and the probe is the one that decides
    /// that.
    pub(super) fn of<T>(result: &Result<T, ForwardError>) -> Self {
        match result {
            Ok(_) => Self::Answered,
            Err(ForwardError::Unreachable(_) | ForwardError::TimedOut) => Self::Failed,
            Err(_) => Self::NotJudged,
        }
    }
}

/// A backend picked for one request, counted as busy until the request's
/// answer is done with.
pub(super) struct Lease {
    member: Arc<Member>,
}

impl Lease {
    /// Counts a request open on `member`.
    fn open(member: Arc<Member>) -> Self {
        member.in_flight.fetch_add(1, Ordering::Relaxed);
        Self { member }
    }

    /// Where the backend answers.
    pub(super) fn url(&self) -> &HttpUrl {
        self.member.url()
    }

    /// Tells the backend's breaker how the request turned out.
    pub(super) fn record(&self, outcome: Outcome) {
        match outcome {
            Outcome::Answered => self.member.breaker.record_success(),
            Outcome::Failed => self.member.breaker.record_failure(Instant::now()),
            Outcome::NotJudged => {}
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.member.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::backend::circuit_breaker::BreakerSettings;
    use ianua_domain::types::Seconds;

    use super::*;
    use crate::forward::tests::support::{backend, pool_with, upstream_over};

    fn breaking_after(failures: u32) -> CircuitBreaker {
        CircuitBreaker::On(BreakerSettings::new(failures, Seconds::new(60)).unwrap())
    }

    fn picked(pool: &ServicePool, affinity: Option<&AffinityKey>) -> String {
        pool.lease(affinity).unwrap().url().as_str().to_owned()
    }

    /// A name scaled to zero resolves to nothing, and the route is refused
    /// rather than sent to an address nobody stands behind.
    #[test]
    fn a_pool_with_no_backends_refuses() {
        let pool = pool_with(
            &upstream_over(&["http://10.0.0.1:80"]),
            &HealthCheckPolicy::Disabled,
        );

        pool.replace_backends(Vec::new());

        assert!(matches!(pool.lease(None), Err(ForwardError::NoBackends)));
    }

    #[test]
    fn backends_take_turns() {
        let pool = pool_with(
            &upstream_over(&["http://10.0.0.1:80", "http://10.0.0.2:80"]),
            &HealthCheckPolicy::Disabled,
        );

        assert_ne!(picked(&pool, None), picked(&pool, None));
    }

    #[test]
    fn a_backend_its_breaker_set_aside_gets_no_traffic() {
        let upstream = upstream_over(&["http://10.0.0.1:80", "http://10.0.0.2:80"])
            .with_circuit_breaker(breaking_after(2));
        let pool = pool_with(&upstream, &HealthCheckPolicy::Disabled);
        let first = pool.members()[0].url().as_str().to_owned();

        for _ in 0..2 {
            Lease::open(Arc::clone(&pool.members()[0])).record(Outcome::Failed);
        }

        for _ in 0..6 {
            assert_ne!(picked(&pool, None), first);
        }
    }

    #[test]
    fn a_backend_probed_down_gets_no_traffic() {
        let pool = pool_with(
            &upstream_over(&[
                "http://10.0.0.1:80",
                "http://10.0.0.2:80",
                "http://10.0.0.3:80",
            ]),
            &HealthCheckPolicy::Disabled,
        );
        pool.members()[1].set_probed(Probed::Down);

        for _ in 0..9 {
            assert_ne!(picked(&pool, None), "http://10.0.0.2:80");
        }
    }

    #[test]
    fn every_backend_down_without_panic_mode_refuses() {
        let pool = pool_with(
            &upstream_over(&["http://10.0.0.1:80"]),
            &HealthCheckPolicy::Disabled,
        );

        pool.members()[0].set_probed(Probed::Down);

        assert!(matches!(
            pool.lease(None),
            Err(ForwardError::NoHealthyBackend)
        ));
    }

    /// With the one backend failing its probe, refusing every request is
    /// worse than trying it.
    #[test]
    fn panic_mode_tries_every_backend_when_too_few_are_up() {
        let pool = pool_with(
            &upstream_over(&["http://10.0.0.1:80"]),
            &HealthCheckPolicy::default(),
        );

        pool.members()[0].set_probed(Probed::Down);

        assert!(pool.lease(None).is_ok());
    }

    #[test]
    fn a_pinned_caller_stays_on_its_backend() {
        let pool = pool_with(
            &upstream_over(&[
                "http://10.0.0.1:80",
                "http://10.0.0.2:80",
                "http://10.0.0.3:80",
            ]),
            &HealthCheckPolicy::Disabled,
        );
        let ann = AffinityKey::new("user-ann");

        let first = picked(&pool, Some(&ann));

        for _ in 0..10 {
            assert_eq!(picked(&pool, Some(&ann)), first);
        }
    }

    #[test]
    fn least_connections_sends_to_the_least_busy_backend() {
        let upstream = upstream_over(&["http://10.0.0.1:80", "http://10.0.0.2:80"])
            .with_balancing(LoadBalancing::LeastConnections);
        let pool = pool_with(&upstream, &HealthCheckPolicy::Disabled);

        let busy = pool.lease(None).unwrap();
        let next = pool.lease(None).unwrap();

        assert_ne!(busy.url(), next.url());
    }

    /// A backend that stays when the name resolves again keeps what its
    /// breaker learned; one that is new starts clean.
    #[test]
    fn a_backend_that_stays_keeps_its_state() {
        let pool = pool_with(
            &upstream_over(&["http://10.0.0.1:80"]),
            &HealthCheckPolicy::Disabled,
        );
        pool.members()[0].set_probed(Probed::Down);

        pool.replace_backends(vec![
            backend("http://10.0.0.1:80", 1),
            backend("http://10.0.0.9:80", 1),
        ]);

        let members = pool.members();
        assert!(!members[0].takes_traffic(Instant::now()));
        assert!(members[1].takes_traffic(Instant::now()));
    }

    #[test]
    fn a_backend_at_a_refused_address_is_never_sent_to() {
        let metadata = upstream_over(&["http://169.254.169.254:80"]);
        let pool = pool_with(&metadata, &HealthCheckPolicy::Disabled);

        assert!(matches!(
            pool.lease(None),
            Err(ForwardError::AddressRefused)
        ));
    }

    /// A backend reached through a connector is at an address inside the
    /// tenant's network, which the operator's networks know nothing of. It
    /// is leased, and the connector's scope holds it when it is dialled.
    #[test]
    fn a_backend_behind_a_connector_is_held_to_its_scope_not_the_networks() {
        let upstream = upstream_over(&["http://192.168.7.20:80"])
            .through_connector(ianua_domain::types::ConnectorId::new());
        let pool = pool_with(&upstream, &HealthCheckPolicy::Disabled);

        assert!(pool.lease(None).is_ok());
    }

    #[test]
    fn only_the_backend_is_judged_by_a_failure() {
        let timed_out: Result<(), ForwardError> = Err(ForwardError::TimedOut);
        let too_large: Result<(), ForwardError> = Err(ForwardError::RequestTooLarge);

        assert_eq!(Outcome::of(&Ok::<(), ForwardError>(())), Outcome::Answered);
        assert_eq!(Outcome::of(&timed_out), Outcome::Failed);
        assert_eq!(Outcome::of(&too_large), Outcome::NotJudged);
    }
}
