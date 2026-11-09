//! Per-IP rate limiting middleware for login endpoints.
//!
//! Limits the attempts one source IP makes, at so many per window, with an
//! allowance that refills evenly across the window: no stretch of that
//! length ever lets through more than the limit, however the requests fall.
//! Independent of the per-user rate limiting in the domain layer.
//! Returns 429 Too Many Requests when the limit is exceeded, with
//! `Retry-After` saying how many seconds until one request is back.
//!
//! The client IP is taken from the connection socket. `X-Forwarded-For`
//! is honored only when the immediate peer is a configured trusted proxy,
//! so a client cannot spoof its source IP to evade the limiter. The
//! counter map is sharded and self-evicting to bound
//! memory and lock contention.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ianua_domain::message;
use ianua_domain::shared::security::allowance::{Allowance, Rate};

/// Number of independent counter shards. Spreads lock contention on the
/// busiest endpoint across many mutexes instead of one global lock.
const SHARD_COUNT: usize = 16;

/// Configuration for per-IP rate limiting.
#[derive(Clone)]
pub(crate) struct IpRateLimitConfig {
    /// Maximum attempts per IP per window, the most the allowance holds.
    pub max_attempts: u32,
    /// The window over which the allowance refills.
    pub window: Duration,
    /// Proxies whose `X-Forwarded-For` header is trusted. Empty means
    /// the header is never trusted and the socket IP is always used.
    pub trusted_proxies: super::client_ip::TrustedProxies,
    /// Hard cap on tracked IPs (across all shards). A backstop against
    /// memory exhaustion; normal load stays well under it via eviction.
    pub max_tracked_ips: usize,
}

/// What one address has left, and whether it has been refused since it
/// was last forgotten.
struct IpCounter {
    allowance: Allowance,
    refused: bool,
}

/// Shared state for IP rate limiting.
#[derive(Clone)]
pub(crate) struct IpRateLimitState {
    config: IpRateLimitConfig,
    shards: Arc<Vec<Mutex<HashMap<IpAddr, IpCounter>>>>,
}

impl IpRateLimitState {
    /// Creates a new rate limit state.
    #[must_use]
    pub(crate) fn new(config: IpRateLimitConfig) -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        Self {
            config,
            shards: Arc::new(shards),
        }
    }

    /// The shard that holds the counter for an address.
    fn shard_for(&self, ip: IpAddr) -> &Mutex<HashMap<IpAddr, IpCounter>> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ip.hash(&mut hasher);
        &self.shards[hasher.finish() as usize % SHARD_COUNT]
    }

    /// The rate every address is held to.
    fn rate(&self) -> Rate {
        Rate::new(self.config.max_attempts, self.config.window)
    }

    /// Spends one request of an address's allowance, or answers how long
    /// until one is back when none was there to spend.
    fn admit(&self, ip: IpAddr) -> Result<(), Duration> {
        let now = Instant::now();
        let rate = self.rate();
        let shard_cap = self.config.max_tracked_ips.div_ceil(SHARD_COUNT).max(1);
        let mut counters = self
            .shard_for(ip)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        prune(&mut counters, now, rate, shard_cap);

        let counter = counters.entry(ip).or_insert(IpCounter {
            allowance: Allowance::full(rate, now),
            refused: false,
        });
        let admitted = counter.allowance.spend(rate, now).is_some();
        counter.refused |= !admitted;
        if admitted {
            return Ok(());
        }
        Err(counter.allowance.wait_at(rate, now))
    }

    /// Spends one request of an address's allowance and says whether it
    /// was there to spend.
    #[cfg(test)]
    fn check_and_increment(&self, ip: IpAddr) -> bool {
        self.admit(ip).is_ok()
    }
}

/// Forgets addresses whose allowance is full again, then the least
/// valuable ones, to keep a shard under its cap. A no-op while the shard
/// has room.
///
/// "Least valuable" is deliberate, and it is not the same as oldest. An
/// attacker decides when this runs: they need only present addresses until
/// the shard fills. An address that has been refused is kept in preference
/// to one that has not, so a flood of fresh addresses cannot clear the very
/// counters that were doing the work: buying a fresh allowance costs an
/// attacker a shard full of addresses that were *each* refused already.
fn prune(counters: &mut HashMap<IpAddr, IpCounter>, now: Instant, rate: Rate, cap: usize) {
    if counters.len() < cap {
        return;
    }

    counters.retain(|_, c| !c.allowance.is_full_at(rate, now));
    if counters.len() < cap {
        return;
    }

    let mut by_value: Vec<(IpAddr, bool)> =
        counters.iter().map(|(ip, c)| (*ip, c.refused)).collect();
    by_value.sort_by_key(|(_, refused)| *refused);

    for (ip, _) in by_value.into_iter().take(counters.len() - cap + 1) {
        counters.remove(&ip);
    }
}

/// Axum middleware function for per-IP rate limiting.
///
/// Apply to login routes:
/// ```ignore
/// .route("/api/v1/login", post(handler))
///     .layer(axum::middleware::from_fn_with_state(
///         ip_rate_limit_state.clone(),
///         ip_rate_limit,
///     ))
/// ```
pub(crate) async fn ip_rate_limit(
    axum::extract::State(state): axum::extract::State<IpRateLimitState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let Some(ip) = resolve_client_ip(&request, &state.config.trusted_proxies) else {
        tracing::error!(
            "login rate limiter could not determine a client IP; refusing request \
             (is the server started with ConnectInfo?)"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "client address unavailable",
        )
            .into_response();
    };

    if let Err(wait) = state.admit(ip) {
        return too_many_requests(wait);
    }

    next.run(request).await
}

/// The refusal of a request past its address's allowance, saying in
/// `Retry-After` when one is back, so a client backs off for as long as it
/// must instead of retrying at once.
fn too_many_requests(wait: Duration) -> Response {
    let mut response = crate::error::answered(
        StatusCode::TOO_MANY_REQUESTS,
        crate::error::ErrorCode::RateLimitExceeded,
        message!(
            "api-too-many-requests-from-this-address",
            "too many requests from this address"
        ),
    );
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        retry_after_seconds(wait).into(),
    );
    response
}

/// `wait` in whole seconds as `Retry-After` takes it: rounded up, and at
/// least one, since a zero would invite the retry that is refused again.
fn retry_after_seconds(wait: Duration) -> u64 {
    let whole = wait.as_secs();
    let rounded_up = match wait.subsec_nanos() {
        0 => whole,
        _ => whole.saturating_add(1),
    };
    rounded_up.max(1)
}

/// Resolves the client IP, trusting `X-Forwarded-For` only when the
/// connection's immediate peer is a configured trusted proxy.
///
/// Returns `None` when no socket address is available, so the caller
/// can fail closed instead of bucketing all traffic together. Delegates to
/// [`super::client_ip::resolve`]: the same trust-boundary logic the audit
/// log's IP resolution uses, kept in one place so a fix to one cannot
/// silently leave the other trusting the wrong hop.
fn resolve_client_ip(
    request: &axum::extract::Request,
    trusted: &super::client_ip::TrustedProxies,
) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0);
    super::client_ip::resolve(request.headers(), peer, trusted)
}

/// A limiter allowing one address `max` requests per `window`, believing the
/// deployment's trusted proxies about who the address is.
pub(crate) fn per_address(
    state: &crate::state::ApiState,
    max: u32,
    window: std::time::Duration,
) -> IpRateLimitState {
    IpRateLimitState::new(IpRateLimitConfig {
        max_attempts: max,
        window,
        trusted_proxies: state.trusted_proxies.as_ref().clone(),
        max_tracked_ips: state.http.rate.max_tracked_ips,
    })
}

#[cfg(test)]
mod tests {
    use tower::ServiceExt as _;

    use super::*;
    use crate::middleware::client_ip::TrustedProxies;

    /// A limit of so many attempts per window, trusting no proxy.
    fn config(max_attempts: u32, window: Duration) -> IpRateLimitConfig {
        IpRateLimitConfig {
            max_attempts,
            window,
            trusted_proxies: TrustedProxies::default(),
            max_tracked_ips: 100_000,
        }
    }

    /// Requests up to the limit all go through.
    #[test]
    fn allows_under_limit() {
        let state = IpRateLimitState::new(config(3, Duration::from_secs(60)));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(state.check_and_increment(ip));
        assert!(state.check_and_increment(ip));
        assert!(state.check_and_increment(ip));
    }

    /// One address can use its two permitted requests, but not a third.
    #[test]
    fn rejects_over_limit() {
        let state = IpRateLimitState::new(config(2, Duration::from_secs(60)));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(state.check_and_increment(ip));
        assert!(state.check_and_increment(ip));
        assert!(!state.check_and_increment(ip));
    }

    /// A refused address is told how long until one request is back: three
    /// seconds at most, at twenty a minute.
    #[test]
    fn a_refusal_says_when_to_try_again() {
        let state = IpRateLimitState::new(config(20, Duration::from_secs(60)));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..20 {
            assert!(state.check_and_increment(ip));
        }

        let Err(wait) = state.admit(ip) else {
            panic!("the twenty-first request in the minute is refused");
        };

        assert!(
            wait > Duration::ZERO && wait <= Duration::from_secs(3),
            "{wait:?}"
        );
    }

    /// `Retry-After` is whole seconds, rounded up and never zero.
    #[test]
    fn retry_after_is_whole_seconds_rounded_up() {
        assert_eq!(retry_after_seconds(Duration::from_millis(200)), 1);
        assert_eq!(retry_after_seconds(Duration::ZERO), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(2500)), 3);
        assert_eq!(retry_after_seconds(Duration::from_secs(4)), 4);
    }

    /// An exhausted address receives 429 with a sixty-second Retry-After value.
    #[tokio::test]
    async fn the_refusal_carries_retry_after() {
        let state = IpRateLimitState::new(config(1, Duration::from_secs(60)));
        let app = axum::Router::new()
            .route("/", axum::routing::post(|| async {}))
            .layer(axum::middleware::from_fn_with_state(state, ip_rate_limit));
        let request = || {
            let mut request = axum::http::Request::post("/")
                .body(axum::body::Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(std::net::SocketAddr::from((
                    [10, 0, 0, 9],
                    5000,
                ))));
            request
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        let second = app.oneshot(request()).await.unwrap();

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second.headers()[axum::http::header::RETRY_AFTER], "60");
    }

    /// One address at its limit does not hold back another.
    #[test]
    fn different_ips_have_separate_counters() {
        let state = IpRateLimitState::new(config(1, Duration::from_secs(60)));
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        assert!(state.check_and_increment(ip1));
        assert!(!state.check_and_increment(ip1));
        assert!(state.check_and_increment(ip2));
    }

    /// An immediate retry is refused after the address spends its allowance.
    #[test]
    fn a_burst_at_the_turn_of_a_window_gets_no_second_allowance() {
        let state = IpRateLimitState::new(config(2, Duration::from_secs(60)));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        state.check_and_increment(ip);
        state.check_and_increment(ip);

        assert!(!state.check_and_increment(ip));
    }

    /// Tens of thousands of distinct addresses leave the tracked count
    /// within the configured capacity plus the shard allowance.
    #[test]
    fn map_stays_bounded_under_distinct_ips() {
        let state = IpRateLimitState::new(IpRateLimitConfig {
            max_attempts: 1,
            window: Duration::from_secs(60),
            trusted_proxies: TrustedProxies::default(),
            max_tracked_ips: 64,
        });

        for octet in 0..255u8 {
            for inner in 0..255u8 {
                let ip = IpAddr::from([10, 0, octet, inner]);
                state.check_and_increment(ip);
            }
        }

        let tracked: usize = state.shards.iter().map(|s| s.lock().unwrap().len()).sum();
        assert!(
            tracked <= 64 + SHARD_COUNT,
            "tracked {tracked} exceeded cap"
        );
    }

    /// Eviction is what keeps the map bounded, and an attacker chooses when
    /// it runs: they need only present addresses until the shard is full.
    /// If it takes a live counter with it, rotating addresses is how you
    /// clear your own rate limit: the flood becomes the bypass.
    #[test]
    fn evicting_to_stay_bounded_does_not_clear_a_live_counter() {
        let state = IpRateLimitState::new(IpRateLimitConfig {
            max_attempts: 1,
            window: Duration::from_secs(60),
            trusted_proxies: TrustedProxies::default(),
            max_tracked_ips: 64,
        });
        let blocked: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(state.check_and_increment(blocked));
        assert!(
            !state.check_and_increment(blocked),
            "the attacker is over the limit before the flood"
        );

        for octet in 0..255u8 {
            for inner in 1..255u8 {
                state.check_and_increment(IpAddr::from([172, 16, octet, inner]));
            }
        }

        assert!(
            !state.check_and_increment(blocked),
            "a flood of other addresses must not hand this one a fresh window"
        );
    }

    /// An address that has spent part of its allowance.
    fn counted(rate: Rate, at: Instant) -> IpCounter {
        let mut allowance = Allowance::full(rate, at);
        allowance.spend(rate, at);
        IpCounter {
            allowance,
            refused: false,
        }
    }

    /// A shard with room prunes nothing: the entry a legitimate caller is
    /// counted by has to survive until either its allowance is full again
    /// or the cap forces a choice.
    #[test]
    fn a_shard_with_room_evicts_nothing() {
        let rate = Rate::new(20, Duration::from_secs(60));
        let now = Instant::now();
        let mut counters = HashMap::from([("10.0.0.1".parse().unwrap(), counted(rate, now))]);

        prune(&mut counters, now, rate, 64);

        assert_eq!(counters.len(), 1);
    }

    /// At the cap, eviction makes room: one entry's worth, not the whole
    /// shard. Taking everything is the bypass above; taking nothing lets the
    /// map grow without end.
    #[test]
    fn a_full_shard_of_live_entries_gives_up_room_for_one_more() {
        let rate = Rate::new(20, Duration::from_secs(60));
        let now = Instant::now();
        let cap = 8;
        let mut counters: HashMap<IpAddr, IpCounter> = (0..cap as u8)
            .map(|n| (IpAddr::from([10, 0, 0, n]), counted(rate, now)))
            .collect();

        prune(&mut counters, now, rate, cap);

        assert_eq!(
            counters.len(),
            cap - 1,
            "a full shard of live entries makes room for exactly one"
        );
    }

    /// Entries whose allowance is full again are the first to go, and they
    /// go before any live one is touched.
    #[test]
    fn full_entries_are_evicted_before_live_ones() {
        let window = Duration::from_secs(60);
        let rate = Rate::new(20, window);
        let now = Instant::now();
        let long_ago = now - window - Duration::from_secs(1);
        let cap = 4;
        let mut counters: HashMap<IpAddr, IpCounter> = (0..3u8)
            .map(|n| (IpAddr::from([10, 0, 0, n]), counted(rate, long_ago)))
            .collect();
        let live: IpAddr = "10.0.1.1".parse().unwrap();
        counters.insert(live, counted(rate, now));

        prune(&mut counters, now, rate, cap);

        assert_eq!(counters.len(), 1);
        assert!(
            counters.contains_key(&live),
            "the entry still refilling is the one that stays"
        );
    }

    /// Without a trusted proxy, the limiter uses the peer address despite
    /// a different address in X-Forwarded-For.
    #[test]
    fn forwarded_header_ignored_without_trusted_proxy() {
        let mut request = axum::extract::Request::new(axum::body::Body::empty());
        request
            .headers_mut()
            .insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [10, 0, 0, 9],
                5000,
            ))));

        let ip = resolve_client_ip(&request, &TrustedProxies::default());
        assert_eq!(ip, Some(IpAddr::from([10, 0, 0, 9])));
    }

    /// Behind a trusted proxy, the client address comes from the header
    /// the proxy added.
    #[test]
    fn forwarded_header_used_from_trusted_proxy() {
        let mut request = axum::extract::Request::new(axum::body::Body::empty());
        request
            .headers_mut()
            .insert("x-forwarded-for", "1.2.3.4, 10.0.0.9".parse().unwrap());
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [10, 0, 0, 9],
                5000,
            ))));

        let ip = resolve_client_ip(&request, &TrustedProxies::parse("10.0.0.9"));
        assert_eq!(ip, Some(IpAddr::from([1, 2, 3, 4])));
    }

    /// A request with no known peer address has no client address at all,
    /// rather than a guessed one.
    #[test]
    fn no_socket_info_fails_closed() {
        let request = axum::extract::Request::new(axum::body::Body::empty());
        assert_eq!(
            resolve_client_ip(&request, &TrustedProxies::default()),
            None
        );
    }
}
