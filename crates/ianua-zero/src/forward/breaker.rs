//! What real traffic says about one backend.
//!
//! The health probe asks a backend whether it is well; the breaker watches
//! what happens when it is used, since a backend can answer its probe and
//! fail everything behind it. After the service's number of failures in a
//! row the backend is set aside for the cooldown, then let back in to find
//! out. Every request may go while it is half open: the probe is already
//! the careful prober, and a shared slot would put contention on every
//! request. A failure while half open sets it aside again at once.
//!
//! It decides availability, never who is let in. A breaker that is off
//! leaves the backend to the health probe alone.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ianua_domain::domains::routing::backend::circuit_breaker::CircuitBreaker;

/// What the open circuit's opening time reads while the circuit is closed.
const CLOSED: u64 = 0;

/// One backend's breaker. Lock free: it is read on every request.
pub(super) struct Breaker {
    rule: CircuitBreaker,
    epoch: Instant,
    failures: AtomicU32,
    opened_at: AtomicU64,
}

impl Breaker {
    /// A closed breaker following `rule`.
    pub(super) fn new(rule: CircuitBreaker) -> Self {
        Self {
            rule,
            epoch: Instant::now(),
            failures: AtomicU32::new(0),
            opened_at: AtomicU64::new(CLOSED),
        }
    }

    /// Whether the backend may take traffic at `now`: the circuit is
    /// closed, or its cooldown has passed.
    pub(super) fn allows_traffic(&self, now: Instant) -> bool {
        let Some(settings) = self.rule.settings() else {
            return true;
        };
        let opened = self.opened_at.load(Ordering::Acquire);
        if opened == CLOSED {
            return true;
        }
        let cooldown = settings.cooldown_secs().std_duration();
        self.since_epoch(now).saturating_sub(opened) >= millis(cooldown)
    }

    /// The backend answered: the count starts again and the circuit closes.
    pub(super) fn record_success(&self) {
        self.failures.store(0, Ordering::Release);
        self.opened_at.store(CLOSED, Ordering::Release);
    }

    /// The backend failed at `now`; enough failures in a row open the
    /// circuit, or open it again.
    pub(super) fn record_failure(&self, now: Instant) {
        let Some(settings) = self.rule.settings() else {
            return;
        };
        let failures = self
            .failures
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                Some(n.saturating_add(1))
            })
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        if failures < settings.failure_threshold() {
            return;
        }
        self.opened_at
            .store(self.since_epoch(now), Ordering::Release);
    }

    /// Milliseconds from this breaker's start to `now`, never zero.
    fn since_epoch(&self, now: Instant) -> u64 {
        millis(now.saturating_duration_since(self.epoch)).saturating_add(1)
    }
}

/// `duration` in whole milliseconds.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::backend::circuit_breaker::BreakerSettings;
    use ianua_domain::types::Seconds;

    use super::*;

    fn breaker(threshold: u32, cooldown_secs: u32) -> Breaker {
        let settings = BreakerSettings::new(threshold, Seconds::new(cooldown_secs)).unwrap();
        Breaker::new(CircuitBreaker::On(settings))
    }

    fn later(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    #[test]
    fn a_new_breaker_lets_traffic_through() {
        assert!(breaker(3, 30).allows_traffic(Instant::now()));
    }

    #[test]
    fn failures_short_of_the_threshold_leave_it_closed() {
        let breaker = breaker(3, 30);

        breaker.record_failure(Instant::now());
        breaker.record_failure(Instant::now());

        assert!(breaker.allows_traffic(Instant::now()));
    }

    #[test]
    fn the_threshold_sets_the_backend_aside() {
        let breaker = breaker(3, 30);

        for _ in 0..3 {
            breaker.record_failure(Instant::now());
        }

        assert!(!breaker.allows_traffic(Instant::now()));
    }

    #[test]
    fn an_answer_starts_the_count_again() {
        let breaker = breaker(2, 30);

        breaker.record_failure(Instant::now());
        breaker.record_success();
        breaker.record_failure(Instant::now());

        assert!(breaker.allows_traffic(Instant::now()));
    }

    /// Recovery without anyone stepping in: once the cooldown passes,
    /// traffic is let back to find out.
    #[test]
    fn the_backend_is_let_back_after_the_cooldown() {
        let breaker = breaker(1, 30);

        breaker.record_failure(Instant::now());

        assert!(!breaker.allows_traffic(later(29)));
        assert!(breaker.allows_traffic(later(31)));
    }

    #[test]
    fn a_failure_while_half_open_sets_it_aside_again() {
        let breaker = breaker(1, 30);
        breaker.record_failure(Instant::now());

        breaker.record_failure(later(31));

        assert!(!breaker.allows_traffic(later(40)));
        assert!(breaker.allows_traffic(later(62)));
    }

    #[test]
    fn a_breaker_that_is_off_never_sets_a_backend_aside() {
        let breaker = Breaker::new(CircuitBreaker::Off);

        for _ in 0..50 {
            breaker.record_failure(Instant::now());
        }

        assert!(breaker.allows_traffic(Instant::now()));
    }
}
