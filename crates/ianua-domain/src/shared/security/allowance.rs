//! How many requests a caller may make: an allowance that refills at a
//! steady pace, so no stretch of time ever lets through more than the rate.
//!
//! A count reset every minute lets a caller send the whole minute's limit at
//! the end of one minute and again at the start of the next: twice the limit
//! in a few seconds. Here each request spends one unit, and units come back
//! one at a time, evenly over the period. A caller who has been quiet starts
//! with the full allowance; one who has spent it waits for each unit as it
//! returns.

use std::time::{Duration, Instant};

/// So many requests per so long, the most an allowance holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    max: u32,
    per: Duration,
}

impl Rate {
    /// `max` requests per `per`. A zero `max` or `per` lets nothing through.
    #[must_use]
    pub fn new(max: u32, per: Duration) -> Self {
        Self { max, per }
    }

    /// The most requests the allowance holds at once.
    #[must_use]
    pub fn max(&self) -> u32 {
        self.max
    }

    /// The most the allowance holds, in parts of a request.
    fn capacity(&self) -> u128 {
        u128::from(self.max) * PARTS
    }

    /// How many parts of a request come back in `elapsed`.
    fn refilled_in(&self, elapsed: Duration) -> u128 {
        elapsed
            .as_nanos()
            .saturating_mul(self.capacity())
            .checked_div(self.per.as_nanos())
            .unwrap_or(0)
    }

    /// How long `parts` of a request take to come back, rounded up. A zero
    /// rate gives nothing back, so the answer is its whole period.
    fn time_to_refill(&self, parts: u128) -> Duration {
        let capacity = self.capacity();
        if capacity == 0 {
            return self.per;
        }
        let nanos = self.per.as_nanos().saturating_mul(parts).div_ceil(capacity);
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

/// The parts one request is counted in, so a request that has partly come
/// back is not lost between counts.
const PARTS: u128 = 1_000_000;

/// What one caller has left of a [`Rate`].
#[derive(Debug, Clone, Copy)]
pub struct Allowance {
    left: u128,
    counted_at: Instant,
}

impl Allowance {
    /// A caller seen for the first time at `now`: the full allowance.
    #[must_use]
    pub fn full(rate: Rate, now: Instant) -> Self {
        Self {
            left: rate.capacity(),
            counted_at: now,
        }
    }

    /// Spends one request at `now`, and gives the whole requests left, or
    /// `None` when none is left and the request is refused.
    pub fn spend(&mut self, rate: Rate, now: Instant) -> Option<u32> {
        self.refill(rate, now);
        self.left = self.left.checked_sub(PARTS)?;
        u32::try_from(self.left / PARTS).ok()
    }

    /// Whether the allowance is back to full at `now`, so forgetting the
    /// caller changes nothing.
    #[must_use]
    pub fn is_full_at(&self, rate: Rate, now: Instant) -> bool {
        self.left_at(rate, now) >= rate.capacity()
    }

    /// Whether the caller has nothing left at `now`, so their requests are
    /// being refused.
    #[must_use]
    pub fn is_spent_at(&self, rate: Rate, now: Instant) -> bool {
        self.left_at(rate, now) < PARTS
    }

    /// How long from `now` until a whole request is back, so a refused
    /// caller can be told when to try again: nothing when one is left.
    #[must_use]
    pub fn wait_at(&self, rate: Rate, now: Instant) -> Duration {
        let missing = PARTS.saturating_sub(self.left_at(rate, now));
        if missing == 0 {
            return Duration::ZERO;
        }
        rate.time_to_refill(missing)
    }

    /// What is left at `now`, with what came back since the last count,
    /// up to the rate's most.
    fn left_at(&self, rate: Rate, now: Instant) -> u128 {
        let elapsed = now.saturating_duration_since(self.counted_at);
        self.left
            .saturating_add(rate.refilled_in(elapsed))
            .min(rate.capacity())
    }

    /// Adds back what came in since the last count.
    fn refill(&mut self, rate: Rate, now: Instant) {
        self.left = self.left_at(rate, now);
        self.counted_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    /// A caller seen for the first time may send the whole rate at once.
    #[test]
    fn a_new_caller_starts_with_the_whole_rate() {
        let rate = Rate::new(3, MINUTE);
        let now = Instant::now();
        let mut allowance = Allowance::full(rate, now);

        let spent: Vec<_> = (0..4).map(|_| allowance.spend(rate, now)).collect();

        assert_eq!(spent, [Some(2), Some(1), Some(0), None]);
    }

    /// After exhausting 2000 requests, ten seconds restores only 333 whole
    /// requests rather than resetting the minute's entire allowance.
    #[test]
    fn a_burst_across_a_minute_boundary_gets_no_second_allowance() {
        let rate = Rate::new(2000, MINUTE);
        let start = Instant::now();
        let mut allowance = Allowance::full(rate, start);
        for _ in 0..2000 {
            allowance.spend(rate, start);
        }

        let later = start + Duration::from_secs(10);
        let through = (0..2000)
            .filter(|_| allowance.spend(rate, later).is_some())
            .count();

        assert_eq!(through, 333);
    }

    /// Units come back evenly: a caller who spent everything gets one back
    /// after a sixtieth of a minute, at sixty a minute.
    #[test]
    fn a_spent_allowance_returns_one_request_at_a_time() {
        let rate = Rate::new(60, MINUTE);
        let start = Instant::now();
        let mut allowance = Allowance::full(rate, start);
        for _ in 0..60 {
            allowance.spend(rate, start);
        }

        assert!(allowance.spend(rate, start).is_none());
        assert!(
            allowance
                .spend(rate, start + Duration::from_secs(1))
                .is_some()
        );
    }

    /// A quiet caller's allowance never grows past the rate.
    #[test]
    fn a_long_quiet_never_holds_more_than_the_rate() {
        let rate = Rate::new(5, MINUTE);
        let start = Instant::now();
        let mut allowance = Allowance::full(rate, start);
        allowance.spend(rate, start);

        let much_later = start + Duration::from_secs(3600);

        assert!(allowance.is_full_at(rate, much_later));
        assert_eq!(allowance.spend(rate, much_later), Some(4));
    }

    /// A caller with nothing left is known to be refused until a unit
    /// comes back.
    #[test]
    fn a_spent_allowance_is_known_as_spent() {
        let rate = Rate::new(1, MINUTE);
        let start = Instant::now();
        let mut allowance = Allowance::full(rate, start);
        allowance.spend(rate, start);

        assert!(allowance.is_spent_at(rate, start));
        assert!(!allowance.is_spent_at(rate, start + MINUTE));
    }

    /// A caller who spent everything is told how long until one request is
    /// back: a second, at sixty a minute.
    #[test]
    fn a_spent_allowance_says_when_one_request_is_back() {
        let rate = Rate::new(60, MINUTE);
        let start = Instant::now();
        let mut allowance = Allowance::full(rate, start);
        for _ in 0..60 {
            allowance.spend(rate, start);
        }

        assert_eq!(allowance.wait_at(rate, start), Duration::from_secs(1));
        assert_eq!(
            allowance.wait_at(rate, start + Duration::from_millis(400)),
            Duration::from_millis(600)
        );
    }

    /// A caller with a request left waits for nothing.
    #[test]
    fn an_allowance_with_a_request_left_waits_for_nothing() {
        let rate = Rate::new(3, MINUTE);
        let now = Instant::now();
        let mut allowance = Allowance::full(rate, now);
        allowance.spend(rate, now);

        assert_eq!(allowance.wait_at(rate, now), Duration::ZERO);
    }

    /// A zero rate gives nothing back, so the wait is its whole period.
    #[test]
    fn a_zero_rate_waits_its_whole_period() {
        let rate = Rate::new(0, MINUTE);
        let now = Instant::now();
        let allowance = Allowance::full(rate, now);

        assert_eq!(allowance.wait_at(rate, now), MINUTE);
    }

    /// A zero rate lets nothing through.
    #[test]
    fn a_zero_rate_refuses_everything() {
        let rate = Rate::new(0, MINUTE);
        let now = Instant::now();
        let mut allowance = Allowance::full(rate, now);

        assert!(allowance.spend(rate, now).is_none());
    }
}
