//! How long a password sign-in to an account waits before its password is
//! checked, from the account's failures across every origin.
//!
//! The lockout counts one origin's guesses at one account. Guesses spread
//! over many networks stay under it, so every failed password is also
//! counted against the account, from wherever it came, over the lockout's
//! window. Up to as many failures as one origin may make, nothing changes.
//! Each failure past that adds a short wait before the next attempt on the
//! account is checked, up to a cap of a few seconds. The wait never grows
//! into a lock: the owner, with the right password and from a network that
//! is not locked out, always gets through once it has passed. A sign-in
//! from a device the person trusted does not wait at all.

use time::Duration;

use crate::domains::authentication::risk_engine::pressure::FailureCount;
use crate::domains::authentication::risk_engine::rate_limit::RateLimitPolicy;
use crate::domains::authentication::risk_engine::step_up::Familiarity;

/// The wait each failure across every origin adds, past the free ones.
pub(crate) const PACE_STEP: Duration = Duration::milliseconds(250);

/// The longest a sign-in to an account ever waits.
pub const MOST_PACE: Duration = Duration::seconds(3);

/// How long a sign-in to an account waits before its password is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountPace(Duration);

impl AccountPace {
    /// The pace of an account with `failures` failed passwords counted
    /// across every origin in the window, under `policy`.
    ///
    /// As many failures as `policy` lets one origin make are free. Each
    /// one past them adds `PACE_STEP`, up to [`MOST_PACE`].
    #[must_use]
    pub fn for_failures(failures: FailureCount, policy: &RateLimitPolicy) -> Self {
        let free = u64::from(policy.max_failed_attempts());
        let past = failures.get().saturating_sub(free);
        let past = i32::try_from(past).unwrap_or(i32::MAX);
        Self(PACE_STEP.saturating_mul(past).min(MOST_PACE))
    }

    /// How long a sign-in from `device` waits. A device the person trusted
    /// does not wait.
    #[must_use]
    pub fn wait_for(self, device: Familiarity) -> Duration {
        match device {
            Familiarity::Known => Duration::ZERO,
            Familiarity::New => self.0,
        }
    }

    /// Whether nothing waits at this pace, so the device need not be asked.
    #[must_use]
    pub fn is_unhurried(self) -> bool {
        self.0.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn paced(failures: u64) -> AccountPace {
        AccountPace::for_failures(FailureCount::from(failures), &RateLimitPolicy::DEFAULT)
    }

    /// Ann mistypes her password five times under the default limit of
    /// five. Her next sign-in does not wait.
    #[test]
    fn failures_one_origin_may_make_add_no_wait() {
        assert!(paced(5).is_unhurried());
        assert_eq!(paced(5).wait_for(Familiarity::New), Duration::ZERO);
    }

    /// A botnet's failures against Ann's account pass the free five. Each
    /// further one adds a quarter of a second.
    #[test]
    fn each_failure_past_the_free_ones_adds_a_step() {
        assert_eq!(paced(6).wait_for(Familiarity::New), PACE_STEP);
        assert_eq!(
            paced(9).wait_for(Familiarity::New),
            Duration::milliseconds(1_000)
        );
    }

    /// A million failures still produce the maximum permitted pacing delay.
    #[test]
    fn the_wait_never_passes_the_cap() {
        assert_eq!(paced(1_000_000).wait_for(Familiarity::New), MOST_PACE);
    }

    /// Ann signs in on her trusted laptop while her account is being
    /// guessed at. She does not wait.
    #[test]
    fn a_trusted_device_does_not_wait() {
        assert_eq!(paced(1_000).wait_for(Familiarity::Known), Duration::ZERO);
    }

    proptest! {
        /// Whatever the counts, the wait stays between nothing and the cap,
        /// never shrinks as failures grow, is nothing up to the free ones,
        /// and is nothing on a trusted device.
        #[test]
        fn the_wait_is_bounded_and_grows_with_failures(
            max in 1u32..100,
            failures in 0u64..10_000,
            more in 0u64..10_000,
        ) {
            let policy = RateLimitPolicy::new(
                std::num::NonZeroU32::new(max).unwrap(),
                RateLimitPolicy::DEFAULT.lockout(),
                RateLimitPolicy::DEFAULT.window(),
            );
            let pace = |n: u64| AccountPace::for_failures(FailureCount::from(n), &policy);
            let now = pace(failures).wait_for(Familiarity::New);
            let later = pace(failures.saturating_add(more)).wait_for(Familiarity::New);

            prop_assert!(now >= Duration::ZERO && now <= MOST_PACE);
            prop_assert!(later >= now);
            prop_assert_eq!(failures <= u64::from(max), now.is_zero());
            prop_assert_eq!(pace(failures).wait_for(Familiarity::Known), Duration::ZERO);
        }
    }
}
