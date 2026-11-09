use std::num::NonZeroU32;

use crate::shared::validation::ValidationError;

/// How many failed deliveries in a row switch an endpoint off.
///
/// It is at least one. A limit of zero reads as "never", yet would switch an
/// endpoint off on its very first failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureLimit(NonZeroU32);

impl FailureLimit {
    /// A limit of `count` failures in a row.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `count` is zero.
    pub fn new(count: u32) -> Result<Self, ValidationError> {
        NonZeroU32::new(count)
            .map(Self)
            .ok_or(ValidationError::OutOfRange {
                field: "disable_after_failures",
                min: 1,
                max: u64::from(u32::MAX),
                actual: 0,
            })
    }

    /// A limit of `count`, which its type already keeps above zero.
    ///
    /// It is for limits fixed in code. `NonZeroU32::new(n).unwrap()` in a
    /// `const` is checked when the code compiles.
    #[must_use]
    pub const fn from_count(count: NonZeroU32) -> Self {
        Self(count)
    }

    /// The number of failures in a row.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

/// Consecutive failed deliveries to one endpoint, and when they add up to
/// switching it off.
///
/// Webhook subscriptions and security signal streams both stop delivering to
/// an endpoint that keeps failing. This is the one place that counts the
/// failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct FailureStreak(u32);

/// Whether a streak has reached the point of switching its endpoint off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Threshold {
    /// The streak is long enough.
    Reached,
    /// Not yet.
    Below,
}

/// What a failed delivery did to the endpoint it was sent to.
///
/// The caller uses it to report an endpoint as switched off at the moment
/// that happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOutcome {
    /// The failure was counted. The endpoint keeps its status.
    Counted,
    /// The failure reached the threshold and switched the endpoint off.
    Disabled,
}

impl FailureStreak {
    /// A streak of `count` failures, as stored.
    #[must_use]
    pub(crate) fn from_stored(count: u32) -> Self {
        Self(count)
    }

    /// How many deliveries in a row have failed.
    #[must_use]
    pub(crate) fn count(self) -> u32 {
        self.0
    }

    /// Counts one more failure and says whether the streak has now reached
    /// `limit`.
    pub(crate) fn record(&mut self, limit: FailureLimit) -> Threshold {
        self.0 = self.0.saturating_add(1);
        if self.0 >= limit.get() {
            return Threshold::Reached;
        }
        Threshold::Below
    }

    /// Ends the streak after a delivery that succeeded.
    pub(crate) fn reset(&mut self) {
        self.0 = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(count: u32) -> FailureLimit {
        FailureLimit::new(count).unwrap()
    }

    /// With a limit of three, the first two failures stay below it. The
    /// third reaches it, and the count reads three.
    #[test]
    fn the_streak_reaches_its_limit_on_the_limit_th_failure() {
        let mut streak = FailureStreak::default();

        assert_eq!(streak.record(limit(3)), Threshold::Below);
        assert_eq!(streak.record(limit(3)), Threshold::Below);
        assert_eq!(streak.record(limit(3)), Threshold::Reached);
        assert_eq!(streak.count(), 3);
    }

    /// A zero-failure threshold is refused rather than treated as disabling
    /// failure handling; a threshold of one remains valid.
    #[test]
    fn a_limit_of_zero_failures_is_refused() {
        assert!(FailureLimit::new(0).is_err());
        assert_eq!(limit(1).get(), 1);
    }

    /// An endpoint has failed seven times in a row, then a delivery
    /// succeeds. The streak goes back to zero.
    #[test]
    fn a_success_ends_the_streak() {
        let mut streak = FailureStreak::from_stored(7);

        streak.reset();

        assert_eq!(streak.count(), 0);
    }

    /// A streak already at the largest count fails once more. It stays at
    /// that count and still reaches the limit, instead of wrapping to zero.
    #[test]
    fn the_count_never_wraps() {
        let mut streak = FailureStreak::from_stored(u32::MAX);

        assert_eq!(streak.record(limit(5)), Threshold::Reached);
        assert_eq!(streak.count(), u32::MAX);
    }
}
