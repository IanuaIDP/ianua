//! Sweeps: work the platform does again and again on a fixed period, such
//! as purging expired records, run once each period however many workers
//! are up.

use time::{Duration, OffsetDateTime};

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};

text_value! {
    /// The name of a sweep, such as `audit.purge_expired_records`.
    ///
    /// Lowercase letters, digits, `_` and `.`, at most 128 characters.
    pub struct SweepName;
}

impl TextValue for SweepName {
    const FIELD: &'static str = "sweep_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=128,
            Charset::LOWERCASE | Charset::DIGIT | Charset::UNDERSCORE | Charset::DOT,
        )
    }
}

/// The shortest period a sweep may run on. Anything sooner is a job, not a
/// sweep.
const SHORTEST: Duration = Duration::MINUTE;

/// The longest period a sweep may run on, so a missed round is made up
/// within a week.
const LONGEST: Duration = Duration::WEEK;

/// How often a sweep runs: a whole number of seconds, from a minute to a
/// week.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepPeriod(Duration);

impl SweepPeriod {
    /// A period of `every`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is shorter than a minute,
    ///   longer than a week, or not a whole number of seconds.
    pub fn new(every: Duration) -> Result<Self, DomainError> {
        if every < SHORTEST || every > LONGEST {
            return Err(DomainError::invalid(message!(
                "scheduling-a-sweep-runs-at-most-once",
                "a sweep runs at most once a minute and at least once a week"
            )));
        }
        if every.subsec_nanoseconds() != 0 {
            return Err(DomainError::invalid(message!(
                "scheduling-a-sweep-s-period-is-a",
                "a sweep's period is a whole number of seconds"
            )));
        }
        Ok(Self(every))
    }

    /// The period.
    #[must_use]
    pub fn get(self) -> Duration {
        self.0
    }
}

/// One round of a sweep: the period that a moment falls in, counted from
/// the Unix epoch. Every worker counts the same rounds, so "round 4711 of
/// the purge" names the same stretch of time on each of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SweepRound(i64);

impl SweepRound {
    /// The round of a sweep running every `period` that `at` falls in.
    #[must_use]
    pub fn at(at: OffsetDateTime, period: SweepPeriod) -> Self {
        let seconds = period.get().whole_seconds().max(1);
        Self(
            at.unix_timestamp()
                .checked_div_euclid(seconds)
                .unwrap_or_default(),
        )
    }

    /// The round's number.
    #[must_use]
    pub fn number(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn period(every: Duration) -> SweepPeriod {
        SweepPeriod::new(every).unwrap()
    }

    /// Hourly and daily periods are accepted.
    #[test]
    fn an_hour_and_a_day_are_periods() {
        assert!(SweepPeriod::new(Duration::HOUR).is_ok());
        assert!(SweepPeriod::new(Duration::DAY).is_ok());
    }

    /// A sweep every second would be a busy loop, and one every month would
    /// leave expired records lying about: both are refused.
    #[test]
    fn a_period_outside_a_minute_to_a_week_is_refused() {
        assert!(SweepPeriod::new(Duration::SECOND).is_err());
        assert!(SweepPeriod::new(Duration::days(30)).is_err());
    }

    /// A period with a fraction of a second is refused, since rounds are
    /// counted in whole seconds.
    #[test]
    fn a_fractional_period_is_refused() {
        assert!(SweepPeriod::new(Duration::milliseconds(60_500)).is_err());
    }

    /// Two moments in the same hour fall in the same hourly round, and the
    /// next hour is the next round.
    #[test]
    fn moments_in_one_period_share_a_round() {
        let hourly = period(Duration::HOUR);
        let start = OffsetDateTime::from_unix_timestamp(7_200).unwrap();

        let early = SweepRound::at(start, hourly);
        let late = SweepRound::at(start + Duration::minutes(59), hourly);
        let next = SweepRound::at(start + Duration::HOUR, hourly);

        assert_eq!(early, late);
        assert_eq!(next.number(), early.number() + 1);
    }

    /// A sweep name keeps the dots that group it by area.
    #[test]
    fn a_sweep_name_keeps_its_dots() {
        let name = SweepName::new("audit.purge_expired_records").unwrap();

        assert_eq!(name.as_str(), "audit.purge_expired_records");
    }
}
