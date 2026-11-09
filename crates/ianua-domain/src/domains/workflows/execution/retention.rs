//! How long a run that ended is kept before the worker removes it.
//!
//! Each run a person or a trigger started holds what its steps read and
//! made: inputs, outputs and the people it acted for. So a run does not
//! stay for ever. What happened stays in the audit trail, which keeps it
//! as long as the tenant's compliance asks.
//!
//! A deployment may keep runs longer or shorter, but not shorter than
//! [`FEWEST_RUN_DAYS`]: an evaluation names the test runs it read, and
//! is removed [`EVALUATIONS_KEPT_DAYS`] days after it ended, so a test run
//! must outlast every evaluation that could still name it.
//!
//! [`EVALUATIONS_KEPT_DAYS`]: crate::domains::workflows::evaluation::run::EVALUATIONS_KEPT_DAYS

use time::{Duration, OffsetDateTime};

use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;

/// How many days an ended run is kept unless the deployment says otherwise.
pub const RUNS_KEPT_DAYS: u32 = 90;

/// The fewest days a deployment may keep an ended run: comfortably longer
/// than an evaluation, which reads test runs, is kept.
pub(crate) const FEWEST_RUN_DAYS: u32 = 60;

/// The most days a deployment may keep an ended run: ten years.
const MOST_RUN_DAYS: u32 = 3_650;

/// How long ended runs are kept here, within what a deployment may set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunsKept(u32);

impl RunsKept {
    /// Runs kept for `days` days.
    ///
    /// # Errors
    ///
    /// [`ValidationError`] when `days` is below [`FEWEST_RUN_DAYS`] or
    /// above ten years.
    pub fn for_days(days: u32) -> Result<Self, ValidationError> {
        validate_range(
            "workflow_runs_kept_days",
            days,
            FEWEST_RUN_DAYS..=MOST_RUN_DAYS,
        )?;
        Ok(Self(days))
    }

    /// The moment before which a run that ended is removed, at `now`.
    #[must_use]
    pub fn since(self, now: OffsetDateTime) -> OffsetDateTime {
        now.saturating_sub(Duration::days(i64::from(self.0)))
    }
}

impl Default for RunsKept {
    fn default() -> Self {
        Self(RUNS_KEPT_DAYS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::evaluation::run::EVALUATIONS_KEPT_DAYS;

    /// By default a run ended ninety days and an hour ago is past its
    /// keeping and one ended ninety days less an hour ago is not.
    #[test]
    fn the_default_keeps_a_run_ninety_days() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(1_000);
        let cutoff = RunsKept::default().since(now);

        assert!(now - Duration::days(90) - Duration::HOUR < cutoff);
        assert!(now - Duration::days(90) + Duration::HOUR > cutoff);
    }

    /// A deployment cannot keep runs for so little that a test run goes
    /// before the evaluation that read it, or for longer than ten years.
    #[test]
    fn a_keeping_outside_its_range_is_refused() {
        assert!(RunsKept::for_days(FEWEST_RUN_DAYS - 1).is_err());
        assert!(RunsKept::for_days(MOST_RUN_DAYS + 1).is_err());
        assert!(RunsKept::for_days(FEWEST_RUN_DAYS).is_ok());
    }

    /// The fewest days a run may be kept outlasts an evaluation's keeping
    /// by a month, so an evaluation is always removed before a test run
    /// it read.
    #[test]
    fn a_run_outlasts_every_evaluation_that_could_read_it() {
        assert!(i64::from(FEWEST_RUN_DAYS) >= EVALUATIONS_KEPT_DAYS + 30);
    }
}
