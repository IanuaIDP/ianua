//! Lanes: the job types one worker loop runs, how many at once, how long
//! each may take, and the waits between a failed job's tries.
//!
//! Each lane runs on its own, so a slow kind of work never holds up
//! another: mail goes out while certificates are still being issued.

use std::num::NonZeroU32;

use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use time::{Duration, OffsetDateTime};

/// How much longer than its slowest job a lane holds a claimed job, so a
/// job that just timed out is settled before its lease runs out.
const LEASE_MARGIN: Duration = Duration::seconds(30);

/// One kind of job a lane runs, and how long a run of it may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobKind {
    /// The handler selection used to dispatch this work.
    pub job_type: JobType,
    /// How long one run may take before it is given up and tried again.
    pub timeout: Duration,
}

/// The job types one worker loop runs, and how many of them at once.
#[derive(Debug, Clone)]
pub struct Lane {
    kinds: Vec<JobKind>,
    job_types: Vec<JobType>,
    concurrency: NonZeroU32,
    per_tenant: NonZeroU32,
}

impl Lane {
    /// A lane running `kinds`, at most `concurrency` jobs at once and at
    /// most `per_tenant` of one tenant's.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the lane runs no kind, a
    /// kind has no time to run in, or one tenant may take more than the
    /// whole lane.
    pub fn new(
        kinds: Vec<JobKind>,
        concurrency: NonZeroU32,
        per_tenant: NonZeroU32,
    ) -> Result<Self, DomainError> {
        if kinds.is_empty() {
            return Err(DomainError::invalid(message!(
                "scheduling-a-lane-runs-at-least-one",
                "a lane runs at least one job type"
            )));
        }
        if kinds.iter().any(|kind| kind.timeout <= Duration::ZERO) {
            return Err(DomainError::invalid(message!(
                "scheduling-every-job-type-has-time-to",
                "every job type has time to run in"
            )));
        }
        if per_tenant > concurrency {
            return Err(DomainError::invalid(message!(
                "scheduling-one-tenant-may-take-at-most",
                "one tenant may take at most the whole lane"
            )));
        }
        let job_types = kinds.iter().map(|kind| kind.job_type.clone()).collect();
        Ok(Self {
            kinds,
            job_types,
            concurrency,
            per_tenant,
        })
    }

    /// The job types the lane runs.
    #[must_use]
    pub fn job_types(&self) -> &[JobType] {
        &self.job_types
    }

    /// How many jobs the lane runs at once.
    #[must_use]
    pub fn concurrency(&self) -> NonZeroU32 {
        self.concurrency
    }

    /// How many of one tenant's jobs the lane runs at once.
    #[must_use]
    pub fn per_tenant(&self) -> NonZeroU32 {
        self.per_tenant
    }

    /// How long a run of `job_type` may take, or `None` when the lane does
    /// not run it.
    #[must_use]
    pub fn timeout_of(&self, job_type: &JobType) -> Option<Duration> {
        self.kinds
            .iter()
            .find(|kind| &kind.job_type == job_type)
            .map(|kind| kind.timeout)
    }

    /// How long a claim holds the lane's jobs: its slowest job's time, and a
    /// margin to settle it in.
    #[must_use]
    pub fn lease(&self) -> Duration {
        let slowest = self
            .kinds
            .iter()
            .map(|kind| kind.timeout)
            .max()
            .unwrap_or_default();
        slowest.saturating_add(LEASE_MARGIN)
    }
}

/// How long a failed job waits before it is tried again.
#[derive(Debug, Clone)]
pub struct Backoff {
    waits: Vec<Duration>,
}

impl Backoff {
    /// Waiting `waits[n]` after the `n + 1`th failure, the last wait
    /// repeating for every later one.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when `waits` is empty.
    pub fn new(waits: Vec<Duration>) -> Result<Self, DomainError> {
        if waits.is_empty() {
            return Err(DomainError::invalid(message!(
                "scheduling-a-backoff-has-at-least-one",
                "a backoff has at least one wait"
            )));
        }
        Ok(Self { waits })
    }

    /// When a job that failed on its `attempt`th try runs next.
    #[must_use]
    pub(crate) fn next_run(&self, attempt: u32) -> OffsetDateTime {
        let step = usize::try_from(attempt.saturating_sub(1)).unwrap_or(usize::MAX);
        let wait = self
            .waits
            .get(step)
            .or_else(|| self.waits.last())
            .copied()
            .unwrap_or_default();
        clock::now() + wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(job_type: &str, seconds: i64) -> JobKind {
        JobKind {
            job_type: JobType::new(job_type).unwrap(),
            timeout: Duration::seconds(seconds),
        }
    }

    fn count(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn backoff() -> Backoff {
        Backoff::new(
            [300, 900, 3600, 21600, 86400]
                .map(Duration::seconds)
                .to_vec(),
        )
        .unwrap()
    }

    /// A lane for mail and webhooks holds a claimed job as long as its
    /// slowest kind may take, and half a minute more to settle it.
    #[test]
    fn a_lane_holds_jobs_as_long_as_its_slowest_kind_and_a_margin() {
        let lane = Lane::new(
            vec![kind("mail.send", 30), kind("webhooks.deliver", 60)],
            count(8),
            count(2),
        )
        .unwrap();

        assert_eq!(lane.lease(), Duration::seconds(90));
        assert_eq!(
            lane.timeout_of(&JobType::new("mail.send").unwrap()),
            Some(Duration::seconds(30))
        );
    }

    /// A lane that runs nothing, or a kind with no time to run in, is
    /// refused.
    #[test]
    fn an_empty_lane_or_a_kind_without_time_is_refused() {
        assert!(Lane::new(Vec::new(), count(4), count(1)).is_err());
        assert!(Lane::new(vec![kind("mail.send", 0)], count(4), count(1)).is_err());
    }

    /// One tenant may not be given more of a lane than the lane holds.
    #[test]
    fn a_tenant_share_above_the_lane_is_refused() {
        let result = Lane::new(vec![kind("mail.send", 30)], count(2), count(3));

        assert!(result.is_err());
    }

    /// A backoff with no wait at all is refused: a failed job would retry
    /// at once, again and again.
    #[test]
    fn a_backoff_without_a_wait_is_refused() {
        assert!(Backoff::new(Vec::new()).is_err());
    }

    /// Each attempt waits its own step: a longer wait than the backoff says
    /// is as wrong as a shorter one, since it is what a retry storm and a
    /// stalled queue look like respectively.
    #[test]
    fn each_attempt_waits_its_own_step_of_the_backoff() {
        let steps = [
            (0u32, 300i64),
            (1, 300),
            (2, 900),
            (3, 3600),
            (4, 21600),
            (5, 86400),
            (9, 86400),
        ];

        for (attempt, expected) in steps {
            let now = clock::now();
            let delay = backoff().next_run(attempt) - now;

            assert!(
                (delay - Duration::seconds(expected)).abs() < Duration::seconds(10),
                "attempt {attempt} waited {delay} rather than {expected}s"
            );
        }
    }
}
