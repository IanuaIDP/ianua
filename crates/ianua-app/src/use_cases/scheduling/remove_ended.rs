//! Remove ended jobs: completed, dead and superseded jobs leave the queue
//! once they were queued longer ago than [`ENDED_JOBS_KEPT_DAYS`].
//!
//! A job keyed once holds its key for as long as it is kept, so an event
//! the bus delivers again queues nothing. The bus keeps events seven days,
//! and a consumer that was down catches up from there, so an ended job is
//! kept longer than that: the event cannot come again once its job is
//! gone. A dead job stays as long for operators to look into.
//!
//! It runs on a schedule, outside any request, for nobody, so no one's
//! rights are asked. The jobs are the queue's own working rows, not a
//! record of what happened, which stays in the audit trail; so nothing is
//! recorded of their removal.

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::JobQueue;
use crate::use_case::Command;

/// How long an ended job is kept, in days: longer than the bus keeps an
/// event that could be delivered again.
pub const ENDED_JOBS_KEPT_DAYS: u32 = 14;

/// The most bounded rounds of removal one run takes, so a backlog drains
/// over a few runs without one run holding the sweep past its hour.
const MOST_ROUNDS: u32 = 20;

/// The ports [`RemoveEndedJobsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveEndedJobsPorts {
    /// The queue the ended jobs are removed from.
    pub jobs: Arc<dyn JobQueue>,
}

/// Removes the ended jobs past their keeping, a bounded round at a time.
pub struct RemoveEndedJobsUseCase {
    ports: RemoveEndedJobsPorts,
}

impl RemoveEndedJobsUseCase {
    /// A sweep over `ports`.
    #[must_use]
    pub fn new(ports: RemoveEndedJobsPorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveEndedJobsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u64, AppError>;

    /// Removes ended jobs queued more than [`ENDED_JOBS_KEPT_DAYS`] ago,
    /// round after round until one removes nothing or [`MOST_ROUNDS`] ran,
    /// and says how many went.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the queue cannot be written; what earlier
    /// rounds removed stays removed, and the next run goes on.
    async fn execute(&self, (): &(), _auditor: &RequestAuditor, (): ()) -> Result<u64, AppError> {
        let mut removed = 0_u64;
        for _ in 0..MOST_ROUNDS {
            let round = self
                .ports
                .jobs
                .cleanup(ENDED_JOBS_KEPT_DAYS)
                .await
                .or_internal()?;
            removed = removed.saturating_add(round);
            if round == 0 {
                break;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::scheduling::job::ScheduledJob;
    use ianua_domain::domains::scheduling::job_key::JobKey;
    use ianua_domain::domains::scheduling::job_type::JobType;
    use ianua_domain::shared::clock;

    use super::*;
    use crate::ports::scheduling::Enqueued;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// Acme's event handed to its webhook, the job keyed once and ended.
    fn delivered_webhook() -> ScheduledJob {
        let mut job = ScheduledJob::new(
            JobType::new("webhook.deliver").unwrap(),
            "{}".to_owned(),
            clock::now(),
            NonZeroU32::MIN,
        )
        .keyed_once(JobKey::new("event-1:hook-1").unwrap());
        job.mark_running().unwrap();
        job.mark_completed().unwrap();
        job
    }

    fn sweep(queue: Arc<FakeJobQueue>) -> RemoveEndedJobsUseCase {
        RemoveEndedJobsUseCase::new(RemoveEndedJobsPorts { jobs: queue })
    }

    /// The webhook job ended a moment ago. The sweep removes nothing, and
    /// the event delivered again by the bus still queues nothing.
    #[test]
    fn an_ended_job_within_its_keeping_stays_and_holds_its_key() {
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![delivered_webhook()]));
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));

        let removed = block_on(sweep(queue.clone()).execute(&(), &auditor, ())).unwrap();

        assert_eq!(removed, 0);
        let again = ScheduledJob::new(
            JobType::new("webhook.deliver").unwrap(),
            "{}".to_owned(),
            clock::now(),
            NonZeroU32::MIN,
        )
        .keyed_once(JobKey::new("event-1:hook-1").unwrap());
        assert_eq!(
            block_on(queue.enqueue(&again)).unwrap(),
            Enqueued::AlreadyQueued
        );
    }

    /// The webhook job ended fifteen days ago, a day past its keeping;
    /// the sweep removes it, and only then may the same work be queued
    /// again.
    #[test]
    fn an_ended_job_past_its_keeping_is_removed() {
        let long_ago = clock::now() - time::Duration::days(i64::from(ENDED_JOBS_KEPT_DAYS) + 1);
        let old = {
            let _frozen = clock::freeze(long_ago);
            delivered_webhook()
        };
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![old]));
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));

        let removed = block_on(sweep(queue.clone()).execute(&(), &auditor, ())).unwrap();

        assert_eq!(removed, 1);
        assert!(queue.jobs_of("webhook.deliver").is_empty());
    }
}
