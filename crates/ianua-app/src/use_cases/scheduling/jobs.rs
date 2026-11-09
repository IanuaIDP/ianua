//! Building and reading the jobs the app queues, the same way for every
//! kind: the payload written out once, read back by the handler, under a
//! key that keeps the same work from being queued twice.

use std::fmt::Display;
use std::num::NonZeroU32;

use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::{JobKey, KeyHold};
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::types::TenantId;
use serde::Serialize;
use serde::de::DeserializeOwned;
use time::OffsetDateTime;

use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::{Enqueued, JobQueue};

/// One job to queue: what kind, for which tenant, under which key, when,
/// and how many tries it gets.
pub(crate) struct NewJob<'a, P> {
    /// The job type, which picks its handler.
    pub(crate) job_type: &'static str,
    /// What the handler reads.
    pub(crate) payload: &'a P,
    /// The tenant the job works for.
    pub(crate) tenant_id: TenantId,
    /// The key naming the work once.
    pub(crate) key: JobKey,
    /// How long the key keeps the same work from being queued again: while
    /// it waits or runs, or for as long as it is kept, for work done once
    /// per event.
    pub(crate) hold: KeyHold,
    /// When it runs.
    pub(crate) run_at: OffsetDateTime,
    /// How many tries it gets.
    pub(crate) attempts: NonZeroU32,
}

impl<P: Serialize> NewJob<'_, P> {
    /// The job, ready to queue.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the type is not a job type or the payload
    /// cannot be written out.
    pub(crate) fn build(&self) -> Result<ScheduledJob, AppError> {
        let job_type = JobType::new(self.job_type).or_internal()?;
        let payload = serde_json::to_string(self.payload).map_err(AppError::internal)?;
        let job = ScheduledJob::new(job_type, payload, self.run_at, self.attempts)
            .for_tenant(self.tenant_id);
        Ok(match self.hold {
            KeyHold::WhileLive => job.keyed(self.key.clone()),
            KeyHold::WhileKept => job.keyed_once(self.key.clone()),
        })
    }

    /// Builds the job and queues it on `queue`.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(&self, queue: &dyn JobQueue) -> Result<Enqueued, AppError> {
        let job = self.build()?;
        queue.enqueue(&job).await.or_internal()
    }
}

/// The key naming `what` done to `target`, such as an event sent to a
/// subscription.
///
/// # Errors
///
/// `AppError::Internal` when the two do not make a key.
pub(crate) fn key_of(what: impl Display, target: impl Display) -> Result<JobKey, AppError> {
    JobKey::of(what, target).or_internal()
}

/// The payload `job` carries, as its handler reads it.
///
/// # Errors
///
/// `AppError::Internal` when the payload is not the handler's.
pub(crate) fn payload_of<P: DeserializeOwned>(job: &ScheduledJob) -> Result<P, AppError> {
    serde_json::from_str(job.payload()).map_err(AppError::internal)
}

/// What planning an event came to: one job per target, some of them
/// already queued by an earlier delivery of the same event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlanReport {
    /// Jobs queued now.
    pub queued: u32,
    /// Jobs queued before, by an earlier delivery of the same event.
    pub already_queued: u32,
}

impl PlanReport {
    /// This report with one more job counted.
    #[must_use]
    pub(crate) fn counting(self, enqueued: Enqueued) -> Self {
        match enqueued {
            Enqueued::Queued => Self {
                queued: self.queued.saturating_add(1),
                ..self
            },
            Enqueued::AlreadyQueued => Self {
                already_queued: self.already_queued.saturating_add(1),
                ..self
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::scheduling::FakeJobQueue;

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Sample {
        target: String,
    }

    fn sample_job<'a>(sample: &'a Sample, key: &str) -> NewJob<'a, Sample> {
        NewJob {
            job_type: "test.sample",
            payload: sample,
            tenant_id: TenantId::new(),
            key: JobKey::new(key).unwrap(),
            hold: KeyHold::WhileLive,
            run_at: clock::now(),
            attempts: NonZeroU32::new(3).unwrap(),
        }
    }

    /// A queued job reads back as the payload it was queued with, for its
    /// tenant and under its key.
    #[test]
    fn a_job_reads_back_its_payload() {
        let sample = Sample {
            target: "hook-1".to_owned(),
        };
        let new = sample_job(&sample, "event-1:hook-1");

        let job = new.build().unwrap();

        assert_eq!(payload_of::<Sample>(&job).unwrap(), sample);
        assert_eq!(job.tenant_id(), Some(&new.tenant_id));
        assert_eq!(job.key().unwrap().as_str(), "event-1:hook-1");
    }

    /// The same event planned twice queues its job once; the second time
    /// is counted as already queued.
    #[test]
    fn the_same_key_is_queued_once() {
        let queue = Arc::new(FakeJobQueue::new());
        let sample = Sample {
            target: "hook-1".to_owned(),
        };
        let new = sample_job(&sample, "event-1:hook-1");

        let first = block_on(new.queue(queue.as_ref())).unwrap();
        let second = block_on(new.queue(queue.as_ref())).unwrap();
        let report = PlanReport::default().counting(first).counting(second);

        assert_eq!(queue.count(), 1);
        assert_eq!(
            report,
            PlanReport {
                queued: 1,
                already_queued: 1
            }
        );
    }

    /// `new` as the queue keeps it once a worker ran it to the end.
    fn completed(new: &NewJob<'_, Sample>) -> ScheduledJob {
        let mut job = new.build().unwrap();
        job.mark_running().unwrap();
        job.mark_completed().unwrap();
        job
    }

    /// Acme's event went to its webhook and the job ended. The bus delivers
    /// the event again: the job keyed once is not queued again.
    #[test]
    fn work_keyed_once_is_not_queued_again_after_it_ended() {
        let sample = Sample {
            target: "hook-1".to_owned(),
        };
        let mut new = sample_job(&sample, "event-1:hook-1");
        new.hold = KeyHold::WhileKept;
        let queue = FakeJobQueue::with_jobs(vec![completed(&new)]);

        let again = block_on(new.queue(&queue)).unwrap();

        assert_eq!(again, Enqueued::AlreadyQueued);
        assert_eq!(queue.count(), 0);
    }

    /// A run's drive ended; the run is woken again and its next drive is
    /// queued under the same key.
    #[test]
    fn work_keyed_while_live_is_queued_again_after_it_ended() {
        let sample = Sample {
            target: "run-1".to_owned(),
        };
        let new = sample_job(&sample, "run-1:drive");
        let queue = FakeJobQueue::with_jobs(vec![completed(&new)]);

        let again = block_on(new.queue(&queue)).unwrap();

        assert_eq!(again, Enqueued::Queued);
        assert_eq!(queue.count(), 1);
    }
}
