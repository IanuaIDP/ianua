//! Retry a dead job: an operator gives a job that used up its tries one
//! more attempt, once whatever made it fail is put right.

use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::types::JobId;

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::{JobQueue, Retried};
use crate::use_case::Command;
use crate::use_cases::scheduling::lookup::existing_job;

/// The ports [`RetryDeadUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RetryDeadPorts {
    /// The job queue the job goes back on.
    pub queue: Arc<dyn JobQueue>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Puts a dead job back on the queue for one more attempt.
pub struct RetryDeadUseCase {
    ports: RetryDeadPorts,
}

impl RetryDeadUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RetryDeadPorts) -> Self {
        Self { ports }
    }
}

impl Command for RetryDeadUseCase {
    type Caller = OperatorCaller;
    type Input = JobId;
    type Output = Result<(), AppError>;

    /// Gives the dead job `job_id` one more attempt, due at once, and
    /// records `operator.dead_job_retried` naming the operator and the
    /// job, never what the job carries.
    ///
    /// The job runs once more. Of two operators retrying it at once, one
    /// puts it back; a job that waits, runs or finished is not retried.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's operator or key no
    ///   longer exists; `AppError::Forbidden` when the key no longer works
    ///   or its operator is disabled.
    /// - `AppError::NotFound` when the queue holds no such job.
    /// - `AppError::Conflict` when the job is not dead, was retried by
    ///   someone else meanwhile, or the same work waits or runs already.
    /// - `AppError::Internal` on queue or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        job_id: JobId,
    ) -> Result<(), AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let order = authority.job_retry();
        let mut job = existing_job(self.ports.queue.as_ref(), &job_id).await?;
        job.retry(&order).map_err(AppError::from_domain)?;
        let retried = self.ports.queue.retry(&job).await.or_internal()?;
        ensure_queued(retried)?;
        auditor
            .dispatch_by(&authority.actor(), authority.dead_job_retried(&job))
            .await
            .or_internal()
    }
}

/// Refuses a retry the queue did not carry out.
fn ensure_queued(retried: Retried) -> Result<(), AppError> {
    match retried {
        Retried::Queued => Ok(()),
        Retried::NoLongerDead => Err(AppError::Conflict(message!(
            "scheduling-the-job-is-dead-no-more",
            "the job is dead no more: someone retried or removed it meanwhile"
        ))),
        Retried::SameWorkQueued => Err(AppError::Conflict(message!(
            "scheduling-the-same-work-waits-or-runs-already",
            "the same work waits or runs already"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::scheduling::job::{NextAttempt, ScheduledJob};
    use ianua_domain::domains::scheduling::job_key::JobKey;
    use ianua_domain::domains::scheduling::job_status::JobStatus;
    use ianua_domain::domains::scheduling::job_type::JobType;
    use ianua_domain::shared::clock;
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::{test_operator_caller, test_operator_id};
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// Ann's address, which the payload of her mail names.
    const ANN: &str = "ann@acme.com";

    struct Setup {
        uc: RetryDeadUseCase,
        queue: Arc<FakeJobQueue>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn holding(jobs: Vec<ScheduledJob>, authorities: FakeOperatorAuthorities) -> Self {
            let queue = Arc::new(FakeJobQueue::with_jobs(jobs));
            let uc = RetryDeadUseCase::new(RetryDeadPorts {
                queue: queue.clone(),
                operator_authorities: Arc::new(authorities),
            });
            Self {
                uc,
                queue,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn with(jobs: Vec<ScheduledJob>) -> Self {
            Self::holding(jobs, FakeOperatorAuthorities::admitting())
        }

        fn retry(&self, job: JobId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                job,
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn stored(&self, job: &JobId) -> ScheduledJob {
            block_on(self.queue.find(job)).unwrap().unwrap()
        }
    }

    /// A mail to Ann that bounced on its only try, under `key` if given.
    fn bounced_mail(key: Option<&str>) -> ScheduledJob {
        let job = ScheduledJob::new(
            JobType::new("mail.send").unwrap(),
            format!(r#"{{"to":"{ANN}"}}"#),
            clock::now(),
            NonZeroU32::MIN,
        );
        let mut job = match key {
            Some(key) => job.keyed(JobKey::of("mail", key).unwrap()),
            None => job,
        };
        job.mark_running().unwrap();
        job.mark_failed(UntrustedText::record("bounced"), NextAttempt::AsScheduled)
            .unwrap();
        job
    }

    /// Bob retries the bounced mail once the mail service is back. It
    /// waits again with one more attempt, and the retry is recorded once.
    #[test]
    fn a_dead_job_goes_back_on_the_queue_and_the_retry_is_recorded() {
        let mail = bounced_mail(None);
        let id = *mail.id();
        let setup = Setup::with(vec![mail]);

        setup.retry(id).unwrap();

        let stored = setup.stored(&id);
        assert_eq!(stored.status(), JobStatus::Pending);
        assert_eq!(stored.max_attempts().get(), 2);
        assert_eq!(setup.recorded(), vec!["operator.dead_job_retried"]);
    }

    /// Bob retries the mail twice. The second retry finds it waiting, is
    /// refused as a conflict, and records nothing more.
    #[test]
    fn a_second_retry_of_the_same_job_is_refused() {
        let mail = bounced_mail(None);
        let id = *mail.id();
        let setup = Setup::with(vec![mail]);
        setup.retry(id).unwrap();

        let again = setup.retry(id);

        assert!(matches!(again, Err(AppError::Conflict(_))));
        assert_eq!(setup.stored(&id).max_attempts().get(), 2);
        assert_eq!(setup.recorded(), vec!["operator.dead_job_retried"]);
    }

    /// A mail still waiting for its first try is not dead, so Bob's retry
    /// is refused and nothing is recorded.
    #[test]
    fn a_job_that_is_not_dead_is_refused() {
        let waiting = ScheduledJob::new(
            JobType::new("mail.send").unwrap(),
            "{}".to_owned(),
            clock::now(),
            NonZeroU32::MIN,
        );
        let id = *waiting.id();
        let setup = Setup::with(vec![waiting]);

        let result = setup.retry(id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.recorded().is_empty());
    }

    /// An id the queue holds no job for is not found.
    #[test]
    fn an_unknown_job_is_not_found() {
        let setup = Setup::with(Vec::new());

        let result = setup.retry(JobId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// The same mail was queued again under its key and waits. Retrying
    /// the dead one would send it twice, so it is refused and stays dead.
    #[test]
    fn a_dead_job_whose_work_waits_again_is_left_dead() {
        let dead = bounced_mail(Some("welcome-ann"));
        let id = *dead.id();
        let setup = Setup::with(vec![dead]);
        let twin = ScheduledJob::new(
            JobType::new("mail.send").unwrap(),
            "{}".to_owned(),
            clock::now(),
            NonZeroU32::MIN,
        )
        .keyed(JobKey::of("mail", "welcome-ann").unwrap());
        block_on(setup.queue.enqueue(&twin)).unwrap();

        let result = setup.retry(id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.stored(&id).status(), JobStatus::Dead);
        assert!(setup.recorded().is_empty());
    }

    /// A disabled operator's key retries nothing.
    #[test]
    fn a_disabled_operator_is_refused() {
        let mail = bounced_mail(None);
        let id = *mail.id();
        let setup = Setup::holding(
            vec![mail],
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
        );

        let result = setup.retry(id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored(&id).status(), JobStatus::Dead);
    }

    /// The record names the job and Bob and never the mail's contents.
    #[test]
    fn the_record_never_holds_what_the_job_carries() {
        let mail = bounced_mail(None);
        let id = *mail.id();
        let setup = Setup::with(vec![mail]);

        setup.retry(id).unwrap();

        let payload = setup.audit.payload_of("operator.dead_job_retried");
        assert_eq!(payload.get("job_id"), Some(id.to_string().as_str()));
        assert_eq!(
            payload.get("retried_by"),
            Some(test_operator_id().to_string().as_str())
        );
        assert!(!format!("{payload:?}").contains(ANN));
    }
}
