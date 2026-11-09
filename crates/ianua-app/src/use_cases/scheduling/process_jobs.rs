//! Process jobs: one round of one lane. It claims as many due jobs as the
//! lane runs at once, runs them together, each bounded by its type's
//! timeout, and settles each by how it went.
//!
//! The worker runs one loop per lane, so a lane of slow work never holds
//! up another. A round lasts at most as long as the lane's slowest job may.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::future::{Either, select};
use ianua_domain::domains::scheduling::job::{NextAttempt, ScheduledJob};
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UntrustedText;
use time::Duration;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::{JobClaim, JobQueue, JobTimer};
use crate::use_case::Command;
use crate::use_cases::scheduling::handler::{Handled, JobHandler, RetryWhen};
use crate::use_cases::scheduling::lanes::{Backoff, Lane};

/// The reason kept on a job no handler knows.
const UNHANDLED: &str = "no handler registered for job type";

/// The reason kept on a job that failed on an error of the platform's own:
/// what went wrong is logged, not shown.
const INTERNAL: &str = "the job failed on an internal error";

/// The reason kept on a job that ran out of time.
const TIMED_OUT: &str = "the job ran out of time";

/// The ports [`ProcessJobsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ProcessJobsPorts {
    /// The queue due jobs are claimed from and settled on.
    pub queue: Arc<dyn JobQueue>,
    /// Ends a job's time to run.
    pub timer: Arc<dyn JobTimer>,
}

/// How one run of a job ended, short of settling it.
enum Ran {
    /// The handler finished, with this outcome.
    Handled(Handled),
    /// The handler failed.
    Failed(AppError),
    /// The handler ran out of time and was stopped.
    TimedOut,
    /// No handler runs the job's type.
    Unhandled,
}

/// Runs one lane's due jobs through their handlers.
///
/// It runs as a background job: no one calls it, so it takes no caller.
pub struct ProcessJobsUseCase {
    ports: ProcessJobsPorts,
    lane: Lane,
    handlers: HashMap<JobType, Arc<dyn JobHandler>>,
    backoff: Backoff,
}

impl ProcessJobsUseCase {
    /// A processor for `lane` on `ports`' queue, handing each job to the
    /// handler for its type and waiting `backoff` after a failure.
    #[must_use]
    pub fn new(
        ports: ProcessJobsPorts,
        lane: Lane,
        handlers: impl IntoIterator<Item = Arc<dyn JobHandler>>,
        backoff: Backoff,
    ) -> Self {
        Self {
            ports,
            lane,
            handlers: handlers
                .into_iter()
                .map(|handler| (handler.job_type().clone(), handler))
                .collect(),
            backoff,
        }
    }

    /// Runs one job and keeps how it went.
    async fn process_one(
        &self,
        mut job: ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<(), AppError> {
        let ran = self.run(&job, auditor).await;
        self.mark(&mut job, ran).or_internal()?;
        self.ports.queue.settle(&job).await.or_internal()
    }

    /// Runs `job` through the handler for its type, giving up once its
    /// type's time is up.
    async fn run(&self, job: &ScheduledJob, auditor: &RequestAuditor) -> Ran {
        let Some(handler) = self.handlers.get(job.job_type()) else {
            return Ran::Unhandled;
        };
        let timeout = self.lane.timeout_of(job.job_type()).unwrap_or_default();
        let handled = Box::pin(handler.handle(job, auditor));
        let elapsed = Box::pin(self.ports.timer.wait(timeout));
        match select(handled, elapsed).await {
            Either::Left((Ok(outcome), _)) => Ran::Handled(outcome),
            Either::Left((Err(error), _)) => Ran::Failed(error),
            Either::Right(((), _)) => Ran::TimedOut,
        }
    }

    /// Marks `job` with how its run went.
    ///
    /// A job no handler knows is failed as scheduled, so it stays due and
    /// is picked up again until its attempts run out; a job that failed or
    /// timed out is retried on the backoff, and one whose handler asked
    /// for a retry when its handler said.
    fn mark(&self, job: &mut ScheduledJob, ran: Ran) -> Result<(), DomainError> {
        match ran {
            Ran::Handled(Handled::Done) => job.mark_completed(),
            Ran::Handled(Handled::Retry { reason, when }) => {
                let next = self.retry_at(job, when);
                job.mark_failed(UntrustedText::record(reason), next)
            }
            Ran::Failed(error) => {
                let reason = shown_reason(job, &error);
                let next = self.retry_at(job, RetryWhen::OnBackoff);
                job.mark_failed(UntrustedText::record(&reason), next)
            }
            Ran::TimedOut => {
                let next = self.retry_at(job, RetryWhen::OnBackoff);
                job.mark_failed(UntrustedText::record(TIMED_OUT), next)
            }
            Ran::Unhandled => {
                job.mark_failed(UntrustedText::record(UNHANDLED), NextAttempt::AsScheduled)
            }
        }
    }

    /// When `job` runs again, as `when` says.
    fn retry_at(&self, job: &ScheduledJob, when: RetryWhen) -> NextAttempt {
        match when {
            RetryWhen::After(wait) => NextAttempt::At(clock::now() + wait.max(Duration::ZERO)),
            RetryWhen::OnBackoff => NextAttempt::At(self.backoff.next_run(job.attempt())),
        }
    }
}

impl Command for ProcessJobsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u32, AppError>;

    /// Claims as many of the lane's due jobs as it runs at once, no more of
    /// one tenant's than its share, runs them together and settles each.
    /// A job running past its lease was held by a worker that stopped, and
    /// is handed out again.
    ///
    /// Returns the number of jobs run, however each went. Each handler
    /// records what its job changes through `auditor`; settling a job is
    /// the queue's own bookkeeping and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when claiming or settling a job fails, or a
    ///   claimed job comes back not running. Every job of the round is
    ///   still run and settled first.
    async fn execute(&self, (): &(), auditor: &RequestAuditor, (): ()) -> Result<u32, AppError> {
        let claim = JobClaim {
            job_types: self.lane.job_types(),
            limit: self.lane.concurrency(),
            per_tenant: self.lane.per_tenant(),
            lease: self.lane.lease(),
        };
        let jobs = self.ports.queue.claim(&claim).await.or_internal()?;
        let processed = u32::try_from(jobs.len()).unwrap_or(u32::MAX);
        let settled = futures_util::future::join_all(
            jobs.into_iter().map(|job| self.process_one(job, auditor)),
        )
        .await;
        settled.into_iter().collect::<Result<Vec<()>, AppError>>()?;
        Ok(processed)
    }
}

/// The reason kept on `job` for `error`, in words safe to show whoever
/// follows the job. A failure of the platform's own is logged with the job
/// and kept as a plain phrase, so no store or network detail reaches a
/// status page.
fn shown_reason(job: &ScheduledJob, error: &AppError) -> String {
    if !error.is_server_error() {
        return error.to_string();
    }
    tracing::warn!(job_id = %job.id(), job_type = %job.job_type(), %error, "job failed");
    INTERNAL.to_owned()
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::scheduling::job_key::JobKey;
    use ianua_domain::domains::scheduling::job_status::JobStatus;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::ports::scheduling::Enqueued;
    use crate::test_support::scheduling::{FakeJobQueue, FakeJobTimer};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::scheduling::lanes::JobKind;

    const RETRY: &str = "domain.verify_retry";
    const MAIL: &str = "mail.send";

    /// A handler that answers with what it was made with.
    struct Answering {
        job_type: JobType,
        answer: fn() -> Result<Handled, AppError>,
    }

    #[async_trait::async_trait]
    impl JobHandler for Answering {
        fn job_type(&self) -> &JobType {
            &self.job_type
        }

        async fn handle(
            &self,
            _job: &ScheduledJob,
            _auditor: &RequestAuditor,
        ) -> Result<Handled, AppError> {
            (self.answer)()
        }
    }

    /// A handler that never finishes, as a hung certificate authority.
    struct Hanging(JobType);

    #[async_trait::async_trait]
    impl JobHandler for Hanging {
        fn job_type(&self) -> &JobType {
            &self.0
        }

        async fn handle(
            &self,
            _job: &ScheduledJob,
            _auditor: &RequestAuditor,
        ) -> Result<Handled, AppError> {
            std::future::pending().await
        }
    }

    fn job_type(name: &str) -> JobType {
        JobType::new(name).unwrap()
    }

    fn answering(name: &str, answer: fn() -> Result<Handled, AppError>) -> Arc<dyn JobHandler> {
        Arc::new(Answering {
            job_type: job_type(name),
            answer,
        })
    }

    fn count(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    /// A lane running domain checks and mail, `concurrency` at once and
    /// one tenant's at most `per_tenant`.
    fn lane(concurrency: u32, per_tenant: u32) -> Lane {
        let kinds = [RETRY, MAIL]
            .map(|name| JobKind {
                job_type: job_type(name),
                timeout: Duration::seconds(30),
            })
            .to_vec();
        Lane::new(kinds, count(concurrency), count(per_tenant)).unwrap()
    }

    fn backoff() -> Backoff {
        Backoff::new(vec![Duration::minutes(5)]).unwrap()
    }

    fn processor_on(
        queue: Arc<FakeJobQueue>,
        timer: FakeJobTimer,
        lane: Lane,
        handlers: impl IntoIterator<Item = Arc<dyn JobHandler>>,
    ) -> ProcessJobsUseCase {
        let ports = ProcessJobsPorts {
            queue,
            timer: Arc::new(timer),
        };
        ProcessJobsUseCase::new(ports, lane, handlers, backoff())
    }

    fn processor(
        queue: Arc<FakeJobQueue>,
        handlers: impl IntoIterator<Item = Arc<dyn JobHandler>>,
    ) -> ProcessJobsUseCase {
        processor_on(queue, FakeJobTimer::Never, lane(8, 8), handlers)
    }

    fn make_job(job_type: &str) -> ScheduledJob {
        job_with_attempts(job_type, 5)
    }

    fn job_with_attempts(job_type: &str, attempts: u32) -> ScheduledJob {
        ScheduledJob::new(
            JobType::new(job_type).unwrap(),
            "{}".to_owned(),
            clock::now(),
            count(attempts),
        )
    }

    fn run(uc: &ProcessJobsUseCase) -> u32 {
        block_on(uc.execute(&(), &test_auditor(Arc::new(FakeEventDispatcher::new())), ())).unwrap()
    }

    fn dns_missing() -> Result<Handled, AppError> {
        Err(AppError::from_domain(DomainError::invalid(
            "DNS record not found",
        )))
    }

    /// A due domain check runs through its handler and is marked done.
    #[test]
    fn processes_jobs_with_matching_handler() {
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![make_job(RETRY)]));
        let uc = processor(queue.clone(), [answering(RETRY, || Ok(Handled::Done))]);

        let count = run(&uc);

        assert_eq!(count, 1);
        assert_eq!(queue.settled()[0].status(), JobStatus::Completed);
    }

    /// A domain check whose record is not found yet goes back to the queue,
    /// with the handler's reason kept on the job and a later run time.
    #[test]
    fn failing_handler_puts_the_job_back_for_later() {
        let job = make_job(RETRY);
        let due = job.run_at();
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![job]));
        let uc = processor(queue.clone(), [answering(RETRY, dns_missing)]);

        run(&uc);

        let settled = queue.settled();
        assert_eq!(settled[0].status(), JobStatus::Pending);
        assert!(settled[0].error().unwrap().contains("DNS record not found"));
        assert!(settled[0].run_at() > due);
    }

    /// An internal error containing a connection string leaves only the
    /// safe internal-failure reason on the job.
    #[test]
    fn an_internal_failure_keeps_only_a_plain_reason() {
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![make_job(RETRY)]));
        let uc = processor(
            queue.clone(),
            [answering(RETRY, || {
                Err(AppError::internal_msg("postgres://admin:hunter2@db down"))
            })],
        );

        run(&uc);

        let reason = queue.settled()[0].error().unwrap().to_owned();
        assert_eq!(reason, INTERNAL);
    }

    /// A job whose handler fails on its last attempt is given up on, not
    /// retried for ever.
    #[test]
    fn a_job_failing_its_last_attempt_is_dead() {
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![job_with_attempts(RETRY, 1)]));
        let uc = processor(queue.clone(), [answering(RETRY, dns_missing)]);

        run(&uc);

        assert_eq!(queue.settled()[0].status(), JobStatus::Dead);
    }

    /// A webhook's policy says to try again in ten seconds. The job is due
    /// again then, not on the queue's own five-minute backoff.
    #[test]
    fn a_handler_asking_for_a_retry_after_a_wait_runs_again_then() {
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![make_job(RETRY)]));
        let uc = processor(
            queue.clone(),
            [answering(RETRY, || {
                Ok(Handled::Retry {
                    reason: "endpoint answered 503",
                    when: RetryWhen::After(Duration::seconds(10)),
                })
            })],
        );

        run(&uc);

        let settled = queue.settled();
        let wait = settled[0].run_at() - clock::now();
        assert_eq!(settled[0].status(), JobStatus::Pending);
        assert!(wait <= Duration::seconds(10) && wait > Duration::seconds(5));
        assert_eq!(settled[0].error(), Some("endpoint answered 503"));
    }

    /// A hanging handler is stopped at its deadline; the job returns to
    /// pending with a timeout reason and a later run time.
    #[test]
    fn a_job_that_runs_out_of_time_is_retried_on_the_backoff() {
        let job = make_job(RETRY);
        let due = job.run_at();
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![job]));
        let uc = processor_on(
            queue.clone(),
            FakeJobTimer::UpAtOnce,
            lane(8, 8),
            [Arc::new(Hanging(job_type(RETRY))) as Arc<dyn JobHandler>],
        );

        run(&uc);

        let settled = queue.settled();
        assert_eq!(settled[0].status(), JobStatus::Pending);
        assert_eq!(settled[0].error(), Some(TIMED_OUT));
        assert!(settled[0].run_at() > due);
    }

    /// A job that keeps running out of time ends dead once its attempts are
    /// spent.
    #[test]
    fn a_job_that_runs_out_of_time_on_its_last_attempt_is_dead() {
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![job_with_attempts(RETRY, 1)]));
        let uc = processor_on(
            queue.clone(),
            FakeJobTimer::UpAtOnce,
            lane(8, 8),
            [Arc::new(Hanging(job_type(RETRY))) as Arc<dyn JobHandler>],
        );

        run(&uc);

        assert_eq!(queue.settled()[0].status(), JobStatus::Dead);
    }

    /// A job no handler knows is failed with a reason and stays due as
    /// scheduled, so it is not lost while a handler is being deployed.
    #[test]
    fn unhandled_job_type_fails_with_message() {
        let job = make_job(RETRY);
        let due = job.run_at();
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![job]));
        let uc = processor(queue.clone(), []);

        run(&uc);

        let settled = queue.settled();
        assert_eq!(settled[0].status(), JobStatus::Pending);
        assert_eq!(settled[0].error(), Some(UNHANDLED));
        assert_eq!(settled[0].run_at(), due);
    }

    /// With nothing due, a run processes nothing.
    #[test]
    fn empty_queue_returns_zero() {
        let uc = processor(Arc::new(FakeJobQueue::new()), []);

        assert_eq!(run(&uc), 0);
    }

    /// A lane running two at once takes two of five due jobs in a round.
    #[test]
    fn a_round_runs_no_more_jobs_than_the_lane_runs_at_once() {
        let jobs = (0..5).map(|_| make_job(MAIL)).collect();
        let queue = Arc::new(FakeJobQueue::with_jobs(jobs));
        let uc = processor_on(
            queue.clone(),
            FakeJobTimer::Never,
            lane(2, 2),
            [answering(MAIL, || Ok(Handled::Done))],
        );

        assert_eq!(run(&uc), 2);
    }

    /// Acme queued four mails before Globex queued one. With one of a
    /// tenant's jobs a round, Globex's mail goes out in the first round
    /// beside Acme's first, rather than after all of Acme's.
    #[test]
    fn a_tenant_with_a_backlog_does_not_hold_up_another() {
        let acme = TenantId::new();
        let globex = TenantId::new();
        let mut jobs: Vec<ScheduledJob> = (0..4).map(|_| make_job(MAIL).for_tenant(acme)).collect();
        jobs.push(make_job(MAIL).for_tenant(globex));
        let queue = Arc::new(FakeJobQueue::with_jobs(jobs));
        let uc = processor_on(
            queue.clone(),
            FakeJobTimer::Never,
            lane(4, 1),
            [answering(MAIL, || Ok(Handled::Done))],
        );

        run(&uc);

        let tenants: Vec<Option<TenantId>> = queue
            .settled()
            .iter()
            .map(|job| job.tenant_id().copied())
            .collect();
        assert_eq!(tenants.len(), 2);
        assert!(tenants.contains(&Some(globex)));
    }

    /// A lane for mail never takes a certificate job, so mail is not held
    /// behind a slow authority.
    #[test]
    fn a_lane_takes_only_its_own_job_types() {
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![make_job(
            "domain.provision_tls",
        )]));
        let uc = processor(queue.clone(), [answering(MAIL, || Ok(Handled::Done))]);

        assert_eq!(run(&uc), 0);
        assert!(queue.settled().is_empty());
    }

    /// Completion from a worker whose lease expired is ignored after another
    /// worker claims the job, leaving the second attempt running.
    #[test]
    fn a_settle_from_a_worker_that_lost_its_job_is_dropped() {
        let job = make_job(MAIL);
        let id = *job.id();
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![job]));
        let claim = JobClaim {
            job_types: &[job_type(MAIL)],
            limit: count(1),
            per_tenant: count(1),
            lease: Duration::seconds(60),
        };
        let mut stale = block_on(queue.claim(&claim)).unwrap().remove(0);
        queue.lapse_leases();
        block_on(queue.claim(&claim)).unwrap();

        stale.mark_completed().unwrap();
        block_on(queue.settle(&stale)).unwrap();

        let held = block_on(queue.find(&id)).unwrap().unwrap();
        assert_eq!(held.status(), JobStatus::Running);
        assert_eq!(held.attempt(), 2);
    }

    /// A job with a key is queued once while it waits; once it is done, the
    /// same work may be queued again.
    #[test]
    fn a_key_queues_its_work_once_while_it_waits() {
        let queue = Arc::new(FakeJobQueue::new());
        let keyed = || make_job(MAIL).keyed(JobKey::new("event-1:hook-1").unwrap());

        let first = block_on(queue.enqueue(&keyed())).unwrap();
        let again = block_on(queue.enqueue(&keyed())).unwrap();
        let uc = processor(queue.clone(), [answering(MAIL, || Ok(Handled::Done))]);
        run(&uc);
        let after_done = block_on(queue.enqueue(&keyed())).unwrap();

        assert_eq!(first, Enqueued::Queued);
        assert_eq!(again, Enqueued::AlreadyQueued);
        assert_eq!(after_done, Enqueued::Queued);
    }

    /// A worker took a job and died before settling it. Once its lease ran
    /// out, the next round takes it again with the attempt counted.
    #[test]
    fn a_job_held_by_a_stopped_worker_is_taken_again() {
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![make_job(MAIL)]));
        let claim = JobClaim {
            job_types: &[job_type(MAIL)],
            limit: count(1),
            per_tenant: count(1),
            lease: Duration::seconds(60),
        };
        block_on(queue.claim(&claim)).unwrap();
        queue.lapse_leases();
        let uc = processor(queue.clone(), [answering(MAIL, || Ok(Handled::Done))]);

        run(&uc);

        let settled = queue.settled();
        assert_eq!(settled[0].status(), JobStatus::Completed);
        assert_eq!(settled[0].attempt(), 2);
    }
}
