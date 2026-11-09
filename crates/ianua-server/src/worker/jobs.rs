//! The job processor: five lanes, each claiming its due jobs from the
//! queue and running them, so a slow kind of work never holds up another.
//!
//! Mail runs on a lane of its own, certificate orders on another, agent
//! runs, which last as long as their steps may, on a third, the long work
//! of tenants' setups and teardowns, clones, imports and audit log exports
//! on a fourth, and every other job on the general lane. A lane's round
//! lasts as long as its slowest job, so a job that takes minutes never
//! keeps a webhook or a signal waiting. Each lane claims as many due jobs
//! as it runs at once, no more of one tenant's than its share, runs them
//! together, each held to its timeout, and settles each before it claims
//! again; a lane that found nothing waits for the poll interval. A claimed
//! job is held for its lane's longest timeout and a margin, so a job that
//! ran out of time is settled before another worker may take it, and a
//! job whose worker died is taken again once that hold has passed.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use ianua_app::auditor::RequestAuditor;
use ianua_app::use_case::Command;
use ianua_app::use_cases::agents::runs::DRIVE_RUN_JOB;
use ianua_app::use_cases::audit::exports::WRITE_EXPORT_JOB;
use ianua_app::use_cases::domain::verification::verified::PROVISION_TLS_JOB;
use ianua_app::use_cases::identity::imports::IMPORT_JOB;
use ianua_app::use_cases::scheduling::{
    Backoff, JobHandler, JobKind, Lane, ProcessJobsPorts, ProcessJobsUseCase,
};
use ianua_app::use_cases::tenant::clones::RUN_CLONE_JOB;
use ianua_app::use_cases::tenant::setup::SETUP_STEP_JOB;
use ianua_app::use_cases::tenant::teardown::TEARDOWN_STEP_JOB;
use ianua_app::use_cases::workflows::executions::RUN_CODE_JOB;
use ianua_app::use_cases::workflows::sandboxes::BUILD_SANDBOX_JOB;
use ianua_boot::shutdown::Shutdown;
use ianua_domain::shared::errors::DomainError;
use ianua_infra::mail::MAIL_JOB;

use crate::config::serving::worker::JobConfig;
use crate::error::{PlatformError, ServerError};
use crate::worker::handlers::agents::longest_drive;
use crate::worker::handlers::handlers;
use crate::worker::parts::Parts;

/// How much shorter than the hold on its run an agent run's job is, so a
/// drive stopped at its timeout lets go of the run before another worker
/// may take it.
const RUN_SETTLE_MARGIN: Duration = Duration::from_secs(30);

/// The lanes jobs run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaneName {
    /// Runs delivery jobs independently of the general work queue.
    Mail,
    /// Certificate orders.
    Certificates,
    /// Drives model execution with its own concurrency allowance.
    AgentRuns,
    /// Work that takes minutes.
    Long,
    /// Every other job.
    General,
}

/// How long each lane's jobs may run.
#[derive(Debug, Clone, Copy)]
struct Timeouts {
    /// Mail and the general lane's jobs.
    general: Duration,
    /// Certificate orders.
    certificates: Duration,
    /// The deadline derived from the maximum model and tool steps.
    agent_runs: Duration,
    /// Long work.
    long: Duration,
}

impl Timeouts {
    /// The timeouts `jobs` set, an agent run's held to `run_lease`, the
    /// time a drive holds its run.
    fn of(jobs: &JobConfig, run_lease: Duration) -> Self {
        Self {
            general: jobs.timeout,
            certificates: jobs.tls_timeout,
            agent_runs: run_lease.saturating_sub(RUN_SETTLE_MARGIN),
            long: jobs.long_timeout,
        }
    }
}

impl LaneName {
    /// Every lane.
    const ALL: [Self; 5] = [
        Self::Mail,
        Self::Certificates,
        Self::AgentRuns,
        Self::Long,
        Self::General,
    ];

    /// The lane jobs of `job_type` run on.
    fn of(job_type: &str) -> Self {
        match job_type {
            MAIL_JOB => Self::Mail,
            PROVISION_TLS_JOB => Self::Certificates,
            DRIVE_RUN_JOB => Self::AgentRuns,
            SETUP_STEP_JOB | TEARDOWN_STEP_JOB | RUN_CLONE_JOB | IMPORT_JOB | WRITE_EXPORT_JOB
            | BUILD_SANDBOX_JOB | RUN_CODE_JOB => Self::Long,
            _ => Self::General,
        }
    }

    /// What the lane's loop is called in the log.
    fn task(self) -> &'static str {
        match self {
            Self::Mail => "the mail lane",
            Self::Certificates => "the certificate lane",
            Self::AgentRuns => "the agent run lane",
            Self::Long => "the long job lane",
            Self::General => "the general job lane",
        }
    }

    /// How many of the lane's jobs run at once.
    fn concurrency(self, jobs: &JobConfig) -> NonZeroU32 {
        match self {
            Self::Mail => jobs.mail_concurrency,
            Self::Certificates => jobs.tls_concurrency,
            Self::AgentRuns => jobs.agent_run_concurrency,
            Self::Long => jobs.long_concurrency,
            Self::General => jobs.concurrency,
        }
    }

    /// The longest one of the lane's jobs may run.
    fn timeout(self, timeouts: Timeouts) -> Duration {
        match self {
            Self::Certificates => timeouts.certificates,
            Self::AgentRuns => timeouts.agent_runs,
            Self::Long => timeouts.long,
            Self::Mail | Self::General => timeouts.general,
        }
    }
}

/// One lane with the handlers of its jobs.
struct LaneOf {
    name: LaneName,
    lane: Lane,
    handlers: Vec<Arc<dyn JobHandler>>,
}

/// Each lane with the handlers whose jobs run on it; a lane no handler's
/// jobs run on is left out.
///
/// # Errors
///
/// [`DomainError`] when a timeout does not fit, or the app refuses a lane.
fn lanes(
    handlers: &[Arc<dyn JobHandler>],
    jobs: &JobConfig,
    timeouts: Timeouts,
) -> Result<Vec<LaneOf>, DomainError> {
    let mut built = Vec::with_capacity(LaneName::ALL.len());
    for name in LaneName::ALL {
        let on_lane: Vec<Arc<dyn JobHandler>> = handlers
            .iter()
            .filter(|handler| LaneName::of(handler.job_type().as_str()) == name)
            .map(Arc::clone)
            .collect();
        if on_lane.is_empty() {
            continue;
        }
        let timeout =
            time::Duration::try_from(name.timeout(timeouts)).map_err(DomainError::infra)?;
        let kinds = on_lane
            .iter()
            .map(|handler| JobKind {
                job_type: handler.job_type().clone(),
                timeout,
            })
            .collect();
        let concurrency = name.concurrency(jobs);
        let lane = Lane::new(kinds, concurrency, jobs.per_tenant.min(concurrency))?;
        built.push(LaneOf {
            name,
            lane,
            handlers: on_lane,
        });
    }
    Ok(built)
}

/// Starts a loop for each lane, running every handler's jobs.
///
/// # Errors
///
/// [`ServerError`] when a handler cannot be built, or the lanes or the
/// backoff are refused.
pub(super) fn start(parts: &Parts<'_>, shutdown: &Shutdown) -> Result<(), ServerError> {
    let jobs = &parts.config.worker.jobs;
    let backoff = backoff(jobs).map_err(PlatformError::of("the jobs' backoff"))?;
    let timeouts = Timeouts::of(jobs, longest_drive(&parts.config.agents));
    let lanes =
        lanes(&handlers(parts)?, jobs, timeouts).map_err(PlatformError::of("the job lanes"))?;
    for LaneOf {
        name,
        lane,
        handlers,
    } in lanes
    {
        let ports = ProcessJobsPorts {
            queue: Arc::clone(&parts.jobs),
            timer: Arc::clone(&parts.timer),
        };
        let processor = Processor {
            use_case: ProcessJobsUseCase::new(ports, lane, handlers, backoff.clone()),
            auditor: parts.system_auditor(),
            poll: jobs.poll_interval,
            name,
        };
        shutdown.spawn(name.task(), processor.run(shutdown.clone()));
    }
    Ok(())
}

/// The waits before each retry, as the configuration says.
fn backoff(jobs: &JobConfig) -> Result<Backoff, DomainError> {
    let waits = jobs
        .retry_backoff
        .iter()
        .map(|wait| time::Duration::try_from(*wait).map_err(DomainError::infra))
        .collect::<Result<Vec<_>, _>>()?;
    Backoff::new(waits)
}

/// One lane's loop.
struct Processor {
    use_case: ProcessJobsUseCase,
    auditor: RequestAuditor,
    poll: Duration,
    name: LaneName,
}

impl Processor {
    /// Runs rounds until `shutdown` stops it. A round under way when the
    /// stop comes finishes, within the stop's grace, so the jobs in hand
    /// are settled; a stop past the grace leaves them to be taken again
    /// once their hold has passed.
    async fn run(self, shutdown: Shutdown) {
        while !shutdown.is_stopping() {
            let pause = self.round().await;
            let Some(pause) = pause else {
                continue;
            };
            tokio::select! {
                () = shutdown.stopping() => return,
                () = tokio::time::sleep(pause) => {}
            }
        }
    }

    /// Runs one round, and answers how long to wait before the next: none
    /// after a round that ran jobs, as more may be due.
    async fn round(&self) -> Option<Duration> {
        match self.use_case.execute(&(), &self.auditor, ()).await {
            Ok(0) => Some(self.poll),
            Ok(ran) => {
                tracing::debug!(lane = self.name.task(), ran, "jobs ran");
                None
            }
            Err(error) => {
                tracing::warn!(lane = self.name.task(), %error, "jobs could not be claimed or settled; the lane tries again");
                Some(self.poll)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use async_trait::async_trait;
    use ianua_app::error::AppError;
    use ianua_app::ports::scheduling::JobQueue;
    use ianua_app::test_support::FakeEventDispatcher;
    use ianua_app::test_support::scheduling::FakeJobQueue;
    use ianua_app::use_cases::scheduling::Handled;
    use ianua_boot::env::Env;
    use ianua_domain::domains::scheduling::job::ScheduledJob;
    use ianua_domain::domains::scheduling::job_status::JobStatus;
    use ianua_domain::domains::scheduling::job_type::JobType;
    use ianua_domain::shared::clock;
    use ianua_domain::types::JobId;
    use ianua_infra::postgres::scheduling::PgJobQueue;
    use ianua_infra::runtime::LocalJobTimer;
    use ianua_infra::test_support::TestDb;
    use tokio::sync::Notify;

    use super::*;
    use crate::config::serving::WorkerConfig;

    struct Runs(JobType);

    #[async_trait]
    impl JobHandler for Runs {
        fn job_type(&self) -> &JobType {
            &self.0
        }

        async fn handle(
            &self,
            _job: &ScheduledJob,
            _auditor: &RequestAuditor,
        ) -> Result<Handled, AppError> {
            Ok(Handled::Done)
        }
    }

    fn runs(job_type: &str) -> Arc<dyn JobHandler> {
        Arc::new(Runs(JobType::new(job_type).unwrap()))
    }

    /// How long a drive holds its run in these tests: twenty-one minutes.
    const RUN_LEASE: Duration = Duration::from_secs(1260);

    fn settings(pairs: &[(&str, &str)]) -> JobConfig {
        WorkerConfig::read(&Env::of(pairs.iter().copied()))
            .unwrap()
            .jobs
    }

    fn lanes_for(handlers: &[Arc<dyn JobHandler>], pairs: &[(&str, &str)]) -> Vec<LaneOf> {
        let jobs = settings(pairs);
        lanes(handlers, &jobs, Timeouts::of(&jobs, RUN_LEASE)).unwrap()
    }

    /// Mail, certificates, agent runs, long work and the rest each run on
    /// a lane of their own.
    #[test]
    fn each_kind_of_work_runs_on_its_own_lane() {
        let handlers = [
            MAIL_JOB,
            PROVISION_TLS_JOB,
            DRIVE_RUN_JOB,
            RUN_CLONE_JOB,
            IMPORT_JOB,
            "webhooks.deliver",
            "workflow.drive",
        ]
        .map(runs)
        .to_vec();

        let lanes = lanes_for(&handlers, &[]);

        let by_lane: Vec<(LaneName, usize)> = lanes
            .iter()
            .map(|lane| (lane.name, lane.lane.job_types().len()))
            .collect();
        assert_eq!(
            by_lane,
            [
                (LaneName::Mail, 1),
                (LaneName::Certificates, 1),
                (LaneName::AgentRuns, 1),
                (LaneName::Long, 2),
                (LaneName::General, 2)
            ]
        );
    }

    /// Certificate jobs retain their configured timeout independently of
    /// general jobs, with a lease longer than the certificate timeout.
    #[test]
    fn certificate_orders_keep_their_own_timeout() {
        let handlers = vec![runs(PROVISION_TLS_JOB), runs("webhooks.deliver")];

        let lanes = lanes_for(
            &handlers,
            &[
                ("JOB_TLS_TIMEOUT_SECONDS", "900"),
                ("JOB_TIMEOUT_SECONDS", "60"),
            ],
        );

        let tls = JobType::new(PROVISION_TLS_JOB).unwrap();
        let general = JobType::new("webhooks.deliver").unwrap();
        assert_eq!(
            lanes[0].lane.timeout_of(&tls),
            Some(time::Duration::seconds(900))
        );
        assert_eq!(
            lanes[1].lane.timeout_of(&general),
            Some(time::Duration::seconds(60))
        );
        assert!(lanes[0].lane.lease() > time::Duration::seconds(900));
    }

    /// An agent job's timeout leaves thirty seconds before its run lease
    /// expires, and its job lease stays within that run lease.
    #[test]
    fn an_agent_run_runs_until_just_before_its_hold_ends() {
        let lanes = lanes_for(&[runs(DRIVE_RUN_JOB)], &[]);

        let drive = JobType::new(DRIVE_RUN_JOB).unwrap();
        let timeout = lanes[0].lane.timeout_of(&drive).unwrap();
        assert_eq!(timeout, time::Duration::seconds(1230));
        assert!(lanes[0].lane.lease() <= time::Duration::seconds(1260));
    }

    /// A tenant share configured above certificate concurrency is reduced
    /// to that lane's concurrency when the lane is built.
    #[test]
    fn a_tenants_share_is_held_to_its_lane() {
        let lanes = lanes_for(
            &[runs(PROVISION_TLS_JOB)],
            &[("JOB_TLS_CONCURRENCY", "2"), ("JOB_PER_TENANT", "10")],
        );

        assert_eq!(lanes[0].lane.per_tenant().get(), 2);
    }

    /// The configured waits become the backoff, in order.
    #[test]
    fn the_configured_waits_become_the_backoff() {
        assert!(backoff(&settings(&[("JOB_RETRY_BACKOFF_SECONDS", "1,2,3")])).is_ok());
    }

    /// The job type the counting handler runs.
    const COUNTED: &str = "test.counted";

    /// A handler counting its runs, failing the first `failing` of them,
    /// each taking `takes`.
    struct Counted {
        job_type: JobType,
        runs: AtomicU32,
        failing: u32,
        takes: Duration,
        started: Notify,
    }

    impl Counted {
        fn new(failing: u32, takes: Duration) -> Arc<Self> {
            Arc::new(Self {
                job_type: JobType::new(COUNTED).unwrap(),
                runs: AtomicU32::new(0),
                failing,
                takes,
                started: Notify::new(),
            })
        }

        fn runs(&self) -> u32 {
            self.runs.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl JobHandler for Counted {
        fn job_type(&self) -> &JobType {
            &self.job_type
        }

        async fn handle(
            &self,
            _job: &ScheduledJob,
            _auditor: &RequestAuditor,
        ) -> Result<Handled, AppError> {
            let run = self.runs.fetch_add(1, Ordering::SeqCst) + 1;
            self.started.notify_one();
            tokio::time::sleep(self.takes).await;
            if run <= self.failing {
                return Err(AppError::internal_msg("the endpoint is down"));
            }
            Ok(Handled::Done)
        }
    }

    /// A lane running the counting handler's jobs, each held to `timeout`,
    /// over `queue`, retrying at once.
    fn processor(queue: Arc<dyn JobQueue>, handler: &Arc<Counted>, timeout: Duration) -> Processor {
        let kinds = vec![JobKind {
            job_type: handler.job_type.clone(),
            timeout: time::Duration::try_from(timeout).unwrap(),
        }];
        let four = NonZeroU32::new(4).unwrap();
        let ports = ProcessJobsPorts {
            queue,
            timer: Arc::new(LocalJobTimer),
        };
        let handlers = [Arc::clone(handler) as Arc<dyn JobHandler>];
        Processor {
            use_case: ProcessJobsUseCase::new(
                ports,
                Lane::new(kinds, four, four).unwrap(),
                handlers,
                Backoff::new(vec![time::Duration::ZERO]).unwrap(),
            ),
            auditor: RequestAuditor::system(Arc::new(FakeEventDispatcher::new())),
            poll: Duration::from_millis(10),
            name: LaneName::General,
        }
    }

    /// Queues one counting job of no tenant, with `attempts` tries.
    async fn queued(queue: &dyn JobQueue, attempts: u32) -> JobId {
        let job = ScheduledJob::new(
            JobType::new(COUNTED).unwrap(),
            "{}".to_owned(),
            clock::now(),
            NonZeroU32::new(attempts).unwrap(),
        );
        let id = *job.id();
        queue.enqueue(&job).await.unwrap();
        id
    }

    async fn found(queue: &dyn JobQueue, id: &JobId) -> ScheduledJob {
        queue.find(id).await.unwrap().unwrap()
    }

    /// Two workers claim from one queue at the same moment: the job runs
    /// on one of them, once, and is done.
    #[tokio::test]
    async fn a_job_runs_once_across_two_workers() {
        let db = TestDb::fresh().await;
        let queue: Arc<dyn JobQueue> = Arc::new(PgJobQueue::new(Arc::clone(&db.databases)));
        let other: Arc<dyn JobQueue> = Arc::new(PgJobQueue::new(db.another_node()));
        let handler = Counted::new(0, Duration::from_millis(50));
        let id = queued(queue.as_ref(), 3).await;
        let first = processor(Arc::clone(&queue), &handler, Duration::from_secs(5));
        let second = processor(other, &handler, Duration::from_secs(5));

        tokio::join!(first.round(), second.round());

        assert_eq!(handler.runs(), 1);
        assert_eq!(
            found(queue.as_ref(), &id).await.status(),
            JobStatus::Completed
        );
    }

    /// A handler exceeding its timeout leaves the job pending after one
    /// attempt, with the timeout reason recorded for its retry.
    #[tokio::test]
    async fn a_job_past_its_timeout_is_released() {
        let db = TestDb::fresh().await;
        let queue: Arc<dyn JobQueue> = Arc::new(PgJobQueue::new(Arc::clone(&db.databases)));
        let handler = Counted::new(0, Duration::from_secs(30));
        let id = queued(queue.as_ref(), 3).await;
        let lane = processor(Arc::clone(&queue), &handler, Duration::from_millis(100));

        lane.round().await;

        let job = found(queue.as_ref(), &id).await;
        assert_eq!(job.status(), JobStatus::Pending);
        assert_eq!(job.error(), Some("the job ran out of time"));
        assert_eq!(job.attempt(), 1);
    }

    /// A job that fails once succeeds on its second attempt and remains
    /// completed; the following round waits without running it again.
    #[tokio::test]
    async fn a_retried_job_is_not_run_again_after_its_success() {
        let db = TestDb::fresh().await;
        let queue: Arc<dyn JobQueue> = Arc::new(PgJobQueue::new(Arc::clone(&db.databases)));
        let handler = Counted::new(1, Duration::ZERO);
        let id = queued(queue.as_ref(), 3).await;
        let lane = processor(Arc::clone(&queue), &handler, Duration::from_secs(5));

        let failed = lane.round().await;
        let succeeded = lane.round().await;
        let after = lane.round().await;

        assert_eq!((failed, succeeded), (None, None));
        assert_eq!(after, Some(lane.poll));
        assert_eq!(handler.runs(), 2);
        assert_eq!(
            found(queue.as_ref(), &id).await.status(),
            JobStatus::Completed
        );
    }

    /// Stopping a worker during a job lets that job finish within the
    /// shutdown grace and records it as completed before joining.
    #[tokio::test]
    async fn a_stop_lets_the_running_job_finish() {
        let queue = Arc::new(FakeJobQueue::new());
        let handler = Counted::new(0, Duration::from_millis(200));
        queued(queue.as_ref(), 3).await;
        let lane = processor(Arc::clone(&queue) as _, &handler, Duration::from_secs(5));
        let shutdown = Shutdown::new(Duration::from_secs(2));
        shutdown.spawn("the test lane", lane.run(shutdown.clone()));
        handler.started.notified().await;

        shutdown.stop();
        let joined = shutdown.join().await;

        assert!(joined.is_ok());
        assert_eq!(queue.settled()[0].status(), JobStatus::Completed);
    }
}
