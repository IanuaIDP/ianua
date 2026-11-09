//! The worker: how it takes jobs, how many it runs at once and for how
//! long, how it relays and hears events, how often it looks for due
//! sweeps, and when it hands out again work left half-done.
//!
//! How often each sweep runs is not a setting: the app fixes every sweep's
//! period, and every worker must agree on it, or two workers would count
//! a sweep's rounds differently and each run it.

use std::num::NonZeroU32;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_domain::domains::workflows::execution::retention::{RUNS_KEPT_DAYS, RunsKept};

const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(86_400);

/// How jobs are taken from the queue and run.
///
/// Jobs run on five lanes, each claiming as many due jobs as it runs at
/// once: mail, certificate orders, agent runs, long work (tenants' setup
/// and teardown steps, clones, user imports and audit log exports), and
/// every other job. A claimed job is held for its lane's longest timeout
/// and half a minute more, so a job that ran out of time is settled before
/// another worker may take it. An agent run's timeout is worked out from
/// the agents' settings: its most steps, each a model call and a tool
/// call.
#[derive(Debug, Clone)]
pub(crate) struct JobConfig {
    /// `JOB_POLL_INTERVAL_SECONDS` (2): how long a lane that found nothing
    /// due waits before it asks the queue again.
    pub poll_interval: Duration,
    /// `JOB_PER_TENANT` (10): jobs of one tenant a lane takes in one claim,
    /// so one tenant's flood does not starve the others; never more than
    /// the lane runs at once.
    pub per_tenant: NonZeroU32,
    /// `JOB_TIMEOUT_SECONDS` (120): the longest a mail or general job may
    /// run before it is stopped and tried again.
    pub timeout: Duration,
    /// `JOB_TLS_TIMEOUT_SECONDS` (600): the longest a certificate order may
    /// run, waiting for its proof to be seen, before it is stopped and
    /// tried again.
    pub tls_timeout: Duration,
    /// `JOB_CONCURRENCY` (16): jobs run at once on the general lane.
    pub concurrency: NonZeroU32,
    /// `JOB_MAIL_CONCURRENCY` (8): mail jobs run at once, on a lane of
    /// their own.
    pub mail_concurrency: NonZeroU32,
    /// `JOB_TLS_CONCURRENCY` (2): certificate orders run at once, on a
    /// lane of their own.
    pub tls_concurrency: NonZeroU32,
    /// `JOB_AGENT_RUN_CONCURRENCY` (8): agent runs driven at once, on a
    /// lane of their own.
    pub agent_run_concurrency: NonZeroU32,
    /// `JOB_LONG_CONCURRENCY` (4): long jobs run at once, on a lane of
    /// their own.
    pub long_concurrency: NonZeroU32,
    /// `JOB_LONG_TIMEOUT_SECONDS` (1800): the longest a long job may run
    /// before it is stopped and tried again.
    pub long_timeout: Duration,
    /// `JOB_MAX_ATTEMPTS` (5): tries a job the worker queues gets before it
    /// is given up and left dead for an operator to see, where the work
    /// itself sets no count of its own.
    pub max_attempts: NonZeroU32,
    /// `JOB_RETRY_BACKOFF_SECONDS` (`300,900,3600,21600,86400`): the waits
    /// before each retry, in order; the last repeats.
    pub retry_backoff: Vec<Duration>,
}

/// How events reach the bus and the worker's consumers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EventConfig {
    /// `WORKER_OUTBOX_SWEEP_INTERVAL_SECONDS` (1): how often the outbox is
    /// relayed to the bus.
    pub relay_interval: Duration,
    /// `WORKER_OUTBOX_BATCH_SIZE` (100): events relayed from each database
    /// in one pass.
    pub relay_batch: NonZeroU32,
    /// `WORKER_INBOX_INTERVAL_SECONDS` (1): how often the gateway's inbox
    /// is drained into the audit trail.
    pub inbox_interval: Duration,
    /// `WORKER_INBOX_BATCH_SIZE` (100): gateway events drained from each
    /// database in one pass.
    pub inbox_batch: NonZeroU32,
    /// `WORKER_EVENT_MAX_DELIVER` (5): times an event is handed to a
    /// consumer before it is set aside.
    pub max_deliver: u32,
    /// `WORKER_EVENT_RETRY_DELAY_SECONDS` (5): the wait before a consumer
    /// is handed an event again after it failed on it.
    pub retry_delay: Duration,
    /// `WORKER_EVENT_ACK_WAIT_SECONDS` (60): how long a consumer may take
    /// over one event before the bus takes it to have stopped and hands
    /// the event to another.
    pub ack_wait: Duration,
}

/// How often the worker asks which sweeps are due.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SweepConfig {
    /// `WORKER_SWEEP_TICK_SECONDS` (15): how often each worker asks which
    /// sweeps' rounds have come; the one that claims a round runs it. At
    /// most a minute, the period of the shortest sweep.
    pub tick: Duration,
}

/// When work left half-done is handed out again.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReconcileConfig {
    /// `WORKER_RECONCILE_STALE_AFTER_SECONDS` (900): how long an agent run,
    /// a tenant's setup or teardown, or a clone may stand unchanged before
    /// it is taken to be left and handed out again. Longer than any of
    /// them takes.
    pub stale_after: Duration,
    /// `WORKER_RECONCILE_BATCH` (100): the most of each kind one round
    /// hands out again.
    pub batch: NonZeroU32,
}

/// Controls background concurrency, retries, event delivery and maintenance polling.
#[derive(Debug, Clone)]
pub(crate) struct WorkerConfig {
    /// Claim sizes, lane concurrency and timeouts for queued background work.
    pub jobs: JobConfig,
    /// Polling and delivery bounds for the outbox, gateway inbox and bus consumers.
    pub events: EventConfig,
    /// The cadence at which workers claim due maintenance rounds.
    pub sweeps: SweepConfig,
    /// The work left half-done.
    pub reconcile: ReconcileConfig,
    /// `PRIVACY_ERASURE_GRACE_DAYS` (30): the time a person has to cancel
    /// an erasure before it is carried out.
    pub erasure_grace: Duration,
    /// `WORKFLOW_RUNS_KEPT_DAYS` (90): how long a workflow run that ended
    /// is kept before the worker removes it.
    pub workflow_runs_kept: RunsKept,
}

impl WorkerConfig {
    /// The worker settings `vars` holds.
    ///
    /// # Errors
    ///
    /// A setting that does not read, a count or interval of zero, a sweep
    /// tick longer than a minute, or an event wait that cannot hold.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            jobs: jobs(vars)?,
            events: events(vars)?,
            sweeps: sweeps(vars)?,
            reconcile: reconcile(vars)?,
            erasure_grace: vars.days("PRIVACY_ERASURE_GRACE_DAYS", 30 * DAY)?,
            workflow_runs_kept: workflow_runs_kept(vars)?,
        })
    }
}

/// How long ended workflow runs are kept, as `WORKFLOW_RUNS_KEPT_DAYS` says.
fn workflow_runs_kept(vars: &Env) -> Read<RunsKept> {
    let name = "WORKFLOW_RUNS_KEPT_DAYS";
    let days = vars.days(name, RUNS_KEPT_DAYS * DAY)?.as_secs() / DAY.as_secs();
    let days = u32::try_from(days).unwrap_or(u32::MAX);
    RunsKept::for_days(days).map_err(|_| {
        ConfigError::invalid(
            name,
            "must be between 60 and 3650, longer than an evaluation that read a run is kept",
        )
    })
}

/// A count `name` holds, at least one.
fn count(vars: &Env, name: &str, default: u32, most: u32) -> Read<NonZeroU32> {
    let counted = vars.number_in(name, default, 1..=most)?;
    NonZeroU32::new(counted).ok_or_else(|| ConfigError::invalid(name, "must be at least 1"))
}

/// An interval `name` holds, never zero.
fn interval(vars: &Env, name: &str, default: Duration) -> Read<Duration> {
    let every = vars.seconds(name, default)?;
    if every.is_zero() {
        return Err(ConfigError::invalid(name, "must be at least one second"));
    }
    Ok(every)
}

fn jobs(vars: &Env) -> Read<JobConfig> {
    let default_backoff = [300, 900, 3600, 21_600, 86_400].map(Duration::from_secs);
    Ok(JobConfig {
        poll_interval: interval(vars, "JOB_POLL_INTERVAL_SECONDS", Duration::from_secs(2))?,
        per_tenant: count(vars, "JOB_PER_TENANT", 10, 1000)?,
        timeout: interval(vars, "JOB_TIMEOUT_SECONDS", 2 * MINUTE)?,
        tls_timeout: interval(vars, "JOB_TLS_TIMEOUT_SECONDS", 10 * MINUTE)?,
        concurrency: count(vars, "JOB_CONCURRENCY", 16, 1024)?,
        mail_concurrency: count(vars, "JOB_MAIL_CONCURRENCY", 8, 1024)?,
        tls_concurrency: count(vars, "JOB_TLS_CONCURRENCY", 2, 64)?,
        agent_run_concurrency: count(vars, "JOB_AGENT_RUN_CONCURRENCY", 8, 1024)?,
        long_concurrency: count(vars, "JOB_LONG_CONCURRENCY", 4, 256)?,
        long_timeout: interval(vars, "JOB_LONG_TIMEOUT_SECONDS", 30 * MINUTE)?,
        max_attempts: count(vars, "JOB_MAX_ATTEMPTS", 5, 100)?,
        retry_backoff: vars.seconds_list("JOB_RETRY_BACKOFF_SECONDS", &default_backoff)?,
    })
}

fn events(vars: &Env) -> Read<EventConfig> {
    let retry_delay = vars.seconds("WORKER_EVENT_RETRY_DELAY_SECONDS", Duration::from_secs(5))?;
    let ack_wait = interval(vars, "WORKER_EVENT_ACK_WAIT_SECONDS", MINUTE)?;
    if retry_delay >= ack_wait {
        return Err(ConfigError::contradicts(
            "WORKER_EVENT_RETRY_DELAY_SECONDS",
            "is not shorter than WORKER_EVENT_ACK_WAIT_SECONDS, so an event put off would be handed out again before its delay",
        ));
    }
    Ok(EventConfig {
        relay_interval: interval(
            vars,
            "WORKER_OUTBOX_SWEEP_INTERVAL_SECONDS",
            Duration::from_secs(1),
        )?,
        relay_batch: count(vars, "WORKER_OUTBOX_BATCH_SIZE", 100, 10_000)?,
        inbox_interval: interval(
            vars,
            "WORKER_INBOX_INTERVAL_SECONDS",
            Duration::from_secs(1),
        )?,
        inbox_batch: count(vars, "WORKER_INBOX_BATCH_SIZE", 100, 10_000)?,
        max_deliver: vars.number_in("WORKER_EVENT_MAX_DELIVER", 5, 1..=100)?,
        retry_delay,
        ack_wait,
    })
}

fn sweeps(vars: &Env) -> Read<SweepConfig> {
    let tick = interval(vars, "WORKER_SWEEP_TICK_SECONDS", Duration::from_secs(15))?;
    if tick > MINUTE {
        return Err(ConfigError::invalid(
            "WORKER_SWEEP_TICK_SECONDS",
            "must be at most 60, or the sweeps that run each minute would miss rounds",
        ));
    }
    Ok(SweepConfig { tick })
}

fn reconcile(vars: &Env) -> Read<ReconcileConfig> {
    Ok(ReconcileConfig {
        stale_after: interval(vars, "WORKER_RECONCILE_STALE_AFTER_SECONDS", 15 * MINUTE)?,
        batch: count(vars, "WORKER_RECONCILE_BATCH", 100, 10_000)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs are kept ninety days unless a deployment says otherwise, and
    /// a deployment that would lose them before the evaluations that read
    /// them is refused at start.
    #[test]
    fn workflow_runs_are_kept_ninety_days_and_never_too_few() {
        assert_eq!(
            WorkerConfig::read(&Env::of([])).unwrap().workflow_runs_kept,
            RunsKept::default()
        );
        let longer = Env::of([("WORKFLOW_RUNS_KEPT_DAYS", "120")]);
        assert_eq!(
            WorkerConfig::read(&longer).unwrap().workflow_runs_kept,
            RunsKept::for_days(120).unwrap()
        );
        let too_few = Env::of([("WORKFLOW_RUNS_KEPT_DAYS", "7")]);
        assert!(WorkerConfig::read(&too_few).is_err());
    }

    /// With nothing set, the documented schedule holds.
    #[test]
    fn with_nothing_set_the_documented_schedule_holds() {
        let config = WorkerConfig::read(&Env::of([])).unwrap();

        assert_eq!(
            config
                .jobs
                .retry_backoff
                .iter()
                .map(Duration::as_secs)
                .collect::<Vec<_>>(),
            [300, 900, 3600, 21_600, 86_400]
        );
        assert_eq!(config.jobs.concurrency.get(), 16);
        assert_eq!(config.events.relay_interval, Duration::from_secs(1));
        assert_eq!(config.events.inbox_interval, Duration::from_secs(1));
        assert_eq!(config.events.inbox_batch.get(), 100);
        assert_eq!(config.sweeps.tick, Duration::from_secs(15));
        assert_eq!(config.reconcile.stale_after, 15 * MINUTE);
    }

    /// A sweep interval over one minute is refused, naming the invalid
    /// interval setting.
    #[test]
    fn a_sweep_tick_longer_than_a_minute_is_refused() {
        let read = WorkerConfig::read(&Env::of([("WORKER_SWEEP_TICK_SECONDS", "61")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "WORKER_SWEEP_TICK_SECONDS")
        );
    }

    /// An event retry delay equal to the acknowledgement wait is refused,
    /// naming the conflicting delay setting.
    #[test]
    fn a_retry_delay_as_long_as_the_ack_wait_is_refused() {
        let read = WorkerConfig::read(&Env::of([
            ("WORKER_EVENT_RETRY_DELAY_SECONDS", "60"),
            ("WORKER_EVENT_ACK_WAIT_SECONDS", "60"),
        ]));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "WORKER_EVENT_RETRY_DELAY_SECONDS")
        );
    }

    /// Worker configuration refuses a job concurrency of zero.
    #[test]
    fn a_concurrency_of_zero_is_refused() {
        assert!(WorkerConfig::read(&Env::of([("JOB_CONCURRENCY", "0")])).is_err());
    }

    /// Worker configuration refuses a sweep interval of zero.
    #[test]
    fn a_tick_of_zero_is_refused() {
        assert!(WorkerConfig::read(&Env::of([("WORKER_SWEEP_TICK_SECONDS", "0")])).is_err());
    }

    /// An inbox batch size of zero is refused, naming the invalid batch
    /// setting.
    #[test]
    fn an_inbox_batch_of_zero_is_refused() {
        let read = WorkerConfig::read(&Env::of([("WORKER_INBOX_BATCH_SIZE", "0")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "WORKER_INBOX_BATCH_SIZE")
        );
    }
}
