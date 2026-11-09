//! Fakes for the scheduling ports: an in-memory job queue that keeps the
//! queue's contract, sweep claims, a timer, local times, stalled work and
//! the scheduled workflows, and the neutral job queues the use cases that
//! queue work take.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::{ScheduledJob, ScheduledJobRow};
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_status::JobStatus;
use ianua_domain::domains::scheduling::sweep::{SweepName, SweepRound};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{JobId, TenantId, Timezone, UntrustedText};
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::scheduling::{
    DeadJobSortField, Enqueued, JobClaim, JobQueue, JobTimer, Retried, StalledClone, StalledRun,
    StalledWork, SweepClaims, TimeZones,
};
use crate::ports::workflows::{ScheduledVersion, ScheduledWorkflows};
use crate::test_support::Fake;
use crate::test_support::listing::page;
use crate::use_cases::agents::runs::RunDrives;
use crate::use_cases::oauth::flows::LogoutJobs;
use crate::use_cases::workflows::executions::{EventStarts, ScheduledStarts};
use crate::use_cases::workflows::published::holds::AccountChecks;

/// A job as the fake queue holds it, with whether its claimer's lease ran
/// out.
struct Held {
    job: ScheduledJob,
    lease: Lease,
}

/// Whether the worker holding a running job still holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lease {
    /// Held, or not running at all.
    Live,
    /// The lease ran out: the worker is taken to have stopped.
    Lapsed,
}

/// In-memory job queue that keeps the queue's contract: a key queues its
/// work once while it waits or runs, or once for good when keyed once, a claim takes only its lane's due jobs
/// and shares them out between tenants, a lapsed lease hands a running job
/// out again, and a settle from a claim that lost its job is dropped.
#[derive(Default)]
pub struct FakeJobQueue {
    jobs: Mutex<Vec<Held>>,
    enqueued: Mutex<Vec<String>>,
    settled: Mutex<Vec<ScheduledJob>>,
}

impl FakeJobQueue {
    /// Creates an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A queue already holding `jobs`.
    ///
    /// # Panics
    ///
    /// When a job cannot be copied in.
    #[must_use]
    pub fn with_jobs(jobs: Vec<ScheduledJob>) -> Self {
        let held = jobs
            .into_iter()
            .map(|job| Held {
                job: copy_job(&job).unwrap(),
                lease: Lease::Live,
            })
            .collect();
        Self {
            jobs: Mutex::new(held),
            ..Self::default()
        }
    }

    /// How many jobs were queued, duplicates left out.
    #[must_use]
    pub fn count(&self) -> usize {
        self.enqueued.lock().unwrap().len()
    }

    /// Whether a job of `job_type` was queued.
    #[must_use]
    pub fn holds(&self, job_type: &str) -> bool {
        self.enqueued.lock().unwrap().iter().any(|t| t == job_type)
    }

    /// Every job of `job_type` the queue holds, in the order queued.
    ///
    /// # Panics
    ///
    /// When a job cannot be copied out.
    #[must_use]
    pub fn jobs_of(&self, job_type: &str) -> Vec<ScheduledJob> {
        self.jobs
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.job.job_type().as_str() == job_type)
            .map(|held| copy_job(&held.job).unwrap())
            .collect()
    }

    /// The claimed jobs as they were settled, in order.
    ///
    /// # Panics
    ///
    /// When a settled job cannot be read back.
    #[must_use]
    pub fn settled(&self) -> Vec<ScheduledJob> {
        self.settled
            .lock()
            .unwrap()
            .iter()
            .map(|job| copy_job(job).unwrap())
            .collect()
    }

    /// Lets every running job's lease run out, as when the worker holding
    /// it stopped.
    pub fn lapse_leases(&self) {
        for held in self.jobs.lock().unwrap().iter_mut() {
            if held.job.status() == JobStatus::Running {
                held.lease = Lease::Lapsed;
            }
        }
    }
}

#[async_trait]
impl JobQueue for FakeJobQueue {
    async fn enqueue(&self, job: &ScheduledJob) -> Result<Enqueued, DomainError> {
        let mut jobs = self.jobs.lock().unwrap();
        if job.key().is_some() && jobs.iter().any(|held| holds_its_key(&held.job, job)) {
            return Ok(Enqueued::AlreadyQueued);
        }
        jobs.push(Held {
            job: copy_job(job)?,
            lease: Lease::Live,
        });
        self.enqueued
            .lock()
            .unwrap()
            .push(job.job_type().as_str().to_owned());
        Ok(Enqueued::Queued)
    }

    async fn claim(&self, claim: &JobClaim<'_>) -> Result<Vec<ScheduledJob>, DomainError> {
        let mut jobs = self.jobs.lock().unwrap();
        give_up_lapsed(&mut jobs)?;
        let now = clock::now();
        let mut order: Vec<usize> = (0..jobs.len())
            .filter(|at| is_due_in_lane(&jobs[*at].job, claim, now))
            .collect();
        order.sort_by_key(|at| jobs[*at].job.run_at());
        let taken = fair_share(&jobs, &order, claim);
        let mut claimed = Vec::with_capacity(taken.len());
        for at in taken {
            jobs[at].job.mark_running()?;
            jobs[at].lease = Lease::Live;
            claimed.push(copy_job(&jobs[at].job)?);
        }
        Ok(claimed)
    }

    async fn settle(&self, job: &ScheduledJob) -> Result<(), DomainError> {
        self.settled.lock().unwrap().push(copy_job(job)?);
        let mut jobs = self.jobs.lock().unwrap();
        let Some(held) = jobs.iter_mut().find(|held| held.job.id() == job.id()) else {
            return Ok(());
        };
        if held.job.status() != JobStatus::Running || held.job.attempt() != job.attempt() {
            return Ok(());
        }
        held.job = copy_job(job)?;
        held.lease = Lease::Live;
        Ok(())
    }

    async fn find(&self, id: &JobId) -> Result<Option<ScheduledJob>, DomainError> {
        let jobs = self.jobs.lock().unwrap();
        jobs.iter()
            .find(|held| held.job.id() == id)
            .map(|held| copy_job(&held.job))
            .transpose()
    }

    async fn list_dead(&self, request: &PageRequest) -> Result<Page<ScheduledJob>, DomainError> {
        let dead = self
            .jobs
            .lock()
            .unwrap()
            .iter()
            .map(|held| &held.job)
            .filter(|job| job.status() == JobStatus::Dead)
            .map(copy_job)
            .collect::<Result<Vec<_>, _>>()?;
        page(dead, &SortOrder::<DeadJobSortField>::default(), request)
    }

    async fn retry(&self, job: &ScheduledJob) -> Result<Retried, DomainError> {
        let mut jobs = self.jobs.lock().unwrap();
        let Some(at) = jobs.iter().position(|held| held.job.id() == job.id()) else {
            return Ok(Retried::NoLongerDead);
        };
        let stored = &jobs[at].job;
        if stored.status() != JobStatus::Dead || stored.attempt() != job.attempt() {
            return Ok(Retried::NoLongerDead);
        }
        if job.key().is_some() && jobs.iter().any(|held| is_live_twin(&held.job, job)) {
            return Ok(Retried::SameWorkQueued);
        }
        jobs[at] = Held {
            job: copy_job(job)?,
            lease: Lease::Live,
        };
        Ok(Retried::Queued)
    }

    async fn supersede_dead(&self, job: &ScheduledJob) -> Result<u64, DomainError> {
        if job.key().is_none() {
            return Ok(0);
        }
        let mut superseded = 0;
        for held in self.jobs.lock().unwrap().iter_mut() {
            let given_up = held.job.status() == JobStatus::Dead
                && held.job.key() == job.key()
                && held.job.tenant_id() == job.tenant_id();
            if given_up {
                held.job.supersede()?;
                superseded += 1;
            }
        }
        Ok(superseded)
    }

    async fn cleanup(&self, older_than_days: u32) -> Result<u64, DomainError> {
        let before = clock::now().saturating_sub(time::Duration::days(i64::from(older_than_days)));
        let mut jobs = self.jobs.lock().unwrap();
        let mut ended: Vec<_> = jobs
            .iter()
            .filter(|held| {
                matches!(
                    held.job.status(),
                    JobStatus::Completed | JobStatus::Dead | JobStatus::Superseded
                ) && held.job.created_at() < before
            })
            .map(|held| (held.job.created_at(), *held.job.id()))
            .collect();
        ended.sort_unstable_by_key(|(at, id)| (*at, *id.as_uuid()));
        let removed: HashSet<_> = ended.into_iter().take(1_000).map(|(_, id)| id).collect();
        jobs.retain(|held| !removed.contains(held.job.id()));
        Ok(removed.len() as u64)
    }
}

impl Fake for Arc<dyn JobQueue> {
    fn fake() -> Self {
        Arc::new(FakeJobQueue::new())
    }
}

/// Whether `held` is waiting or running under the key `job` carries.
fn is_live_twin(held: &ScheduledJob, job: &ScheduledJob) -> bool {
    held.key() == job.key() && matches!(held.status(), JobStatus::Pending | JobStatus::Running)
}

/// Whether `held` keeps `job` from being queued: it waits or runs under
/// the same key, or both are keyed once and `held` is kept at all.
fn holds_its_key(held: &ScheduledJob, job: &ScheduledJob) -> bool {
    let both_once = held.key_hold() == KeyHold::WhileKept && job.key_hold() == KeyHold::WhileKept;
    is_live_twin(held, job) || (held.key() == job.key() && both_once)
}

/// Gives up every running job whose lease ran out, as a claim does first.
fn give_up_lapsed(jobs: &mut [Held]) -> Result<(), DomainError> {
    for held in jobs.iter_mut().filter(|held| held.lease == Lease::Lapsed) {
        held.job.abandon()?;
        held.lease = Lease::Live;
    }
    Ok(())
}

/// Whether `job` is pending, due by `now`, and of a type `claim` takes.
fn is_due_in_lane(job: &ScheduledJob, claim: &JobClaim<'_>, now: OffsetDateTime) -> bool {
    job.status() == JobStatus::Pending
        && job.run_at() <= now
        && claim.job_types.contains(job.job_type())
}

/// The jobs at `order` a claim takes: at most its limit, and at most its
/// share of any one tenant's.
fn fair_share(jobs: &[Held], order: &[usize], claim: &JobClaim<'_>) -> Vec<usize> {
    let mut per_tenant: HashMap<Option<TenantId>, u32> = HashMap::new();
    let mut taken = Vec::new();
    for at in order {
        if taken.len() >= claim.limit.get() as usize {
            break;
        }
        let count = per_tenant
            .entry(jobs[*at].job.tenant_id().copied())
            .or_default();
        if *count >= claim.per_tenant.get() {
            continue;
        }
        *count += 1;
        taken.push(*at);
    }
    taken
}

/// A copy of `job`, which does not implement `Clone`, read back as a real
/// queue would.
fn copy_job(job: &ScheduledJob) -> Result<ScheduledJob, DomainError> {
    ScheduledJob::reconstitute(ScheduledJobRow {
        id: *job.id(),
        job_type: job.job_type().clone(),
        tenant_id: job.tenant_id().copied(),
        key: job.key().cloned(),
        key_hold: job.key_hold(),
        payload: job.payload().to_owned(),
        run_at: job.run_at(),
        attempt: job.attempt(),
        max_attempts: job.max_attempts(),
        status: job.status(),
        error: job.error().map(UntrustedText::record),
        created_at: job.created_at(),
        last_attempted_at: job.last_attempted_at(),
    })
}

impl Fake for ScheduledStarts {
    fn fake() -> Self {
        ScheduledStarts {
            queue: Arc::new(FakeJobQueue::new()),
            attempts: NonZeroU32::MIN,
        }
    }
}

impl Fake for EventStarts {
    fn fake() -> Self {
        EventStarts {
            queue: Arc::new(FakeJobQueue::new()),
            attempts: NonZeroU32::MIN,
        }
    }
}

impl Fake for AccountChecks {
    fn fake() -> Self {
        AccountChecks {
            queue: Arc::new(FakeJobQueue::new()),
            attempts: NonZeroU32::MIN,
        }
    }
}

/// No version starts on a schedule.
pub struct NoScheduledWorkflows;

#[async_trait]
impl ScheduledWorkflows for NoScheduledWorkflows {
    async fn list_scheduled(
        &self,
        request: &PageRequest,
    ) -> Result<Page<ScheduledVersion>, DomainError> {
        Ok(Page::last(Vec::new(), request.limit()))
    }
}

impl Fake for Arc<dyn ScheduledWorkflows> {
    fn fake() -> Self {
        Arc::new(NoScheduledWorkflows)
    }
}

impl Fake for LogoutJobs {
    fn fake() -> Self {
        LogoutJobs {
            queue: Arc::new(FakeJobQueue::new()),
            attempts: NonZeroU32::MIN,
        }
    }
}

impl Fake for RunDrives {
    fn fake() -> Self {
        RunDrives {
            queue: Arc::new(FakeJobQueue::new()),
            attempts: NonZeroU32::MIN,
        }
    }
}

/// Sweep claims that hand each round to the first caller only, as the
/// shared claim store does across workers.
#[derive(Default)]
pub struct FakeSweepClaims {
    claimed: Mutex<HashSet<(String, SweepRound)>>,
}

#[async_trait]
impl SweepClaims for FakeSweepClaims {
    async fn claim(&self, sweep: &SweepName, round: SweepRound) -> Result<bool, DomainError> {
        Ok(self
            .claimed
            .lock()
            .unwrap()
            .insert((sweep.as_str().to_owned(), round)))
    }
}

impl Fake for Arc<dyn SweepClaims> {
    fn fake() -> Self {
        Arc::new(FakeSweepClaims::default())
    }
}

/// A timer whose time is up at once, or never.
pub enum FakeJobTimer {
    /// Every wait is over at once: a job that has not finished by its first
    /// poll times out.
    UpAtOnce,
    /// No wait ever ends: no job times out.
    Never,
}

#[async_trait]
impl JobTimer for FakeJobTimer {
    async fn wait(&self, _after: time::Duration) {
        if matches!(self, Self::Never) {
            std::future::pending::<()>().await;
        }
    }
}

impl Fake for Arc<dyn JobTimer> {
    fn fake() -> Self {
        Arc::new(FakeJobTimer::Never)
    }
}

/// Local times read in UTC, whatever the zone.
pub struct UtcTimeZones;

impl TimeZones for UtcTimeZones {
    fn local(
        &self,
        _zone: &Timezone,
        at: OffsetDateTime,
    ) -> Result<PrimitiveDateTime, DomainError> {
        let utc = at.to_offset(time::UtcOffset::UTC);
        Ok(PrimitiveDateTime::new(utc.date(), utc.time()))
    }
}

impl Fake for Arc<dyn TimeZones> {
    fn fake() -> Self {
        Arc::new(UtcTimeZones)
    }
}

/// Stalled work a test lays out, handed back whatever the cut-off.
#[derive(Default)]
pub struct FakeStalledWork {
    /// Runs nobody drives.
    pub runs: Vec<StalledRun>,
    /// Tenants still provisioning whose setup never began or stands
    /// running.
    pub setups: Vec<TenantId>,
    /// Clones still copying.
    pub clones: Vec<StalledClone>,
    /// Deleted tenants whose teardown never began or stands running.
    pub teardowns: Vec<TenantId>,
    cutoffs: Mutex<Vec<OffsetDateTime>>,
}

impl FakeStalledWork {
    /// Work holding the agent runs `runs` nobody drives.
    #[must_use]
    pub fn with_runs(runs: Vec<StalledRun>) -> Self {
        Self {
            runs,
            ..Self::default()
        }
    }

    /// Work holding the tenants `tenants` still provisioning, whose setup
    /// never began or stands running.
    #[must_use]
    pub fn with_setups(tenants: Vec<TenantId>) -> Self {
        Self {
            setups: tenants,
            ..Self::default()
        }
    }

    /// Work holding the deleted tenants `tenants` whose teardown never
    /// began or stands running.
    #[must_use]
    pub fn with_teardowns(tenants: Vec<TenantId>) -> Self {
        Self {
            teardowns: tenants,
            ..Self::default()
        }
    }

    /// Work holding the clones `clones` still copying.
    #[must_use]
    pub fn with_clones(clones: Vec<StalledClone>) -> Self {
        Self {
            clones,
            ..Self::default()
        }
    }

    /// The cut-offs asked for, in order.
    #[must_use]
    pub fn cutoffs(&self) -> Vec<OffsetDateTime> {
        self.cutoffs.lock().unwrap().clone()
    }

    /// Keeps `before` and hands back at most `limit` of `items`.
    fn seen<T: Clone>(&self, before: OffsetDateTime, limit: NonZeroU32, items: &[T]) -> Vec<T> {
        self.cutoffs.lock().unwrap().push(before);
        items.iter().take(limit.get() as usize).cloned().collect()
    }
}

#[async_trait]
impl StalledWork for FakeStalledWork {
    async fn runs_without_lease(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<StalledRun>, DomainError> {
        Ok(self.seen(before, limit, &self.runs))
    }

    async fn setups_left(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<TenantId>, DomainError> {
        Ok(self.seen(before, limit, &self.setups))
    }

    async fn teardowns_left(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<TenantId>, DomainError> {
        Ok(self.seen(before, limit, &self.teardowns))
    }

    async fn clones_copying(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<StalledClone>, DomainError> {
        Ok(self.seen(before, limit, &self.clones))
    }
}

impl Fake for Arc<dyn StalledWork> {
    fn fake() -> Self {
        Arc::new(FakeStalledWork::default())
    }
}
