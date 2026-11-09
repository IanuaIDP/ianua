//! Scheduling ports: the job queue, the claims that run each sweep once,
//! the timer that bounds a job, the local time a schedule is read in, and
//! the work left half-done that a reconciliation sweep picks up again.

use std::num::NonZeroU32;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::scheduling::sweep::{SweepName, SweepRound};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentRunId, JobId, TenantCloneId, TenantId, Timezone};
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};

define_sort_field! {
    /// The one order dead jobs are listed in: newest first.
    pub enum DeadJobSortField {
        /// Order by when the job was queued.
        CreatedAt => "created_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<DeadJobSortField> for ScheduledJob {
    fn sort_key(&self, field: DeadJobSortField) -> SortKey {
        match field {
            DeadJobSortField::CreatedAt => self.created_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// What queueing a job came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    /// The job is queued.
    Queued,
    /// A job with the same key waits or runs already, so nothing was added.
    AlreadyQueued,
}

/// What putting a dead job back on the queue came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retried {
    /// The job waits again.
    Queued,
    /// The job was no longer dead at the attempt it was read at: another
    /// operator put it back first, or it was removed, so nothing changed.
    NoLongerDead,
    /// A job with the same key waits or runs already, so the dead one was
    /// left dead: the same work never waits twice.
    SameWorkQueued,
}

/// Which due jobs one claim takes: the job types of one lane, how many in
/// all, how many of one tenant's, and how long the claimer holds them.
#[derive(Debug, Clone, Copy)]
pub struct JobClaim<'a> {
    /// The job types the lane runs. A claim takes no job of another type.
    pub job_types: &'a [JobType],
    /// The most jobs taken.
    pub limit: NonZeroU32,
    /// The most jobs of any one tenant taken, so one tenant's backlog never
    /// keeps another tenant's jobs waiting.
    pub per_tenant: NonZeroU32,
    /// How long the claimer holds each job. A job still running once this
    /// has passed is taken to be held by a worker that stopped.
    pub lease: time::Duration,
}

/// Dyn-safe port for queueing jobs and handing them to workers.
///
/// Production keeps the queue in the database; there is no in-memory
/// fallback outside tests.
#[async_trait]
pub trait JobQueue: Send + Sync {
    /// Queues `job` to run at its time.
    ///
    /// Inside a unit of work the job is written in that unit's transaction,
    /// so it is kept exactly when the change that asked for it is: a request
    /// that rolls back leaves no job behind, and one that commits never
    /// loses its job. Outside a unit it is written on its own.
    ///
    /// A job with a key is queued only when no job with the same key is
    /// pending or running. A job keyed through
    /// [`ScheduledJob::keyed_once`] is also not queued while a job with
    /// its key, keyed the same way, is kept at all, whatever became of it,
    /// so an event delivered again after its job ended queues nothing. A
    /// job keyed through [`ScheduledJob::keyed`] may be queued again once
    /// the last one ended.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the queue cannot be
    /// written, or does not answer within five seconds.
    async fn enqueue(&self, job: &ScheduledJob) -> Result<Enqueued, DomainError>;

    /// Claims the jobs `claim` asks for, oldest due first, sharing them out
    /// between tenants: at most `claim.per_tenant` of any one tenant's.
    ///
    /// A job is due when it is pending and its time has come, or when it is
    /// running and its lease has run out, which means the worker holding it
    /// stopped. Such a job is first given up through
    /// [`ScheduledJob::abandon`], and taken only if that left it pending.
    ///
    /// Claiming is atomic, so no two workers take the same job. Each job
    /// comes back running, through [`ScheduledJob::mark_running`], and held
    /// until `claim.lease` from now.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the queue cannot be read,
    /// or does not answer within five seconds.
    async fn claim(&self, claim: &JobClaim<'_>) -> Result<Vec<ScheduledJob>, DomainError>;

    /// Keeps how a claimed job ended, as the job itself says: completed,
    /// pending again at its next run time, or dead. The job decided which;
    /// the queue only writes it.
    ///
    /// Written only while the job is still held by this claim, at the same
    /// attempt: a job whose lease ran out and that another worker took
    /// since is left to that worker.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the queue cannot be
    /// written, or does not answer within five seconds.
    async fn settle(&self, job: &ScheduledJob) -> Result<(), DomainError>;

    /// The job `id`, wherever it is in its life, so a request that queued
    /// it can say how it stands.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the queue cannot be read,
    /// or does not answer within five seconds.
    async fn find(&self, id: &JobId) -> Result<Option<ScheduledJob>, DomainError>;

    /// One page of the jobs given up on, newest first, for operators to look
    /// into.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the queue cannot be read,
    /// or does not answer within five seconds, or a validation error when
    /// the page's cursor came from another list.
    async fn list_dead(&self, page: &PageRequest) -> Result<Page<ScheduledJob>, DomainError>;

    /// Puts `job`, retried through [`ScheduledJob::retry`], back on the
    /// queue as it now says, provided the stored job is still dead at the
    /// attempt `job` made. Of two operators retrying one job at once, one
    /// puts it back and the other is told [`Retried::NoLongerDead`].
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the queue cannot be
    /// written, or does not answer within five seconds.
    async fn retry(&self, job: &ScheduledJob) -> Result<Retried, DomainError>;

    /// Marks superseded, through [`ScheduledJob::supersede`], every dead
    /// job of `job`'s tenant under `job`'s key: `job` did the work they
    /// were given up on. A job with no key supersedes nothing.
    ///
    /// Returns how many were superseded.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the queue cannot be read
    /// or written, or does not answer within five seconds.
    async fn supersede_dead(&self, job: &ScheduledJob) -> Result<u64, DomainError>;

    /// Removes a bounded round of completed, dead and superseded jobs
    /// older than the given number of days. Later rounds continue through
    /// the backlog. A job keyed once holds its key until it is removed.
    ///
    /// Returns the number of jobs removed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the queue cannot be
    /// written.
    async fn cleanup(&self, older_than_days: u32) -> Result<u64, DomainError>;
}

/// Dyn-safe port making each round of a sweep run once across every
/// worker.
#[async_trait]
pub trait SweepClaims: Send + Sync {
    /// Claims `round` of `sweep` for this worker. `true` for exactly one
    /// caller of each round, whichever asks first; every other caller of
    /// the same round gets `false`, now or later.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the claim cannot be made
    /// or read, or does not answer within five seconds. The caller does not
    /// run the round then.
    async fn claim(&self, sweep: &SweepName, round: SweepRound) -> Result<bool, DomainError>;
}

/// Dyn-safe port that waits, so a job can be given up once its time is up.
#[async_trait]
pub trait JobTimer: Send + Sync {
    /// Returns once `after` has passed.
    async fn wait(&self, after: time::Duration);
}

/// Dyn-safe port reading a moment as the clock on the wall shows it in a
/// timezone, for schedules written in a tenant's own time.
pub trait TimeZones: Send + Sync {
    /// `at` as it reads in `zone`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the zone is not in the
    /// timezone database.
    fn local(&self, zone: &Timezone, at: OffsetDateTime) -> Result<PrimitiveDateTime, DomainError>;
}

/// An agent run left started with nobody driving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StalledRun {
    /// The tenant the run belongs to.
    pub tenant_id: TenantId,
    /// The execution that needs another worker to resume driving it.
    pub run_id: AgentRunId,
}

/// A clone left copying with nobody copying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StalledClone {
    /// The copy operation that needs another worker to finish it.
    pub clone_id: TenantCloneId,
    /// The tenant it fills.
    pub target: TenantId,
}

/// Dyn-safe port finding work left half-done in a state that only ends when
/// a worker takes it on, so a sweep can hand it out again.
///
/// It reads across every tenant: a worker that stopped leaves the same
/// trace in all of them.
#[async_trait]
pub trait StalledWork: Send + Sync {
    /// Agent runs started before `before` that no worker holds a lease on,
    /// at most `limit` of them, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read, or
    /// the read does not answer within ten seconds.
    async fn runs_without_lease(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<StalledRun>, DomainError>;

    /// Tenants still provisioning, created before `before`, whose setup
    /// never began, or stands running unchanged since before `before`, at
    /// most `limit` of them, oldest first. A tenant whose setup failed is
    /// not one: it waits for an operator, and handing it out every round
    /// would do nothing for ever.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read, or
    /// the read does not answer within ten seconds.
    async fn setups_left(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<TenantId>, DomainError>;

    /// Deleted tenants whose teardown never began, or stands running,
    /// unchanged since before `before`, at most `limit` of them, oldest
    /// first. A tenant whose teardown is done or failed is not one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read, or
    /// the read does not answer within ten seconds.
    async fn teardowns_left(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<TenantId>, DomainError>;

    /// Clones still copying that started before `before`, at most `limit`
    /// of them, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read, or
    /// the read does not answer within ten seconds.
    async fn clones_copying(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<StalledClone>, DomainError>;
}
