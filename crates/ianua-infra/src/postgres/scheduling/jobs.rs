//! The job queue, kept in the database of the change that asked for each
//! job: a tenant's jobs wherever the tenant lives, the jobs of no tenant in
//! the platform database, seen only by platform work.
//!
//! A job is queued through the store call of the running unit of work, so
//! it is kept exactly when the change is. A job due now is announced on the
//! job channel in the same transaction, so a listening worker hears of it
//! when the change commits. A claim works one database at a
//! time, each in a transaction of its own: it locks the lane's jobs whose
//! holder stopped and gives them up through the job itself, then locks the
//! due pending jobs, oldest first and at most so many of one tenant's,
//! marks them running and holds them until the lease runs out. Locked rows
//! are skipped by every other claim, so no two workers take one job. Each
//! claim starts from another database, so none waits behind the others.
//! An operator's retry puts a dead job back in one statement that changes
//! it only while it is still dead at the attempt read, so two retries at
//! once put it back once.
//!
//! Every call answers within five seconds or fails.

mod record;
mod words;

use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::listing::{Page, PageRequest, SortKey, SortOrder};
use ianua_app::ports::scheduling::{DeadJobSortField, Enqueued, JobClaim, JobQueue, Retried};
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::JobId;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{JobColumns, JobRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long a call may take before it fails.
const ANSWER_WITHIN: Duration = Duration::from_secs(5);

/// The most ended jobs one cleanup round removes from each database.
const CLEANUP_BATCH: i64 = 1_000;

/// How many due jobs a claim locks for each one it may take, so one
/// tenant's backlog cannot fill the locked set alone.
const LOCKED_PER_TAKEN: u32 = 8;

/// The job queue in the platform database and in every database of its own.
pub struct PgJobQueue {
    databases: Arc<Databases>,
    next_first: AtomicUsize,
}

impl std::fmt::Debug for PgJobQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgJobQueue").finish_non_exhaustive()
    }
}

impl PgJobQueue {
    /// The queue over `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self {
            databases,
            next_first: AtomicUsize::new(0),
        }
    }

    /// Every place jobs are kept: the platform database, then each database
    /// of its own.
    fn places(&self) -> Vec<RowScope> {
        let mut places = vec![RowScope::Platform];
        places.extend(
            self.databases
                .with_own_database()
                .into_iter()
                .map(RowScope::Tenant),
        );
        places
    }

    /// [`places`](Self::places), from a different one each time it is asked.
    fn places_in_turn(&self) -> Vec<RowScope> {
        let mut places = self.places();
        let first = self
            .next_first
            .fetch_add(1, Ordering::Relaxed)
            .checked_rem(places.len())
            .unwrap_or(0);
        places.rotate_left(first);
        places
    }

    /// Removes one retention batch from a single database. Each database is
    /// visited separately because tenant databases have separate connections.
    async fn remove_ended(
        &self,
        place: RowScope,
        before: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let result = scoped(&self.databases, place, async |connection| {
            sqlx::query_file!(
                "queries/scheduled_jobs/remove_ended.sql",
                before,
                CLEANUP_BATCH
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(result.rows_affected())
    }

    /// Claims from `place` what `claim` asks for, at most `most` in all.
    async fn claim_in(
        &self,
        place: RowScope,
        claim: &JobClaim<'_>,
        most: NonZeroU32,
    ) -> Result<Vec<ScheduledJob>, DomainError> {
        let job_types: Vec<String> = claim
            .job_types
            .iter()
            .map(|job_type| job_type.as_str().to_owned())
            .collect();
        let locked = most.get().saturating_mul(LOCKED_PER_TAKEN);
        scoped(&self.databases, place, async |connection| {
            let now = clock::now();
            give_up_lapsed(connection, &job_types, now, locked).await?;
            let due = sqlx::query_file_as!(
                JobRecord,
                "queries/scheduled_jobs/due.sql",
                &job_types,
                now,
                i64::from(locked),
                i64::from(claim.per_tenant.get()),
                i64::from(most.get()),
            )
            .fetch_all(&mut *connection)
            .await?;
            let claimed = running_jobs(due)?;
            hold(connection, &claimed, now, now.saturating_add(claim.lease)).await?;
            Ok(claimed)
        })
        .await
    }
}

/// `work`, failed when it takes longer than [`ANSWER_WITHIN`].
async fn bounded<T>(work: impl Future<Output = Result<T, DomainError>>) -> Result<T, DomainError> {
    tokio::time::timeout(ANSWER_WITHIN, work)
        .await
        .map_err(|_| DomainError::infra_msg("the job queue did not answer within five seconds"))?
}

/// `error` carried out of a database call.
fn carried(error: DomainError) -> sqlx::Error {
    sqlx::Error::Decode(Box::new(error))
}

/// Where `job` is kept.
/// The id of the job `columns` describe once inserted, or none when a job
/// with its key is kept already.
async fn inserted(
    connection: &mut PgConnection,
    columns: &JobColumns<'_>,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_file_scalar!(
        "queries/scheduled_jobs/add.sql",
        columns.id,
        columns.tenant_id,
        columns.job_type,
        columns.job_key,
        columns.key_hold,
        columns.payload,
        columns.run_at,
        columns.attempt,
        columns.max_attempts,
        columns.status,
        columns.error,
        columns.created_at,
        columns.last_attempted_at,
    )
    .fetch_optional(connection)
    .await
}

/// Announces on the job channel that a job is due, heard once the
/// transaction on `connection` commits.
async fn announce(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query_file!("queries/scheduled_jobs/announce.sql")
        .execute(connection)
        .await?;
    Ok(())
}

fn place_of(job: &ScheduledJob) -> RowScope {
    job.tenant_id()
        .map_or(RowScope::Platform, |tenant| RowScope::Tenant(*tenant))
}

/// Gives up the lane's running jobs whose holder's lease ran out before
/// `now`, at most `most`, each through the job itself.
async fn give_up_lapsed(
    connection: &mut PgConnection,
    job_types: &[String],
    now: OffsetDateTime,
    most: u32,
) -> Result<(), sqlx::Error> {
    let lapsed = sqlx::query_file_as!(
        JobRecord,
        "queries/scheduled_jobs/lapsed.sql",
        job_types,
        now,
        i64::from(most),
    )
    .fetch_all(&mut *connection)
    .await?;
    let given_up = lapsed
        .into_iter()
        .map(abandoned)
        .collect::<Result<Vec<_>, _>>()
        .map_err(carried)?;
    settle(connection, &given_up).await
}

/// The job `record` holds, marked running at its next attempt.
fn running(record: JobRecord) -> Result<ScheduledJob, DomainError> {
    let mut job = record.into_job()?;
    job.mark_running()?;
    Ok(job)
}

/// Rebuilds and advances each due job before any lease is written.
fn running_jobs(records: Vec<JobRecord>) -> Result<Vec<ScheduledJob>, sqlx::Error> {
    records
        .into_iter()
        .map(running)
        .collect::<Result<Vec<_>, _>>()
        .map_err(carried)
}

/// The ids of the jobs `records` hold, each marked superseded through the
/// job itself, which refuses one that is not dead.
fn superseded_ids(records: Vec<JobRecord>) -> Result<Vec<Uuid>, DomainError> {
    records
        .into_iter()
        .map(|record| {
            let mut job = record.into_job()?;
            job.supersede()?;
            Ok(*job.id().as_uuid())
        })
        .collect()
}

/// The job `record` holds, given up by the worker that stopped.
fn abandoned(record: JobRecord) -> Result<ScheduledJob, DomainError> {
    let mut job = record.into_job()?;
    job.abandon()?;
    Ok(job)
}

/// Marks `jobs`, just claimed at `now`, running and held until `until`.
async fn hold(
    connection: &mut PgConnection,
    jobs: &[ScheduledJob],
    now: OffsetDateTime,
    until: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    let columns: Vec<JobColumns<'_>> = jobs.iter().map(JobColumns::of).collect();
    let ids: Vec<Uuid> = columns.iter().map(|job| *job.id).collect();
    let tenants: Vec<Option<Uuid>> = columns.iter().map(|job| job.tenant_id).collect();
    let attempts: Vec<i32> = columns.iter().map(|job| job.attempt).collect();
    let attempted: Vec<OffsetDateTime> = columns
        .iter()
        .map(|job| job.last_attempted_at.unwrap_or(now))
        .collect();
    sqlx::query_file!(
        "queries/scheduled_jobs/hold.sql",
        &ids,
        &tenants as &[Option<Uuid>],
        &attempts,
        &attempted,
        until,
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// Writes how `jobs` ended, each while it is still running at its attempt.
async fn settle(connection: &mut PgConnection, jobs: &[ScheduledJob]) -> Result<(), sqlx::Error> {
    let columns: Vec<JobColumns<'_>> = jobs.iter().map(JobColumns::of).collect();
    let ids: Vec<Uuid> = columns.iter().map(|job| *job.id).collect();
    let tenants: Vec<Option<Uuid>> = columns.iter().map(|job| job.tenant_id).collect();
    let attempts: Vec<i32> = columns.iter().map(|job| job.attempt).collect();
    let statuses: Vec<String> = columns.iter().map(|job| job.status.to_owned()).collect();
    let run_at: Vec<OffsetDateTime> = columns.iter().map(|job| job.run_at).collect();
    let errors: Vec<Option<String>> = columns
        .iter()
        .map(|job| job.error.map(str::to_owned))
        .collect();
    sqlx::query_file!(
        "queries/scheduled_jobs/settle.sql",
        &ids,
        &tenants as &[Option<Uuid>],
        &attempts,
        &statuses,
        &run_at,
        &errors as &[Option<String>],
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// The moment and id a page of dead jobs starts after, or none for the
/// first page.
fn cursor_of(keys: Option<&[SortKey]>) -> (Option<OffsetDateTime>, Option<Uuid>) {
    let Some([SortKey::Time(at), SortKey::Id(id)]) = keys else {
        return (None, None);
    };
    (Some(*at), Some(*id))
}

#[async_trait]
impl JobQueue for PgJobQueue {
    async fn enqueue(&self, job: &ScheduledJob) -> Result<Enqueued, DomainError> {
        let columns = JobColumns::of(job);
        let due_now = job.run_at() <= clock::now();
        let added = bounded(scoped(&self.databases, place_of(job), async |connection| {
            let added = inserted(connection, &columns).await?;
            if added.is_some() && due_now {
                announce(connection).await?;
            }
            Ok(added)
        }))
        .await?;
        Ok(match added {
            Some(_) => Enqueued::Queued,
            None => Enqueued::AlreadyQueued,
        })
    }

    async fn claim(&self, claim: &JobClaim<'_>) -> Result<Vec<ScheduledJob>, DomainError> {
        bounded(async {
            let mut claimed = Vec::new();
            for place in self.places_in_turn() {
                let left = claim
                    .limit
                    .get()
                    .saturating_sub(u32::try_from(claimed.len()).unwrap_or(u32::MAX));
                let Some(most) = NonZeroU32::new(left) else {
                    break;
                };
                claimed.extend(self.claim_in(place, claim, most).await?);
            }
            Ok(claimed)
        })
        .await
    }

    async fn settle(&self, job: &ScheduledJob) -> Result<(), DomainError> {
        let ended = std::slice::from_ref(job);
        bounded(scoped(&self.databases, place_of(job), async |connection| {
            settle(connection, ended).await
        }))
        .await
    }

    async fn find(&self, id: &JobId) -> Result<Option<ScheduledJob>, DomainError> {
        let lookups = self.places().into_iter().map(|place| {
            scoped(&self.databases, place, async |connection| {
                sqlx::query_file_as!(JobRecord, "queries/scheduled_jobs/by_id.sql", id.as_uuid())
                    .fetch_optional(connection)
                    .await
            })
        });
        let found = bounded(try_join_all(lookups)).await?;
        found
            .into_iter()
            .flatten()
            .next()
            .map(JobRecord::into_job)
            .transpose()
    }

    async fn list_dead(&self, page: &PageRequest) -> Result<Page<ScheduledJob>, DomainError> {
        let order = SortOrder::<DeadJobSortField>::default();
        let keyset = page.keyset(&order)?;
        let (before_at, before_id) = cursor_of(keyset.after());
        let fetch = i64::try_from(keyset.fetch()).unwrap_or(i64::MAX);
        let pages = self.places().into_iter().map(|place| {
            scoped(&self.databases, place, async |connection| {
                sqlx::query_file_as!(
                    JobRecord,
                    "queries/scheduled_jobs/dead.sql",
                    before_at,
                    before_id,
                    fetch,
                )
                .fetch_all(connection)
                .await
            })
        });
        let records = bounded(try_join_all(pages)).await?;
        let jobs = records
            .into_iter()
            .flatten()
            .map(JobRecord::into_job)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.cut(jobs))
    }

    async fn retry(&self, job: &ScheduledJob) -> Result<Retried, DomainError> {
        let columns = JobColumns::of(job);
        bounded(scoped(&self.databases, place_of(job), async |connection| {
            let put_back = sqlx::query_file_scalar!(
                "queries/scheduled_jobs/retry.sql",
                columns.id,
                columns.tenant_id,
                columns.attempt,
                columns.max_attempts,
                columns.run_at,
                columns.status,
            )
            .fetch_optional(&mut *connection)
            .await?;
            if put_back.is_some() {
                return Ok(Retried::Queued);
            }
            let still_dead = sqlx::query_file_scalar!(
                "queries/scheduled_jobs/still_dead.sql",
                columns.id,
                columns.tenant_id,
                columns.attempt,
            )
            .fetch_one(connection)
            .await?;
            Ok(match still_dead {
                true => Retried::SameWorkQueued,
                false => Retried::NoLongerDead,
            })
        }))
        .await
    }

    async fn supersede_dead(&self, job: &ScheduledJob) -> Result<u64, DomainError> {
        let Some(key) = job.key() else {
            return Ok(0);
        };
        let tenant = job.tenant_id().map(|tenant| *tenant.as_uuid());
        bounded(scoped(&self.databases, place_of(job), async |connection| {
            let given_up = sqlx::query_file_as!(
                JobRecord,
                "queries/scheduled_jobs/dead_with_key.sql",
                tenant,
                key.as_str(),
            )
            .fetch_all(&mut *connection)
            .await?;
            let ids = superseded_ids(given_up).map_err(carried)?;
            let done = sqlx::query_file!("queries/scheduled_jobs/supersede.sql", tenant, &ids)
                .execute(connection)
                .await?;
            Ok(done.rows_affected())
        }))
        .await
    }

    async fn cleanup(&self, older_than_days: u32) -> Result<u64, DomainError> {
        let before = clock::now().saturating_sub(time::Duration::days(i64::from(older_than_days)));
        bounded(async {
            let mut removed = 0_u64;
            for place in self.places_in_turn() {
                removed = removed.saturating_add(self.remove_ended(place, before).await?);
            }
            Ok(removed)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_domain::domains::operator::control::OperatorAuthority;
    use ianua_domain::domains::scheduling::job::{NextAttempt, ScheduledJobRow};
    use ianua_domain::domains::scheduling::job_key::{JobKey, KeyHold};
    use ianua_domain::domains::scheduling::job_status::JobStatus;
    use ianua_domain::domains::scheduling::job_type::JobType;
    use ianua_domain::types::{OperatorId, TenantId, UntrustedText};

    use super::*;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::test_support::TestDb;

    const MAIL: &str = "email.send";
    const TLS: &str = "tls.renew";

    fn job_type(name: &str) -> JobType {
        JobType::new(name).unwrap()
    }

    fn attempts(count: u32) -> NonZeroU32 {
        NonZeroU32::new(count).unwrap()
    }

    /// A job of `kind` for `tenant`, due a second ago.
    fn due(kind: &str, tenant: Option<TenantId>) -> ScheduledJob {
        let job = ScheduledJob::new(
            job_type(kind),
            "{}".to_owned(),
            clock::now() - time::Duration::SECOND,
            attempts(3),
        );
        match tenant {
            Some(tenant) => job.for_tenant(tenant),
            None => job,
        }
    }

    fn lane<'a>(job_types: &'a [JobType], per_tenant: u32) -> JobClaim<'a> {
        JobClaim {
            job_types,
            limit: attempts(10),
            per_tenant: attempts(per_tenant),
            lease: time::Duration::MINUTE,
        }
    }

    fn queue(db: &TestDb) -> PgJobQueue {
        PgJobQueue::new(Arc::clone(&db.databases))
    }

    /// A pending platform job created at `at`, so retention tests can
    /// distinguish old records from recently queued work.
    fn queued_at(at: OffsetDateTime) -> ScheduledJob {
        ScheduledJob::reconstitute(ScheduledJobRow {
            id: JobId::new(),
            job_type: job_type(MAIL),
            tenant_id: None,
            key: None,
            key_hold: KeyHold::WhileLive,
            payload: "{}".to_owned(),
            run_at: at,
            attempt: 0,
            max_attempts: attempts(1),
            status: JobStatus::Pending,
            error: None,
            created_at: at,
            last_attempted_at: None,
        })
        .unwrap()
    }

    /// Enqueues three single-attempt mails and settles each failed claim as dead.
    async fn enqueue_dead_mails(queue: &PgJobQueue, types: &[JobType]) {
        for _ in 0..3 {
            let job = ScheduledJob::new(job_type(MAIL), "{}".to_owned(), clock::now(), attempts(1));
            queue
                .enqueue(&job.for_tenant(TenantId::new()))
                .await
                .unwrap();
        }
        for mut job in queue.claim(&lane(types, 10)).await.unwrap() {
            job.mark_failed(UntrustedText::record("bounced"), NextAttempt::AsScheduled)
                .unwrap();
            queue.settle(&job).await.unwrap();
        }
    }

    /// A backlog is removed in bounded rounds, including dead jobs, while
    /// recent completed jobs and old pending work survive every round.
    #[tokio::test]
    async fn cleanup_bounds_each_round_and_makes_progress() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let now = clock::now();
        let old = now - time::Duration::days(20);
        for _ in 0..1_000 {
            let mut job = queued_at(old);
            job.mark_running().unwrap();
            job.mark_completed().unwrap();
            queue.enqueue(&job).await.unwrap();
        }
        let mut dead = queued_at(old);
        dead.mark_running().unwrap();
        dead.mark_failed(UntrustedText::record("failed"), NextAttempt::AsScheduled)
            .unwrap();
        queue.enqueue(&dead).await.unwrap();
        let pending = queued_at(old);
        queue.enqueue(&pending).await.unwrap();
        let mut recent = queued_at(now);
        recent.mark_running().unwrap();
        recent.mark_completed().unwrap();
        queue.enqueue(&recent).await.unwrap();

        let first = queue.cleanup(10).await.unwrap();
        let second = queue.cleanup(10).await.unwrap();
        let third = queue.cleanup(10).await.unwrap();

        assert_eq!((first, second, third), (1_000, 1, 0));
        assert!(queue.find(pending.id()).await.unwrap().is_some());
        assert!(queue.find(recent.id()).await.unwrap().is_some());
        assert!(queue.find(dead.id()).await.unwrap().is_none());
    }

    /// A queued job is found by its id, a tenant's and one of no tenant
    /// alike.
    #[tokio::test]
    async fn a_queued_job_is_found_by_its_id() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let tenants = due(MAIL, Some(TenantId::new()));
        let platforms = due(MAIL, None);

        queue.enqueue(&tenants).await.unwrap();
        queue.enqueue(&platforms).await.unwrap();

        let found = queue.find(tenants.id()).await.unwrap().unwrap();
        assert_eq!(found.tenant_id(), tenants.tenant_id());
        assert_eq!(found.status(), JobStatus::Pending);
        assert!(queue.find(platforms.id()).await.unwrap().is_some());
        assert!(queue.find(&JobId::new()).await.unwrap().is_none());
    }

    /// A duplicate job key is reported as already queued while its job
    /// waits; completing that job lets another with the same key queue.
    #[tokio::test]
    async fn a_key_is_queued_once_while_its_job_lives() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let tenant = TenantId::new();
        let key = || JobKey::new("verify:example.com").unwrap();
        let first = due(MAIL, Some(tenant)).keyed(key());
        let types = [job_type(MAIL)];

        let queued = queue.enqueue(&first).await.unwrap();
        let twin = queue
            .enqueue(&due(MAIL, Some(tenant)).keyed(key()))
            .await
            .unwrap();
        let mut running = queue.claim(&lane(&types, 10)).await.unwrap().remove(0);
        running.mark_completed().unwrap();
        queue.settle(&running).await.unwrap();
        let again = queue
            .enqueue(&due(MAIL, Some(tenant)).keyed(key()))
            .await
            .unwrap();

        assert_eq!(
            (queued, twin, again),
            (Enqueued::Queued, Enqueued::AlreadyQueued, Enqueued::Queued)
        );
    }

    /// Rolling back the unit of work removes the job enqueued inside it.
    #[tokio::test]
    async fn a_job_of_a_rolled_back_change_is_not_kept() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let job = due(MAIL, Some(TenantId::new()));

        atomically(
            &PgUnitOfWork,
            async {
                queue.enqueue(&job).await.unwrap();
            },
            |()| Settlement::Rollback,
        )
        .await
        .unwrap();

        assert!(queue.find(job.id()).await.unwrap().is_none());
    }

    /// A claim takes the due jobs of its lane, marked running at their first
    /// attempt, and leaves a job of another lane and one not yet due.
    #[tokio::test]
    async fn a_claim_takes_the_due_jobs_of_its_lane() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let tenant = TenantId::new();
        let mail = due(MAIL, Some(tenant));
        let later = ScheduledJob::new(
            job_type(MAIL),
            "{}".to_owned(),
            clock::now() + time::Duration::HOUR,
            attempts(3),
        )
        .for_tenant(tenant);
        let tls = due(TLS, Some(tenant));
        for job in [&mail, &later, &tls] {
            queue.enqueue(job).await.unwrap();
        }
        let types = [job_type(MAIL)];

        let claimed = queue.claim(&lane(&types, 10)).await.unwrap();

        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id(), mail.id());
        assert_eq!(claimed[0].status(), JobStatus::Running);
        assert_eq!(claimed[0].attempt(), 1);
    }

    /// A claim limited to one job per tenant takes one from both the busy
    /// tenant's backlog and the quiet tenant's single queued mail.
    #[tokio::test]
    async fn a_claim_shares_out_between_tenants() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let (busy, quiet) = (TenantId::new(), TenantId::new());
        for _ in 0..3 {
            queue.enqueue(&due(MAIL, Some(busy))).await.unwrap();
        }
        queue.enqueue(&due(MAIL, Some(quiet))).await.unwrap();
        let types = [job_type(MAIL)];

        let claimed = queue.claim(&lane(&types, 1)).await.unwrap();

        let mut tenants: Vec<_> = claimed
            .iter()
            .filter_map(|job| job.tenant_id().copied())
            .collect();
        tenants.sort_by_key(|tenant| *tenant.as_uuid());
        let mut expected = vec![busy, quiet];
        expected.sort_by_key(|tenant| *tenant.as_uuid());
        assert_eq!(tenants, expected);
    }

    /// Concurrent claims return the queued mail job to only one worker.
    #[tokio::test]
    async fn a_claimed_job_is_not_claimed_again() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        queue
            .enqueue(&due(MAIL, Some(TenantId::new())))
            .await
            .unwrap();

        let types = [job_type(MAIL)];
        let claim = lane(&types, 10);

        let (first, second) = futures_util::join!(queue.claim(&claim), queue.claim(&claim));

        assert_eq!(first.unwrap().len() + second.unwrap().len(), 1);
    }

    /// A worker stops holding a job; once its lease ran out the job is
    /// given up and taken again at its next attempt, and the stopped
    /// worker's late word on it is not kept.
    #[tokio::test]
    async fn a_job_whose_holder_stopped_is_taken_again() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        queue
            .enqueue(&due(MAIL, Some(TenantId::new())))
            .await
            .unwrap();
        let types = [job_type(MAIL)];
        let gone = JobClaim {
            lease: time::Duration::ZERO,
            ..lane(&types, 10)
        };
        let mut stopped = queue.claim(&gone).await.unwrap().remove(0);

        let retaken = queue.claim(&lane(&types, 10)).await.unwrap().remove(0);
        stopped.mark_completed().unwrap();
        queue.settle(&stopped).await.unwrap();

        assert_eq!(retaken.attempt(), 2);
        let kept = queue.find(retaken.id()).await.unwrap().unwrap();
        assert_eq!(kept.status(), JobStatus::Running);
    }

    /// A job that failed for the last time is dead, and listed for
    /// operators newest first, a page at a time.
    #[tokio::test]
    async fn dead_jobs_are_listed_newest_first() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let types = [job_type(MAIL)];
        enqueue_dead_mails(&queue, &types).await;

        let first = queue
            .list_dead(&PageRequest::first(Limit::new(2).unwrap()))
            .await
            .unwrap();
        let rest = queue
            .list_dead(
                &PageRequest::first(Limit::new(2).unwrap())
                    .following(&first)
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(first.items.len(), 2);
        assert_eq!(rest.items.len(), 1);
        assert!(first.items[0].created_at() >= first.items[1].created_at());
        assert!(
            first
                .items
                .iter()
                .all(|job| job.status() == JobStatus::Dead)
        );
    }

    /// A single-attempt mail of `tenant` under `key`, if given, claimed and
    /// settled dead.
    async fn dead_mail(queue: &PgJobQueue, tenant: TenantId, key: Option<&str>) -> ScheduledJob {
        let job = ScheduledJob::new(job_type(MAIL), "{}".to_owned(), clock::now(), attempts(1))
            .for_tenant(tenant);
        let job = match key {
            Some(key) => job.keyed(JobKey::of("mail", key).unwrap()),
            None => job,
        };
        queue.enqueue(&job).await.unwrap();
        let types = [job_type(MAIL)];
        let mut claimed = queue.claim(&lane(&types, 10)).await.unwrap();
        let mut dead = claimed.pop().unwrap();
        dead.mark_failed(UntrustedText::record("bounced"), NextAttempt::AsScheduled)
            .unwrap();
        queue.settle(&dead).await.unwrap();
        queue.find(dead.id()).await.unwrap().unwrap()
    }

    /// Bob retries a dead mail. It is stored waiting with one more attempt,
    /// leaves the dead list, and the next claim takes it once.
    #[tokio::test]
    async fn a_retried_dead_job_waits_again_and_is_claimed_once() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let mut dead = dead_mail(&queue, TenantId::new(), None).await;
        dead.retry(&OperatorAuthority::assumed(OperatorId::new()).job_retry())
            .unwrap();

        let retried = queue.retry(&dead).await.unwrap();

        assert_eq!(retried, Retried::Queued);
        let stored = queue.find(dead.id()).await.unwrap().unwrap();
        assert_eq!(stored.status(), JobStatus::Pending);
        assert_eq!(stored.max_attempts(), attempts(2));
        let listed = queue.list_dead(&PageRequest::default()).await.unwrap();
        assert!(listed.items.is_empty());
        let types = [job_type(MAIL)];
        let claimed = queue.claim(&lane(&types, 10)).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempt(), 2);
        assert!(queue.claim(&lane(&types, 10)).await.unwrap().is_empty());
    }

    /// Bob and Carol retry the same dead mail at once. One puts it back;
    /// the other is told it is no longer dead, and it waits once.
    #[tokio::test]
    async fn two_retries_at_once_put_a_dead_job_back_once() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let dead = dead_mail(&queue, TenantId::new(), None).await;
        let mut by_bob = queue.find(dead.id()).await.unwrap().unwrap();
        let mut by_carol = queue.find(dead.id()).await.unwrap().unwrap();
        by_bob
            .retry(&OperatorAuthority::assumed(OperatorId::new()).job_retry())
            .unwrap();
        by_carol
            .retry(&OperatorAuthority::assumed(OperatorId::new()).job_retry())
            .unwrap();

        let (bob, carol) = tokio::join!(queue.retry(&by_bob), queue.retry(&by_carol));

        let mut outcomes = [bob.unwrap(), carol.unwrap()];
        outcomes.sort_by_key(|outcome| *outcome == Retried::NoLongerDead);
        assert_eq!(outcomes, [Retried::Queued, Retried::NoLongerDead]);
        let stored = queue.find(dead.id()).await.unwrap().unwrap();
        assert_eq!(stored.max_attempts(), attempts(2));
    }

    /// The welcome mail was queued again under its key and waits. Retrying
    /// the dead one is left undone, so the same mail never waits twice.
    #[tokio::test]
    async fn a_dead_job_whose_work_waits_again_is_left_dead() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let tenant = TenantId::new();
        let mut dead = dead_mail(&queue, tenant, Some("welcome-ann")).await;
        let twin = ScheduledJob::new(
            job_type(MAIL),
            "{}".to_owned(),
            clock::now() + time::Duration::HOUR,
            attempts(1),
        )
        .for_tenant(tenant)
        .keyed(JobKey::of("mail", "welcome-ann").unwrap());
        queue.enqueue(&twin).await.unwrap();
        dead.retry(&OperatorAuthority::assumed(OperatorId::new()).job_retry())
            .unwrap();

        let retried = queue.retry(&dead).await.unwrap();

        assert_eq!(retried, Retried::SameWorkQueued);
        let stored = queue.find(dead.id()).await.unwrap().unwrap();
        assert_eq!(stored.status(), JobStatus::Dead);
    }

    /// Retention visits both the platform and a tenant's own database.
    /// Old pending work in either database remains usable afterwards.
    #[tokio::test]
    async fn cleanup_visits_platform_and_dedicated_databases() {
        let db = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let apart = TenantId::new();
        db.databases.register(apart, own.as_dedicated());
        let queue = queue(&db);
        let old = clock::now() - time::Duration::days(20);
        let mut platform = queued_at(old);
        platform.mark_running().unwrap();
        platform.mark_completed().unwrap();
        let mut dedicated = queued_at(old).for_tenant(apart);
        dedicated.mark_running().unwrap();
        dedicated.mark_completed().unwrap();
        let waiting = queued_at(old).for_tenant(apart);
        for job in [&platform, &dedicated, &waiting] {
            queue.enqueue(job).await.unwrap();
        }

        assert_eq!(queue.cleanup(10).await.unwrap(), 2);
        assert!(queue.find(platform.id()).await.unwrap().is_none());
        assert!(queue.find(dedicated.id()).await.unwrap().is_none());
        assert!(queue.find(waiting.id()).await.unwrap().is_some());
        assert_eq!(queue.cleanup(10).await.unwrap(), 0);
    }

    /// Another cleanup holds one ended job. This round skips that row,
    /// removes the unlocked job, and a later round removes the released one.
    #[tokio::test]
    async fn cleanup_skips_locked_jobs_and_revisits_them() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let old = clock::now() - time::Duration::days(20);
        let mut locked = queued_at(old);
        locked.mark_running().unwrap();
        locked.mark_completed().unwrap();
        let mut free = queued_at(old);
        free.mark_running().unwrap();
        free.mark_completed().unwrap();
        queue.enqueue(&locked).await.unwrap();
        queue.enqueue(&free).await.unwrap();
        let held = db
            .lock_row(
                "SELECT id FROM scheduled_jobs WHERE id = $1 FOR UPDATE",
                locked.id().as_uuid(),
            )
            .await;

        assert_eq!(queue.cleanup(10).await.unwrap(), 1);
        assert!(queue.find(free.id()).await.unwrap().is_none());
        held.rollback().await.unwrap();
        assert_eq!(queue.cleanup(10).await.unwrap(), 1);
        assert!(queue.find(locked.id()).await.unwrap().is_none());
    }

    /// A tenant with a database of its own keeps its jobs there, and a
    /// claim takes them from it.
    #[tokio::test]
    async fn a_tenant_apart_keeps_its_jobs_in_its_own_database() {
        let db = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let apart = TenantId::new();
        db.databases.register(apart, own.as_dedicated());
        let queue = queue(&db);
        let job = due(MAIL, Some(apart));
        let types = [job_type(MAIL)];

        queue.enqueue(&job).await.unwrap();
        let claimed = queue.claim(&lane(&types, 10)).await.unwrap();

        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id(), job.id());
        let own_queue = PgJobQueue::new(Arc::clone(&own.databases));
        assert!(own_queue.find(job.id()).await.unwrap().is_some());
    }

    /// A webhook job of `tenant` keyed once by `key`.
    fn webhook_once(tenant: TenantId, key: &str) -> ScheduledJob {
        due(MAIL, Some(tenant)).keyed_once(JobKey::new(key).unwrap())
    }

    /// The bus delivers Acme's event to its webhook and the job completes.
    /// The bus delivers the same event again: nothing more is queued, while
    /// the same key in Globex's queue is its own.
    #[tokio::test]
    async fn work_keyed_once_is_not_queued_again_after_it_completed() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let acme = TenantId::new();
        let types = [job_type(MAIL)];
        queue
            .enqueue(&webhook_once(acme, "event-1:hook-1"))
            .await
            .unwrap();
        let mut running = queue.claim(&lane(&types, 10)).await.unwrap().remove(0);
        running.mark_completed().unwrap();
        queue.settle(&running).await.unwrap();

        let again = queue
            .enqueue(&webhook_once(acme, "event-1:hook-1"))
            .await
            .unwrap();
        let elsewhere = queue
            .enqueue(&webhook_once(TenantId::new(), "event-1:hook-1"))
            .await
            .unwrap();

        assert_eq!(again, Enqueued::AlreadyQueued);
        assert_eq!(elsewhere, Enqueued::Queued);
        let reread = queue.find(running.id()).await.unwrap().unwrap();
        assert_eq!(reread.key_hold(), KeyHold::WhileKept);
    }

    /// A job keyed once that died still holds its key: the event delivered
    /// again queues nothing, and only an operator's retry runs it again.
    #[tokio::test]
    async fn a_dead_job_keyed_once_still_holds_its_key() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let acme = TenantId::new();
        let types = [job_type(MAIL)];
        let job = ScheduledJob::new(job_type(MAIL), "{}".to_owned(), clock::now(), attempts(1))
            .for_tenant(acme)
            .keyed_once(JobKey::new("event-2:hook-1").unwrap());
        queue.enqueue(&job).await.unwrap();
        let mut running = queue.claim(&lane(&types, 10)).await.unwrap().remove(0);
        running
            .mark_failed(UntrustedText::record("refused"), NextAttempt::AsScheduled)
            .unwrap();
        queue.settle(&running).await.unwrap();

        let again = queue
            .enqueue(&webhook_once(acme, "event-2:hook-1"))
            .await
            .unwrap();

        assert_eq!(again, Enqueued::AlreadyQueued);
    }

    /// Acme's setup step was given up dead; the job queued again under the
    /// same key did the step. The dead one is superseded: it leaves the
    /// dead list and keeps why it failed. Another tenant's dead job under
    /// the same key is left alone, and superseding again changes nothing.
    #[tokio::test]
    async fn the_job_that_did_the_work_supersedes_those_given_up_on_it() {
        let db = TestDb::fresh().await;
        let queue = queue(&db);
        let acme = TenantId::new();
        let globex = TenantId::new();
        let given_up = dead_mail(&queue, acme, Some("step")).await;
        let other = dead_mail(&queue, globex, Some("step")).await;
        let later = due(MAIL, Some(acme)).keyed(JobKey::of("mail", "step").unwrap());
        queue.enqueue(&later).await.unwrap();

        let superseded = queue.supersede_dead(&later).await.unwrap();
        let repeated = queue.supersede_dead(&later).await.unwrap();

        assert_eq!((superseded, repeated), (1, 0));
        let read = queue.find(given_up.id()).await.unwrap().unwrap();
        assert_eq!(read.status(), JobStatus::Superseded);
        assert_eq!(read.error(), Some("bounced"));
        let stranger = queue.find(other.id()).await.unwrap().unwrap();
        assert_eq!(stranger.status(), JobStatus::Dead);
        let listed = queue.list_dead(&PageRequest::default()).await.unwrap();
        assert_eq!(listed.items.len(), 1, "only Globex's job is still dead");
    }
}
