//! A scheduled job: one piece of work to run later.

use std::num::NonZeroU32;

use time::OffsetDateTime;

use crate::domains::scheduling::job_key::{JobKey, KeyHold};
use crate::domains::scheduling::job_status::JobStatus;
use crate::domains::scheduling::job_type::JobType;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{JobId, TenantId, UntrustedText};

/// Why a job a worker took and never settled failed its attempt.
const ABANDONED: &str = "the worker running it stopped before it finished";

/// The word of someone allowed to put a dead job back on the queue. Only
/// this crate makes one, for a platform operator, so nothing else can.
#[derive(Debug)]
pub struct RetryOrder(());

impl RetryOrder {
    /// The order to put a dead job back.
    pub(crate) fn granted() -> Self {
        Self(())
    }
}

/// One piece of work in the job queue, to run at a set time.
///
/// It keeps when to run, how many attempts were made and the last error.
/// The payload is a string only the job's handler reads. A job may name the
/// tenant it works for, so no tenant's jobs crowd out another's, and a key
/// that keeps the same work from being queued twice.
#[derive(Debug)]
pub struct ScheduledJob {
    id: JobId,
    job_type: JobType,
    tenant_id: Option<TenantId>,
    key: Option<JobKey>,
    key_hold: KeyHold,
    payload: String,
    run_at: OffsetDateTime,
    attempt: u32,
    max_attempts: NonZeroU32,
    status: JobStatus,
    error: Option<UntrustedText>,
    created_at: OffsetDateTime,
    last_attempted_at: Option<OffsetDateTime>,
}

impl ScheduledJob {
    /// A new pending job, given up on after `max_attempts` runs.
    #[must_use]
    pub fn new(
        job_type: JobType,
        payload: String,
        run_at: OffsetDateTime,
        max_attempts: NonZeroU32,
    ) -> Self {
        Self {
            id: JobId::new(),
            job_type,
            tenant_id: None,
            key: None,
            key_hold: KeyHold::WhileLive,
            payload,
            run_at,
            attempt: 0,
            max_attempts,
            status: JobStatus::Pending,
            error: None,
            created_at: crate::shared::clock::now(),
            last_attempted_at: None,
        }
    }

    /// This job, working for `tenant`, so the queue shares its workers out
    /// fairly between the tenants that have work waiting.
    #[must_use]
    pub fn for_tenant(mut self, tenant: TenantId) -> Self {
        self.tenant_id = Some(tenant);
        self
    }

    /// This job under `key`: while a job with the same key waits or runs,
    /// queueing this one adds nothing.
    #[must_use]
    pub fn keyed(mut self, key: JobKey) -> Self {
        self.key = Some(key);
        self.key_hold = KeyHold::WhileLive;
        self
    }

    /// This job under `key`, done once: for as long as the job is kept,
    /// whatever became of it, queueing another with the same key adds
    /// nothing, so an event the bus delivers again after its job ended
    /// queues nothing more.
    #[must_use]
    pub fn keyed_once(mut self, key: JobKey) -> Self {
        self.key = Some(key);
        self.key_hold = KeyHold::WhileKept;
        self
    }

    /// Rebuilds a scheduled job from storage.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] for attempts above the cap, missing or
    /// premature attempt times, errors without attempts, or pending jobs with no retries.
    /// Running and completed jobs require attempts; completed jobs cannot retain errors.
    /// Dead jobs require an error and exhausted retries. Stored failed jobs are invalid:
    /// failure must become pending or dead in the same step.
    pub fn reconstitute(row: ScheduledJobRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            job_type: row.job_type,
            tenant_id: row.tenant_id,
            key: row.key,
            key_hold: row.key_hold,
            payload: row.payload,
            run_at: row.run_at,
            attempt: row.attempt,
            max_attempts: row.max_attempts,
            status: row.status,
            error: row.error,
            created_at: row.created_at,
            last_attempted_at: row.last_attempted_at,
        })
    }

    /// Refuses a stored row that breaks a rule a job keeps.
    fn ensure_consistent(row: &ScheduledJobRow) -> Result<(), DomainError> {
        RowCheck::of("scheduled job")
            .holds(
                row.attempt <= row.max_attempts.get(),
                "more attempts than it is allowed",
            )
            .holds(
                (row.attempt == 0) == row.last_attempted_at.is_none(),
                "attempts counted with no attempt recorded, or the other way round",
            )
            .in_order_if(
                row.created_at,
                row.last_attempted_at,
                "attempted before it was scheduled",
            )
            .holds(
                row.attempt > 0 || row.error.is_none(),
                "an error recorded before any attempt",
            )
            .holds(
                fits_its_status(row),
                "its status contradicts its attempts or its error",
            )
            .holds(
                row.key.is_some() || row.key_hold == KeyHold::WhileLive,
                "a key held for good with no key",
            )
            .finish()
    }

    /// The job's id.
    #[must_use]
    pub fn id(&self) -> &JobId {
        &self.id
    }

    /// The kind of job, which picks its handler.
    #[must_use]
    pub fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// The tenant the job works for, or `None` for the platform's own work.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// The key that keeps the same work from being queued twice, if it has
    /// one.
    #[must_use]
    pub fn key(&self) -> Option<&JobKey> {
        self.key.as_ref()
    }

    /// How long its key keeps the same work from being queued again.
    #[must_use]
    pub fn key_hold(&self) -> KeyHold {
        self.key_hold
    }

    /// The payload, which only the handler reads.
    #[must_use]
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// When the job should run next.
    #[must_use]
    pub fn run_at(&self) -> OffsetDateTime {
        self.run_at
    }

    /// How many times the job has started running.
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// How many attempts the job gets before it is dead.
    #[must_use]
    pub fn max_attempts(&self) -> NonZeroU32 {
        self.max_attempts
    }

    /// Where the job is in its life.
    #[must_use]
    pub fn status(&self) -> JobStatus {
        self.status
    }

    /// The last error message, if the job failed. Cleared when it completes.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_ref().map(UntrustedText::as_str)
    }

    /// When this job was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the job last started running, if it has.
    #[must_use]
    pub fn last_attempted_at(&self) -> Option<OffsetDateTime> {
        self.last_attempted_at
    }

    /// Whether the job has attempts left.
    #[must_use]
    pub fn can_retry(&self) -> bool {
        self.attempt < self.max_attempts.get()
    }

    /// Marks the job as picked up by a worker, and counts the attempt.
    ///
    /// # Errors
    ///
    /// - `DomainError::InvalidTransition` if the job is not pending.
    pub fn mark_running(&mut self) -> Result<(), DomainError> {
        self.status = self.status.try_transition(JobStatus::Running)?;
        self.attempt = self.attempt.saturating_add(1);
        self.last_attempted_at = Some(crate::shared::clock::now());
        Ok(())
    }

    /// Marks the job as finished successfully.
    ///
    /// # Errors
    ///
    /// - `DomainError::InvalidTransition` if the job is not running.
    pub fn mark_completed(&mut self) -> Result<(), DomainError> {
        self.status = self.status.try_transition(JobStatus::Completed)?;
        self.error = None;
        Ok(())
    }

    /// Marks the job as failed with `error`, as its handler reported it.
    ///
    /// With attempts left, the job goes back to pending and runs at the time
    /// `next` names. Without, it is dead.
    ///
    /// # Errors
    ///
    /// - `DomainError::InvalidTransition` if the job is not running.
    pub fn mark_failed(
        &mut self,
        error: UntrustedText,
        next: NextAttempt,
    ) -> Result<(), DomainError> {
        self.status = self.status.try_transition(JobStatus::Failed)?;
        self.error = Some(error);
        if !self.can_retry() {
            self.status = self.status.try_transition(JobStatus::Dead)?;
            return Ok(());
        }
        self.run_at = next.due_after(self.run_at);
        self.status = self.status.try_transition(JobStatus::Pending)?;
        Ok(())
    }

    /// Fails the attempt of a job whose worker stopped before settling it,
    /// once the queue's hold on it ran out. It counts as a failed attempt,
    /// so a job that kills its worker every time ends dead rather than
    /// taking workers down for ever. With attempts left it is due again as
    /// it was scheduled.
    ///
    /// # Errors
    ///
    /// - `DomainError::InvalidTransition` if the job is not running.
    pub fn abandon(&mut self) -> Result<(), DomainError> {
        self.mark_failed(UntrustedText::record(ABANDONED), NextAttempt::AsScheduled)
    }

    /// Marks this dead job superseded: a later job queued for the same
    /// work did it. A setup step whose worker crashed is given up when its
    /// hold runs out; once the platform hands the step out again and it is
    /// done, operators no longer find the first job among the dead. It
    /// keeps its attempts and why the last one failed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the job is not dead.
    pub fn supersede(&mut self) -> Result<(), DomainError> {
        self.status = self.status.try_transition(JobStatus::Superseded)?;
        Ok(())
    }

    /// Gives this dead job one more attempt, due at once, on `_order`.
    ///
    /// It keeps the attempts it made and why the last one failed, and runs
    /// once more: should that attempt fail too, it is dead again. Bob
    /// retries Acme's bounced mail once the mail service is back; it goes
    /// out once, and Carol retrying it a moment later is refused.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the job is not dead: it waits, runs
    ///   or finished, or another operator retried it already; or when its
    ///   attempts cannot grow any further.
    pub fn retry(&mut self, _order: &RetryOrder) -> Result<(), DomainError> {
        if self.status != JobStatus::Dead {
            return Err(DomainError::conflict(message!(
                "scheduling-only-a-dead-job-is-retried",
                "only a job that used up its attempts is retried"
            )));
        }
        let Some(more) = self.max_attempts.checked_add(1) else {
            return Err(DomainError::conflict(message!(
                "scheduling-the-job-has-no-attempt-left-to-give",
                "the job has no attempt left to give"
            )));
        };
        self.status = self.status.try_transition(JobStatus::Pending)?;
        self.max_attempts = more;
        self.run_at = crate::shared::clock::now();
        Ok(())
    }
}

/// When a failed job that may still retry runs next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextAttempt {
    /// At this time, such as after a backoff.
    At(OffsetDateTime),
    /// At the time it was already due.
    AsScheduled,
}

impl NextAttempt {
    /// When the retry runs, for a job that was due at `due`.
    fn due_after(self, due: OffsetDateTime) -> OffsetDateTime {
        match self {
            Self::At(at) => at,
            Self::AsScheduled => due,
        }
    }
}

/// A scheduled job as stored, read back through
/// [`ScheduledJob::reconstitute`].
pub struct ScheduledJobRow {
    /// The job's id.
    pub id: JobId,
    /// The kind of job.
    pub job_type: JobType,
    /// The tenant it works for, or `None` for the platform's own work.
    pub tenant_id: Option<TenantId>,
    /// The key that keeps the same work from being queued twice.
    pub key: Option<JobKey>,
    /// How long the key keeps it from being queued again.
    pub key_hold: KeyHold,
    /// The payload the handler reads.
    pub payload: String,
    /// When the job should run next.
    pub run_at: OffsetDateTime,
    /// How many times the job has started running.
    pub attempt: u32,
    /// How many attempts the job gets before it is dead.
    pub max_attempts: NonZeroU32,
    /// Where the job is in its life.
    pub status: JobStatus,
    /// The last error message.
    pub error: Option<UntrustedText>,
    /// When the job was created.
    pub created_at: OffsetDateTime,
    /// When the job last started running.
    pub last_attempted_at: Option<OffsetDateTime>,
}

/// Whether a stored job's attempts and error fit its status. A pending job
/// has an attempt left, a running or completed one ran, a completed one kept
/// no error, and a dead one used every attempt and kept why. A failure is
/// only ever passing, so it is never stored.
fn fits_its_status(row: &ScheduledJobRow) -> bool {
    match row.status {
        JobStatus::Pending => row.attempt < row.max_attempts.get(),
        JobStatus::Running => row.attempt > 0,
        JobStatus::Completed => row.attempt > 0 && row.error.is_none(),
        JobStatus::Dead | JobStatus::Superseded => {
            row.attempt == row.max_attempts.get() && row.error.is_some()
        }
        JobStatus::Failed => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::row_check::refused_as_corrupt;

    fn test_job() -> ScheduledJob {
        ScheduledJob::new(
            JobType::new("domain.verify_retry").unwrap(),
            r#"{"domain_id":"abc"}"#.to_owned(),
            crate::shared::clock::now(),
            attempts(5),
        )
    }

    fn attempts(count: u32) -> NonZeroU32 {
        NonZeroU32::new(count).unwrap()
    }

    /// An email job allowed `max_attempts` runs, with an empty payload.
    fn email_job(max_attempts: u32) -> ScheduledJob {
        ScheduledJob::new(
            JobType::new("email.send").unwrap(),
            "{}".to_owned(),
            crate::shared::clock::now(),
            attempts(max_attempts),
        )
    }

    fn failure(message: &str) -> UntrustedText {
        UntrustedText::record(message)
    }

    /// A newly queued job waits for a worker. It has no attempts, no
    /// error and no attempt time yet.
    #[test]
    fn new_job_starts_pending_with_zero_attempts() {
        let job = test_job();

        assert_eq!(job.status(), JobStatus::Pending);
        assert_eq!(job.attempt(), 0);
        assert!(job.error().is_none());
        assert!(job.last_attempted_at().is_none());
    }

    /// An email job created with a limit of three attempts reports three.
    #[test]
    fn a_job_keeps_the_attempt_limit_it_was_given() {
        let job = email_job(3);

        assert_eq!(job.max_attempts(), attempts(3));
    }

    /// A worker picks up a pending job. It is running, counts one attempt
    /// and records when that attempt started.
    #[test]
    fn mark_running_increments_attempt() {
        let mut job = test_job();

        job.mark_running().unwrap();

        assert_eq!(job.status(), JobStatus::Running);
        assert_eq!(job.attempt(), 1);
        assert!(job.last_attempted_at().is_some());
    }

    /// A running job that finishes is marked completed.
    #[test]
    fn mark_completed_after_running() {
        let mut job = test_job();
        job.mark_running().unwrap();

        job.mark_completed().unwrap();

        assert_eq!(job.status(), JobStatus::Completed);
    }

    /// A domain check fails with "DNS not found" on its first of five tries.
    /// The job goes back to pending, keeps the error and runs again five
    /// minutes later.
    #[test]
    fn mark_failed_retries_when_under_max() {
        let mut job = test_job();
        job.mark_running().unwrap();
        let next = crate::shared::clock::now() + time::Duration::minutes(5);

        job.mark_failed(failure("DNS not found"), NextAttempt::At(next))
            .unwrap();

        assert_eq!(job.status(), JobStatus::Pending);
        assert_eq!(job.error().unwrap(), "DNS not found");
        assert_eq!(job.run_at(), next);
    }

    /// A job allowed one attempt fails that attempt. It is dead and is not
    /// queued again.
    #[test]
    fn mark_failed_goes_dead_at_max_attempts() {
        let mut job = email_job(1);

        job.mark_running().unwrap();
        job.mark_failed(failure("still failing"), NextAttempt::AsScheduled)
            .unwrap();

        assert_eq!(job.status(), JobStatus::Dead);
    }

    /// A job fails and is retried as scheduled. It keeps the time it was
    /// already due.
    #[test]
    fn a_job_retried_as_scheduled_keeps_its_time() {
        let mut job = test_job();
        let due = job.run_at();
        job.mark_running().unwrap();

        job.mark_failed(failure("timeout"), NextAttempt::AsScheduled)
            .unwrap();

        assert_eq!(job.status(), JobStatus::Pending);
        assert_eq!(job.run_at(), due);
    }

    /// An oversized reported failure is retained at the untrusted text limit
    /// without control characters.
    #[test]
    fn a_reported_failure_is_kept_bounded_and_without_control_characters() {
        let mut job = test_job();
        job.mark_running().unwrap();
        let reported = format!("bounced\nforged line{}", "x".repeat(10_000));

        job.mark_failed(failure(&reported), NextAttempt::AsScheduled)
            .unwrap();

        let kept = job.error().unwrap();
        assert_eq!(
            kept.chars().count(),
            crate::types::naming::untrusted_text::MAX_UNTRUSTED_CHARS
        );
        assert!(!kept.chars().any(char::is_control));
    }

    /// A job allowed two attempts may retry after its first failure. Once
    /// the second attempt starts, it has none left.
    #[test]
    fn can_retry_tracks_attempts_vs_max() {
        let mut job = email_job(2);

        assert!(job.can_retry());
        job.mark_running().unwrap();
        assert!(job.can_retry());
        job.mark_failed(failure("err"), NextAttempt::AsScheduled)
            .unwrap();
        assert_eq!(job.status(), JobStatus::Pending);

        job.mark_running().unwrap();
        assert!(!job.can_retry());
    }

    /// A stored certificate renewal that failed twice with "timeout" and
    /// waits for its third try reads back with the same id, type, attempt
    /// count, status and error.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let id = JobId::new();
        let now = crate::shared::clock::now();
        let jt = JobType::new("cert.renew").unwrap();

        let job = ScheduledJob::reconstitute(ScheduledJobRow {
            id,
            job_type: jt,
            tenant_id: None,
            key: None,
            key_hold: KeyHold::WhileLive,
            payload: r#"{"id":"x"}"#.to_owned(),
            run_at: now,
            attempt: 2,
            max_attempts: attempts(5),
            status: JobStatus::Pending,
            error: Some(failure("timeout")),
            created_at: now,
            last_attempted_at: Some(now),
        })
        .unwrap();

        assert_eq!(*job.id(), id);
        assert_eq!(job.job_type().as_str(), "cert.renew");
        assert_eq!(job.attempt(), 2);
        assert_eq!(job.status(), JobStatus::Pending);
        assert_eq!(job.error().unwrap(), "timeout");
    }

    /// A job no worker has started cannot be marked completed.
    #[test]
    fn mark_completed_rejects_pending_job() {
        let mut job = test_job();
        let result = job.mark_completed();
        assert!(result.is_err());
    }

    /// A second worker tries to start a job that already completed. It is
    /// refused, so the work does not run twice.
    #[test]
    fn mark_running_rejects_completed_job() {
        let mut job = test_job();
        job.mark_running().unwrap();
        job.mark_completed().unwrap();

        let result = job.mark_running();
        assert!(result.is_err());
    }

    /// A job created for domain `abc` hands the worker that exact payload.
    /// A different payload would run the job against the wrong record.
    #[test]
    fn a_job_carries_the_payload_the_worker_reads() {
        assert_eq!(test_job().payload(), r#"{"domain_id":"abc"}"#);
    }

    fn stored(job: &ScheduledJob) -> ScheduledJobRow {
        ScheduledJobRow {
            id: job.id,
            job_type: job.job_type.clone(),
            tenant_id: job.tenant_id,
            key: job.key.clone(),
            key_hold: job.key_hold,
            payload: job.payload.clone(),
            run_at: job.run_at,
            attempt: job.attempt,
            max_attempts: job.max_attempts,
            status: job.status,
            error: job.error.clone(),
            created_at: job.created_at,
            last_attempted_at: job.last_attempted_at,
        }
    }

    /// Two stored rows are read back. One counts six attempts out of five.
    /// The other counts one attempt but has no attempt time. Both are
    /// refused as corrupt.
    #[test]
    fn a_stored_job_whose_attempts_do_not_add_up_is_refused() {
        let mut over = stored(&test_job());
        over.attempt = over.max_attempts.get() + 1;
        over.last_attempted_at = Some(over.created_at);
        let mut unrecorded = stored(&test_job());
        unrecorded.attempt = 1;
        unrecorded.last_attempted_at = None;

        for row in [over, unrecorded] {
            assert!(refused_as_corrupt(&ScheduledJob::reconstitute(row)));
        }
    }

    fn attempted(attempt: u32, status: JobStatus, error: Option<&str>) -> ScheduledJobRow {
        let mut row = stored(&test_job());
        row.attempt = attempt;
        row.status = status;
        row.error = error.map(failure);
        row.last_attempted_at = Some(row.created_at);
        row
    }

    /// A stored pending job that has used all five allowed attempts is
    /// refused as corrupt.
    #[test]
    fn a_stored_pending_job_with_no_attempt_left_is_refused() {
        let row = attempted(5, JobStatus::Pending, Some("timeout"));

        assert!(refused_as_corrupt(&ScheduledJob::reconstitute(row)));
    }

    /// A stored dead job with three attempts still available is refused
    /// as corrupt.
    #[test]
    fn a_stored_dead_job_with_attempts_left_is_refused() {
        let row = attempted(2, JobStatus::Dead, Some("timeout"));

        assert!(refused_as_corrupt(&ScheduledJob::reconstitute(row)));
    }

    /// A stored job that is completed but still holds "timeout" is refused.
    /// Completing a job clears its error, so the row was not written by it.
    #[test]
    fn a_stored_completed_job_with_an_error_is_refused() {
        let row = attempted(1, JobStatus::Completed, Some("timeout"));

        assert!(refused_as_corrupt(&ScheduledJob::reconstitute(row)));
    }

    /// A stored job marked failed is refused. A failure turns into pending
    /// or dead in the same step, so a failed job is never saved.
    #[test]
    fn a_stored_failed_job_is_refused() {
        let row = attempted(1, JobStatus::Failed, Some("timeout"));

        assert!(refused_as_corrupt(&ScheduledJob::reconstitute(row)));
    }

    /// A stored job that is running with no attempt counted, or holds an
    /// error before any attempt, is refused.
    #[test]
    fn a_stored_job_with_work_but_no_attempt_is_refused() {
        let mut running = attempted(0, JobStatus::Running, None);
        running.last_attempted_at = None;
        let mut errored = attempted(0, JobStatus::Pending, Some("timeout"));
        errored.last_attempted_at = None;

        for row in [running, errored] {
            assert!(refused_as_corrupt(&ScheduledJob::reconstitute(row)));
        }
    }

    /// A webhook job for Acme under the key of its event and subscription
    /// keeps both, and reads them back from storage.
    #[test]
    fn a_job_keeps_its_tenant_and_key() {
        let tenant = TenantId::new();
        let key = JobKey::new("event-1:subscription-1").unwrap();

        let job = test_job().for_tenant(tenant).keyed(key.clone());
        let read = ScheduledJob::reconstitute(stored(&job)).unwrap();

        assert_eq!(read.tenant_id(), Some(&tenant));
        assert_eq!(read.key(), Some(&key));
    }

    /// A worker took a job and died before settling it. Once the queue's
    /// hold runs out the job is abandoned: the attempt counts, the reason is
    /// kept, and it is due again at its old time.
    #[test]
    fn an_abandoned_job_counts_the_attempt_and_waits_as_scheduled() {
        let mut job = test_job();
        let due = job.run_at();
        job.mark_running().unwrap();

        job.abandon().unwrap();

        assert_eq!(job.status(), JobStatus::Pending);
        assert_eq!(job.attempt(), 1);
        assert_eq!(job.run_at(), due);
        assert!(job.error().is_some());
    }

    /// A job that killed its worker on its last attempt is dead once it is
    /// abandoned, so it cannot take workers down for ever.
    #[test]
    fn a_job_abandoned_on_its_last_attempt_is_dead() {
        let mut job = email_job(1);
        job.mark_running().unwrap();

        job.abandon().unwrap();

        assert_eq!(job.status(), JobStatus::Dead);
    }

    /// Every state a job reaches through its own actions reads back. A
    /// pending, running, completed and dead job each pass the row check.
    #[test]
    fn every_state_the_actions_reach_reads_back() {
        let pending = test_job();
        let mut running = test_job();
        running.mark_running().unwrap();
        let mut completed = test_job();
        completed.mark_running().unwrap();
        completed.mark_completed().unwrap();
        let mut dead = email_job(1);
        dead.mark_running().unwrap();
        dead.mark_failed(failure("bounced"), NextAttempt::AsScheduled)
            .unwrap();

        for job in [pending, running, completed, dead] {
            assert!(ScheduledJob::reconstitute(stored(&job)).is_ok());
        }
    }

    /// Acme's mail, which bounced on its only try.
    fn bounced_mail() -> ScheduledJob {
        let mut job = email_job(1);
        job.mark_running().unwrap();
        job.mark_failed(failure("bounced"), NextAttempt::AsScheduled)
            .unwrap();
        job
    }

    fn bob() -> RetryOrder {
        RetryOrder::granted()
    }

    /// Bob retries Acme's bounced mail. It waits again, due now, with one
    /// more attempt to make, keeping the one it made and why it failed;
    /// and the job reads back.
    #[test]
    fn a_retried_dead_job_waits_again_with_one_more_attempt() {
        let mut job = bounced_mail();

        job.retry(&bob()).unwrap();

        assert_eq!(job.status(), JobStatus::Pending);
        assert_eq!(job.attempt(), 1);
        assert_eq!(job.max_attempts(), attempts(2));
        assert_eq!(job.error(), Some("bounced"));
        assert!(job.run_at() <= crate::shared::clock::now());
        assert!(ScheduledJob::reconstitute(stored(&job)).is_ok());
    }

    /// The retried mail fails again. With its one more attempt spent it is
    /// dead again, and may be retried again.
    #[test]
    fn a_retried_job_that_fails_again_is_dead_again() {
        let mut job = bounced_mail();
        job.retry(&bob()).unwrap();
        job.mark_running().unwrap();

        job.mark_failed(failure("bounced again"), NextAttempt::AsScheduled)
            .unwrap();

        assert_eq!(job.status(), JobStatus::Dead);
        assert!(job.retry(&bob()).is_ok());
    }

    /// Carol retries the mail a moment after Bob did: it waits already, so
    /// her retry is refused.
    #[test]
    fn a_job_retried_already_is_not_retried_twice() {
        let mut job = bounced_mail();
        job.retry(&bob()).unwrap();

        let again = job.retry(&bob());

        assert!(matches!(again, Err(DomainError::Conflict(_))));
        assert_eq!(job.max_attempts(), attempts(2));
    }

    /// A job that waits, runs or finished was never given up, so no
    /// operator retries it.
    #[test]
    fn a_job_that_is_not_dead_is_not_retried() {
        let pending = test_job();
        let mut running = test_job();
        running.mark_running().unwrap();
        let mut completed = test_job();
        completed.mark_running().unwrap();
        completed.mark_completed().unwrap();

        for mut job in [pending, running, completed] {
            assert!(matches!(job.retry(&bob()), Err(DomainError::Conflict(_))));
        }
    }

    /// Acme's webhook job is keyed to be done once; a run's drive job is
    /// keyed while it waits or runs. Each keeps how its key holds, and
    /// both read back.
    #[test]
    fn a_job_keeps_how_its_key_holds() {
        let once = test_job().keyed_once(JobKey::new("event-1:hook-1").unwrap());
        let live = test_job().keyed(JobKey::new("run-1:drive").unwrap());

        assert_eq!(once.key_hold(), KeyHold::WhileKept);
        assert_eq!(live.key_hold(), KeyHold::WhileLive);
        for job in [once, live] {
            let read = ScheduledJob::reconstitute(stored(&job)).unwrap();
            assert_eq!(read.key_hold(), job.key_hold());
        }
    }

    /// A stored job whose key is held for good but which has no key is
    /// refused as corrupt.
    #[test]
    fn a_stored_job_held_for_good_without_a_key_is_refused() {
        let mut row = stored(&test_job());
        row.key_hold = KeyHold::WhileKept;

        assert!(refused_as_corrupt(&ScheduledJob::reconstitute(row)));
    }

    /// Acme's setup step was given up when its worker crashed; a later job
    /// did the step. The first is superseded, keeping its attempts and
    /// why it failed, and reads back.
    #[test]
    fn a_dead_job_whose_work_was_done_later_is_superseded() {
        let mut job = bounced_mail();

        job.supersede().unwrap();

        assert_eq!(job.status(), JobStatus::Superseded);
        assert_eq!(job.error(), Some("bounced"));
        assert!(ScheduledJob::reconstitute(stored(&job)).is_ok());
        assert!(job.retry(&bob()).is_err());
    }

    /// A job that waits, runs or finished was not given up, so nothing
    /// supersedes it.
    #[test]
    fn a_job_that_is_not_dead_is_not_superseded() {
        let mut completed = test_job();
        completed.mark_running().unwrap();
        completed.mark_completed().unwrap();

        for mut job in [test_job(), completed] {
            assert!(job.supersede().is_err());
        }
    }
}
