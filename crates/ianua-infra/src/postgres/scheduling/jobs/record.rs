//! A job as its row holds it: read back into the aggregate, and written out
//! from it. A job of no tenant has the same columns, without the tenant.

use std::num::NonZeroU32;

use ianua_domain::domains::scheduling::job::{ScheduledJob, ScheduledJobRow};
use ianua_domain::domains::scheduling::job_key::JobKey;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{JobId, TenantId, UntrustedText};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

pub(super) const JOB: Stored = Stored("scheduled job");

/// A job as it is read. The store's checked queries fill it; a job of no
/// tenant reads with no tenant.
pub(super) struct JobRecord {
    pub(super) id: Uuid,
    pub(super) tenant_id: Option<Uuid>,
    pub(super) job_type: String,
    pub(super) job_key: Option<String>,
    pub(super) key_hold: String,
    pub(super) payload: String,
    pub(super) run_at: OffsetDateTime,
    pub(super) attempt: i32,
    pub(super) max_attempts: i32,
    pub(super) status: String,
    pub(super) error: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) last_attempted_at: Option<OffsetDateTime>,
}

impl JobRecord {
    /// The job the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the job keeps.
    pub(super) fn into_job(self) -> Result<ScheduledJob, DomainError> {
        let attempt = u32::try_from(self.attempt)
            .map_err(|_| DomainError::corrupt_row(JOB.0, "a negative attempt"))?;
        let max_attempts = u32::try_from(self.max_attempts)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| DomainError::corrupt_row(JOB.0, "an attempt limit below one"))?;
        ScheduledJob::reconstitute(ScheduledJobRow {
            id: JobId::from_uuid(self.id),
            job_type: JOB.value("job type", JobType::new(self.job_type))?,
            tenant_id: self.tenant_id.map(TenantId::from_uuid),
            key: self
                .job_key
                .map(|key| JOB.value("job key", JobKey::new(key)))
                .transpose()?,
            key_hold: JOB.choice(&self.key_hold)?,
            payload: self.payload,
            run_at: self.run_at,
            attempt,
            max_attempts,
            status: JOB.choice(&self.status)?,
            error: self.error.as_deref().map(UntrustedText::record),
            created_at: self.created_at,
            last_attempted_at: self.last_attempted_at,
        })
    }
}

/// A job's columns, as they are written.
pub(super) struct JobColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) tenant_id: Option<Uuid>,
    pub(super) job_type: &'a str,
    pub(super) job_key: Option<&'a str>,
    pub(super) key_hold: &'static str,
    pub(super) payload: &'a str,
    pub(super) run_at: OffsetDateTime,
    pub(super) attempt: i32,
    pub(super) max_attempts: i32,
    pub(super) status: &'static str,
    pub(super) error: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) last_attempted_at: Option<OffsetDateTime>,
}

impl<'a> JobColumns<'a> {
    /// The columns `job` is written as.
    pub(super) fn of(job: &'a ScheduledJob) -> Self {
        Self {
            id: job.id().as_uuid(),
            tenant_id: job.tenant_id().map(|tenant| *tenant.as_uuid()),
            job_type: job.job_type().as_str(),
            job_key: job.key().map(JobKey::as_str),
            key_hold: job.key_hold().word(),
            payload: job.payload(),
            run_at: job.run_at(),
            attempt: i32::try_from(job.attempt()).unwrap_or(i32::MAX),
            max_attempts: i32::try_from(job.max_attempts().get()).unwrap_or(i32::MAX),
            status: job.status().word(),
            error: job.error(),
            created_at: job.created_at(),
            last_attempted_at: job.last_attempted_at(),
        }
    }
}
