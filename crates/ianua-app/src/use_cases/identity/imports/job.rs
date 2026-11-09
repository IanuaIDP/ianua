//! The job that works an import through, as the queue carries it, and the
//! handler the worker runs it with.

use std::num::NonZeroU32;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::JobKey;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::types::{TenantId, UserImportId};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command as _;
use crate::use_cases::identity::imports::run::RunUseCase;
use crate::use_cases::scheduling::{Handled, JobHandler};

/// The job type that works an import through.
pub const IMPORT_JOB: &str = "identity.import";

/// How many times the worker tries an import before it gives up on it.
/// Each try goes on from the last chunk kept, so a later try never repeats
/// an earlier one's work.
pub(crate) const IMPORT_ATTEMPTS: NonZeroU32 = NonZeroU32::MIN.saturating_add(4);

/// What an import job carries: which import of which tenant, and where the
/// links mailed to its accounts land.
///
/// The one definition of the payload, so the side that queues the job and
/// the worker that runs it cannot disagree on a field name. It carries no
/// record: those stay with the import, password hashes included.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportJob {
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// The import to work through.
    pub import_id: UserImportId,
    /// Where each account's confirmation link lands.
    pub scope: LinkScope,
}

impl ImportJob {
    /// The job that works this import through, due now, keyed by the import
    /// so it is queued once.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the job cannot be built.
    pub fn scheduled(&self) -> Result<ScheduledJob, AppError> {
        let job_type = JobType::new(IMPORT_JOB).or_internal()?;
        let key = JobKey::of("user_import", self.import_id).or_internal()?;
        let payload = serde_json::to_string(self).map_err(AppError::internal)?;
        Ok(
            ScheduledJob::new(job_type, payload, clock::now(), IMPORT_ATTEMPTS)
                .for_tenant(self.tenant_id)
                .keyed(key),
        )
    }
}

/// Whether a try of the job is its last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tries {
    /// The queue tries it again if this try fails.
    MoreLeft,
    /// This is the last try: if it fails, the import is given up on.
    Last,
}

/// One try of an import job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRun {
    /// What the job carries.
    pub job: ImportJob,
    /// Whether this try is the last.
    pub tries: Tries,
}

impl ImportRun {
    /// The try `job` is, as the worker claimed it.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the payload is not an import job's.
    pub fn read(job: &ScheduledJob) -> Result<Self, AppError> {
        let payload = serde_json::from_str(job.payload()).map_err(AppError::internal)?;
        let tries = match job.can_retry() {
            true => Tries::MoreLeft,
            false => Tries::Last,
        };
        Ok(Self {
            job: payload,
            tries,
        })
    }
}

/// Runs import jobs through [`RunUseCase`].
pub struct ImportHandler {
    job_type: JobType,
    running: RunUseCase,
}

impl ImportHandler {
    /// A handler working imports through with `running`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the job type is not a valid name.
    pub fn new(running: RunUseCase) -> Result<Self, AppError> {
        Ok(Self {
            job_type: JobType::new(IMPORT_JOB).or_internal()?,
            running,
        })
    }
}

#[async_trait]
impl JobHandler for ImportHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Works the import through. An import deleted since is done, not
    /// failed, so it is not tried again.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let run = ImportRun::read(job)?;
        match self.running.execute(&(), auditor, run).await {
            Ok(()) | Err(AppError::NotFound(_)) => Ok(Handled::Done),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_link_scope;

    fn job() -> ImportJob {
        ImportJob {
            tenant_id: TenantId::new(),
            import_id: UserImportId::new(),
            scope: test_link_scope(),
        }
    }

    fn claimed(job: &ImportJob) -> ScheduledJob {
        let mut scheduled = job.scheduled().unwrap();
        scheduled.mark_running().unwrap();
        scheduled
    }

    /// An import job for Acme reads back as the same tenant, import and
    /// link scope it was queued with, for Acme and keyed by its import.
    #[test]
    fn a_scheduled_job_reads_back_as_the_same_payload() {
        let sent = job();

        let scheduled = claimed(&sent);

        assert_eq!(scheduled.job_type().as_str(), IMPORT_JOB);
        assert_eq!(scheduled.tenant_id(), Some(&sent.tenant_id));
        assert!(scheduled.key().is_some());
        assert_eq!(ImportRun::read(&scheduled).unwrap().job, sent);
    }

    /// The first try of a job tried five times has tries left.
    #[test]
    fn a_first_try_is_not_the_last() {
        assert_eq!(
            ImportRun::read(&claimed(&job())).unwrap().tries,
            Tries::MoreLeft
        );
    }

    /// A payload naming no import is refused instead of guessed at.
    #[test]
    fn a_payload_without_an_import_is_refused() {
        let scheduled = ScheduledJob::new(
            JobType::new(IMPORT_JOB).unwrap(),
            format!(r#"{{"tenant_id":"{}"}}"#, uuid::Uuid::now_v7()),
            clock::now(),
            IMPORT_ATTEMPTS,
        );

        assert!(matches!(
            ImportRun::read(&scheduled),
            Err(AppError::Internal(_))
        ));
    }
}
