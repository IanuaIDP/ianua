//! The job that writes an audit log export's file, as the queue carries it,
//! and the handler the worker runs it through.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::audit::access::AuditLogOf;
use ianua_domain::domains::audit::export::AuditLogExport;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AuditExportId, OrganizationId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command as _;
use crate::use_cases::audit::exports::write::WriteUseCase;
use crate::use_cases::scheduling::{Handled, JobHandler};

/// The job type that writes an export's file.
pub const WRITE_EXPORT_JOB: &str = "audit.write_export";

/// How many times the worker tries to write a file before the job is dead.
/// Each try writes the file again from the start; an export still not
/// written a day after it was asked for is given up on.
pub(crate) const WRITE_EXPORT_ATTEMPTS: NonZeroU32 = NonZeroU32::MIN.saturating_add(4);

/// The log an export job reads, as its payload names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "scope", content = "id", rename_all = "snake_case")]
pub enum JobLog {
    /// The platform's log.
    Platform,
    /// An organization's log.
    Organization(OrganizationId),
    /// A tenant's own log.
    Tenant(TenantId),
}

impl From<AuditLogOf> for JobLog {
    fn from(log: AuditLogOf) -> Self {
        match log {
            AuditLogOf::Platform => Self::Platform,
            AuditLogOf::Organization(id) => Self::Organization(id),
            AuditLogOf::Tenant(id) => Self::Tenant(id),
        }
    }
}

impl From<JobLog> for AuditLogOf {
    fn from(log: JobLog) -> Self {
        match log {
            JobLog::Platform => Self::Platform,
            JobLog::Organization(id) => Self::Organization(id),
            JobLog::Tenant(id) => Self::Tenant(id),
        }
    }
}

/// What an export job carries: which export of which log.
///
/// The one definition of the payload, so the side that queues the job and
/// the worker that runs it cannot disagree on a field name. It carries no
/// filter: that stays with the export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WriteJob {
    /// The log the export reads.
    pub log: JobLog,
    /// The export to write.
    pub export_id: AuditExportId,
}

impl WriteJob {
    /// The job that writes `export`'s file.
    #[must_use]
    pub fn of(export: &AuditLogExport) -> Self {
        Self {
            log: export.log().into(),
            export_id: *export.id(),
        }
    }

    /// The job, due now.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the job cannot be built.
    pub fn scheduled(&self) -> Result<ScheduledJob, AppError> {
        let job_type = JobType::new(WRITE_EXPORT_JOB).or_internal()?;
        let payload = serde_json::to_string(self).map_err(AppError::internal)?;
        Ok(ScheduledJob::new(
            job_type,
            payload,
            clock::now(),
            WRITE_EXPORT_ATTEMPTS,
        ))
    }

    /// The payload `job` carries.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the payload is not an export job's.
    pub fn read(job: &ScheduledJob) -> Result<Self, AppError> {
        serde_json::from_str(job.payload()).map_err(AppError::internal)
    }
}

/// Runs export jobs through [`WriteUseCase`].
pub struct WriteExportHandler {
    job_type: JobType,
    write: Arc<WriteUseCase>,
}

impl WriteExportHandler {
    /// A handler writing export files through `write`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(write: Arc<WriteUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(WRITE_EXPORT_JOB)?;
        Ok(Self { job_type, write })
    }
}

#[async_trait]
impl JobHandler for WriteExportHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Writes the export's file. An export not visible yet, or a file that
    /// could not be written, is tried again on the queue's backoff; an
    /// export the domain will no longer mark written is done with.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload = WriteJob::read(job)?;
        after_writing(self.write.execute(&(), auditor, payload).await)
    }
}

/// What a write that came to `written` leaves to do.
///
/// # Errors
///
/// Every error but `AppError::Domain` and `AppError::Conflict`: an export
/// not found yet is tried again, as is a file or store that failed.
fn after_writing(written: Result<(), AppError>) -> Result<Handled, AppError> {
    match written {
        Ok(()) | Err(AppError::Domain(_) | AppError::Conflict(_)) => Ok(Handled::Done),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::audit::exports::write::WritePorts;

    fn handler() -> WriteExportHandler {
        WriteExportHandler::new(Arc::new(WriteUseCase::new(WritePorts::fakes()))).unwrap()
    }

    /// The handler runs the jobs export requests queue.
    #[test]
    fn the_handler_runs_export_jobs() {
        assert_eq!(handler().job_type().as_str(), WRITE_EXPORT_JOB);
    }

    /// Missing exports and storage failures remain errors for the job's
    /// retry path, while a successful write finishes the job.
    #[test]
    fn an_export_not_found_yet_is_tried_again() {
        let not_yet = Err(AppError::NotFound(
            "no such audit log export".to_owned().into(),
        ));
        let unwritten = Err(AppError::internal_msg("store down"));

        assert!(after_writing(not_yet).is_err());
        assert!(after_writing(unwritten).is_err());
        assert_eq!(after_writing(Ok(())).unwrap(), Handled::Done);
    }

    /// An export the domain refuses to mark written is done with, rather
    /// than written again and again.
    #[test]
    fn an_export_the_domain_refuses_is_done() {
        let refused = Err(AppError::from_domain(DomainError::invalid(
            "the export is not pending",
        )));

        assert_eq!(after_writing(refused).unwrap(), Handled::Done);
    }

    /// A job whose payload names no export fails before anything is read.
    #[test]
    fn a_job_without_an_export_fails() {
        let job = ScheduledJob::new(
            JobType::new(WRITE_EXPORT_JOB).unwrap(),
            r#"{"log":{"scope":"platform"}}"#.to_owned(),
            clock::now(),
            WRITE_EXPORT_ATTEMPTS,
        );

        let handled =
            block_on(handler().handle(&job, &test_auditor(Arc::new(FakeEventDispatcher::new()))));

        assert!(matches!(handled, Err(AppError::Internal(_))));
    }

    /// A job for Acme's export reads back as the same log and export it was
    /// queued with.
    #[test]
    fn a_scheduled_job_reads_back_as_the_same_payload() {
        let sent = WriteJob {
            log: JobLog::Tenant(TenantId::new()),
            export_id: AuditExportId::new(),
        };

        let scheduled = sent.scheduled().unwrap();

        assert_eq!(scheduled.job_type().as_str(), WRITE_EXPORT_JOB);
        assert_eq!(WriteJob::read(&scheduled).unwrap(), sent);
    }

    /// A payload naming no export is refused instead of guessed at.
    #[test]
    fn a_payload_without_an_export_is_refused() {
        let scheduled = ScheduledJob::new(
            JobType::new(WRITE_EXPORT_JOB).unwrap(),
            r#"{"log":{"scope":"platform"}}"#.to_owned(),
            clock::now(),
            WRITE_EXPORT_ATTEMPTS,
        );

        assert!(matches!(
            WriteJob::read(&scheduled),
            Err(AppError::Internal(_))
        ));
    }
}
