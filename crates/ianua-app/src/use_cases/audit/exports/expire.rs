//! Expire exports: once an export's download window is over its file is
//! deleted and the export closed; one the worker did not write within its
//! deadline is given up on, so it no longer holds a place in its log's cap.
//!
//! A file holding a whole audit log must not outlive the week it was made
//! for: a copy left in storage is one more place to leak from.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::audit::export::AuditLogExport;
use ianua_domain::domains::audit::export::state::AuditExportStatus;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::{AuditExportFiles, AuditExportStore};
use crate::use_case::Command;

/// How many exports one round reads.
const PAGE: NonZeroU32 = NonZeroU32::MIN.saturating_add(99);

/// How many rounds one run takes at most, so exports that cannot be closed
/// this time never keep the run going.
const ROUNDS: u32 = 50;

/// What one run ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpireReport {
    /// Written exports whose window was over; each file was deleted.
    pub expired: u64,
    /// Pending exports past their deadline, given up on.
    pub given_up: u64,
    /// Exports that could not be ended this time; each is tried again next
    /// run.
    pub failed: u64,
}

/// How one export ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// Its window was over and its file is gone.
    Expired,
    /// It was not written in time.
    GivenUp,
    /// It could not be ended this time.
    Failed,
}

impl ExpireReport {
    /// This report with one more export's ending counted.
    fn counting(mut self, ending: Ending) -> Self {
        match ending {
            Ending::Expired => self.expired += 1,
            Ending::GivenUp => self.given_up += 1,
            Ending::Failed => self.failed += 1,
        }
        self
    }
}

/// The ports [`ExpireUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExpirePorts {
    /// Finds expired requests and persists their cleanup state.
    pub exports: Arc<dyn AuditExportStore>,
    /// Deletes the files.
    pub files: Arc<dyn AuditExportFiles>,
}

/// Ends every export whose time is over.
pub struct ExpireUseCase {
    ports: ExpirePorts,
}

impl ExpireUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ExpirePorts) -> Self {
        Self { ports }
    }

    /// Ends one export as of `now`, logging what stopped it.
    async fn end_one(&self, mut export: AuditLogExport, now: OffsetDateTime) -> Ending {
        let ended = match export.status() {
            AuditExportStatus::Pending => self.give_up(&mut export, now).await,
            AuditExportStatus::Ready => self.expire(&mut export, now).await,
            AuditExportStatus::Failed | AuditExportStatus::Expired => return Ending::Failed,
        };
        match ended {
            Ok(ending) => ending,
            Err(error) => {
                tracing::warn!(%error, export_id = %export.id(), "audit log export not ended; retried next run");
                Ending::Failed
            }
        }
    }

    /// Gives up on a pending export past its deadline.
    async fn give_up(
        &self,
        export: &mut AuditLogExport,
        now: OffsetDateTime,
    ) -> Result<Ending, AppError> {
        export.give_up(now).map_err(AppError::from_domain)?;
        self.ports.exports.save(export).await.or_internal()?;
        Ok(Ending::GivenUp)
    }

    /// Deletes a written export's file first, then closes it, so a file is
    /// never left behind a closed export.
    async fn expire(
        &self,
        export: &mut AuditLogExport,
        now: OffsetDateTime,
    ) -> Result<Ending, AppError> {
        export.expire(now).map_err(AppError::from_domain)?;
        self.ports.files.delete(export.id()).await.or_internal()?;
        self.ports.exports.save(export).await.or_internal()?;
        Ok(Ending::Expired)
    }
}

impl Command for ExpireUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<ExpireReport, AppError>;

    /// Ends every export of every log due to end at `now`: deletes the file
    /// of each written one whose window is over, and gives up on each
    /// pending one past its deadline. It records nothing: these are the
    /// worker's bookkeeping, and an export's status shows them.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the exports due cannot be read. One
    /// that cannot be ended is logged and counted, and the others still are.
    async fn execute(
        &self,
        (): &(),
        _: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<ExpireReport, AppError> {
        let mut report = ExpireReport::default();
        for _ in 0..ROUNDS {
            let due = self
                .ports
                .exports
                .due_to_end(now, PAGE)
                .await
                .or_internal()?;
            let full = u64::try_from(due.len()).is_ok_and(|count| count >= u64::from(PAGE.get()));
            for export in due {
                report = report.counting(self.end_one(export, now).await);
            }
            if !full || report.failed > 0 {
                return Ok(report);
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::access::AuditLogOf;
    use ianua_domain::domains::audit::export::{DOWNLOAD_WINDOW, WRITE_DEADLINE};
    use ianua_domain::shared::clock;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::audit::{
        FakeAuditExportFiles, FakeAuditExportStore, pending_export_of, written_export_of,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    fn run(
        exports: &Arc<FakeAuditExportStore>,
        files: &Arc<FakeAuditExportFiles>,
        now: OffsetDateTime,
    ) -> ExpireReport {
        let use_case = ExpireUseCase::new(ExpirePorts {
            exports: exports.clone(),
            files: files.clone(),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&(), &auditor, now)).unwrap()
    }

    /// Ann's export was written a week ago. Its file is deleted and it is
    /// closed.
    #[test]
    fn a_written_export_past_its_window_is_expired_and_its_file_deleted() {
        let export = written_export_of(AuditLogOf::Tenant(TenantId::new()));
        let id = *export.id();
        let exports = Arc::new(FakeAuditExportStore::holding(export));
        let files = Arc::new(FakeAuditExportFiles::default());

        let report = run(&exports, &files, clock::now() + DOWNLOAD_WINDOW);

        assert_eq!(report.expired, 1);
        assert_eq!(
            exports.stored(&id).unwrap().status(),
            AuditExportStatus::Expired
        );
        assert!(files.deleted(&id));
    }

    /// The worker never wrote Olga's export. A day on it is given up on,
    /// and no longer waits in the platform's cap.
    #[test]
    fn a_pending_export_past_its_deadline_is_given_up_on() {
        let export = pending_export_of(AuditLogOf::Platform);
        let id = *export.id();
        let exports = Arc::new(FakeAuditExportStore::holding(export));
        let files = Arc::new(FakeAuditExportFiles::default());

        let report = run(&exports, &files, clock::now() + WRITE_DEADLINE);

        assert_eq!(report.given_up, 1);
        assert!(!exports.stored(&id).unwrap().is_pending());
    }

    /// The file store is down. The export stays written, to be expired on
    /// the next run, and the run reports it.
    #[test]
    fn a_file_that_cannot_be_deleted_leaves_the_export_for_the_next_run() {
        let export = written_export_of(AuditLogOf::Platform);
        let id = *export.id();
        let exports = Arc::new(FakeAuditExportStore::holding(export));
        let files = Arc::new(FakeAuditExportFiles::failing());

        let report = run(&exports, &files, clock::now() + DOWNLOAD_WINDOW);

        assert_eq!(report.failed, 1);
        assert_eq!(
            exports.stored(&id).unwrap().status(),
            AuditExportStatus::Ready
        );
    }
}
