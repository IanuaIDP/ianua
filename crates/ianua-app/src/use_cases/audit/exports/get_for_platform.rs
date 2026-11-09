//! Get an export of the platform's audit log, for operators: where it
//! stands, and a link to its file once written.

use std::sync::Arc;

use ianua_domain::types::AuditExportId;

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::AppError;
use crate::ports::audit::{AuditExportFiles, AuditExportStore};
use crate::use_case::Command;
use crate::use_cases::audit::exports::desk::{Answering, ExportAnswer, answered};

/// The ports [`GetForPlatformUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetForPlatformPorts {
    /// Loads a platform request before a download link is issued.
    pub exports: Arc<dyn AuditExportStore>,
    /// Makes the link each file is fetched through.
    pub files: Arc<dyn AuditExportFiles>,
    /// Who acts on the operator plane.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Answers an export of the platform's audit log.
pub struct GetForPlatformUseCase {
    ports: GetForPlatformPorts,
}

impl GetForPlatformUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: GetForPlatformPorts) -> Self {
        Self { ports }
    }
}

impl Command for GetForPlatformUseCase {
    type Caller = OperatorCaller;
    type Input = AuditExportId;
    type Output = Result<ExportAnswer, AppError>;

    /// Export `id` of the platform's log, with a link that downloads its
    /// file once while it is ready, recording
    /// `operator.audit_log_export_downloaded` for each link handed out.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator's key no longer
    ///   counts.
    /// - `AppError::Forbidden` when the operator is disabled.
    /// - `AppError::NotFound` when the platform's log has no such export.
    /// - `AppError::Internal` when the export cannot be read, the link
    ///   cannot be made or the hand-out cannot be recorded.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        id: AuditExportId,
    ) -> Result<ExportAnswer, AppError> {
        let access = self
            .ports
            .operator_authorities
            .authority(caller)
            .await?
            .audit_log_export();
        let desk = Answering {
            exports: self.ports.exports.as_ref(),
            files: self.ports.files.as_ref(),
        };
        answered(desk, &access, &id, auditor).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::access::AuditLogOf;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::audit::{FakeAuditExportStore, written_export_of};
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    fn get(
        authorities: FakeOperatorAuthorities,
    ) -> (Result<ExportAnswer, AppError>, Arc<FakeEventDispatcher>) {
        let export = written_export_of(AuditLogOf::Platform);
        let id = *export.id();
        let use_case = GetForPlatformUseCase::new(GetForPlatformPorts {
            exports: Arc::new(FakeAuditExportStore::holding(export)),
            operator_authorities: Arc::new(authorities),
            ..GetForPlatformPorts::fakes()
        });
        let sink = Arc::new(FakeEventDispatcher::new());
        let result =
            block_on(use_case.execute(&test_operator_caller(), &test_auditor(sink.clone()), id));
        (result, sink)
    }

    /// Olga's export of the platform's log is written. She gets a link and
    /// the hand-out is recorded on the platform.
    #[test]
    fn an_operator_gets_a_link_to_a_written_export() {
        let (result, sink) = get(FakeOperatorAuthorities::admitting());

        assert!(result.unwrap().download.is_some());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["operator.audit_log_export_downloaded"]
        );
    }

    /// A disabled operator's authority refusal prevents retrieving the
    /// platform export's download link.
    #[test]
    fn a_disabled_operator_gets_no_link() {
        let (result, _) = get(FakeOperatorAuthorities::refusing(Refusal::Forbidden));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
