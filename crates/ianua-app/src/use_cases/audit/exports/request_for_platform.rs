//! Request an export of the whole platform's audit log, for operators,
//! written in the background.

use std::sync::Arc;

use ianua_domain::types::AuditExportId;

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::AppError;
use crate::ports::audit::AuditExportStore;
use crate::ports::scheduling::JobQueue;
use crate::use_case::Command;
use crate::use_cases::audit::exports::desk::{ExportLimits, Opening, Selection, opened};

/// The ports [`RequestForPlatformUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestForPlatformPorts {
    /// Keeps the exports.
    pub exports: Arc<dyn AuditExportStore>,
    /// Queues the job that writes each file.
    pub jobs: Arc<dyn JobQueue>,
    /// Who acts on the operator plane.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Asks for an export of the platform's audit log.
pub struct RequestForPlatformUseCase {
    ports: RequestForPlatformPorts,
    limits: ExportLimits,
}

impl RequestForPlatformUseCase {
    /// A use case working through `ports`, within `limits`.
    #[must_use]
    pub fn new(ports: RequestForPlatformPorts, limits: ExportLimits) -> Self {
        Self { ports, limits }
    }
}

impl Command for RequestForPlatformUseCase {
    type Caller = OperatorCaller;
    type Input = Selection;
    type Output = Result<AuditExportId, AppError>;

    /// Opens an export of the platform's log holding what `request` asks
    /// for, queues the job that writes it, and records
    /// `operator.audit_log_export_requested`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator's key no longer
    ///   counts.
    /// - `AppError::Forbidden` when the operator is disabled.
    /// - `AppError::TooManyRequests` when the platform has as many exports
    ///   waiting as it may.
    /// - `AppError::Internal` on persistence, queue or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        request: Selection,
    ) -> Result<AuditExportId, AppError> {
        let access = self
            .ports
            .operator_authorities
            .authority(caller)
            .await?
            .audit_log_export();
        let desk = Opening {
            exports: self.ports.exports.as_ref(),
            jobs: self.ports.jobs.as_ref(),
            limits: self.limits,
        };
        opened(desk, &access, request, auditor).await
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::audit::access::AuditLogOf;
    use ianua_domain::domains::audit::export::filter::{AuditExportFilter, AuditExportFormat};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::audit::FakeAuditExportStore;
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    fn ask(
        authorities: FakeOperatorAuthorities,
        exports: Arc<FakeAuditExportStore>,
        audit: Arc<FakeEventDispatcher>,
    ) -> Result<AuditExportId, AppError> {
        let use_case = RequestForPlatformUseCase::new(
            RequestForPlatformPorts {
                exports,
                operator_authorities: Arc::new(authorities),
                ..RequestForPlatformPorts::fakes()
            },
            ExportLimits {
                pending_per_log: NonZeroU32::MIN,
            },
        );
        let request = Selection {
            filter: AuditExportFilter::default(),
            format: AuditExportFormat::Csv,
        };
        block_on(use_case.execute(&test_operator_caller(), &test_auditor(audit), request))
    }

    /// Olga, an operator, asks for the platform's log. The export is of the
    /// platform's log, and the request is recorded on the platform.
    #[test]
    fn an_operator_exports_the_platforms_log() {
        let exports = Arc::new(FakeAuditExportStore::default());
        let audit = Arc::new(FakeEventDispatcher::new());

        let id = ask(
            FakeOperatorAuthorities::admitting(),
            exports.clone(),
            audit.clone(),
        )
        .unwrap();

        assert_eq!(exports.stored(&id).unwrap().log(), AuditLogOf::Platform);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["operator.audit_log_export_requested"]
        );
    }

    /// A disabled operator's authority refusal prevents requesting a
    /// platform-log export, and no export is stored.
    #[test]
    fn a_disabled_operator_is_refused() {
        let exports = Arc::new(FakeAuditExportStore::default());

        let result = ask(
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
            exports.clone(),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(exports.count(), 0);
    }
}
