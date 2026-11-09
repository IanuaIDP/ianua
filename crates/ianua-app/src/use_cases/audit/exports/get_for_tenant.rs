//! Get an export of the tenant's own audit log: where it stands, and a
//! link to its file once written.

use std::sync::Arc;

use ianua_domain::types::AuditExportId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::audit::{AuditExportFiles, AuditExportStore};
use crate::use_case::Command;
use crate::use_cases::audit::exports::desk::{Answering, ExportAnswer, answered};

/// The ports [`GetForTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetForTenantPorts {
    /// Loads the tenant's request before a download link is issued.
    pub exports: Arc<dyn AuditExportStore>,
    /// Makes the link each file is fetched through.
    pub files: Arc<dyn AuditExportFiles>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Answers an export of the caller's tenant's audit log.
pub struct GetForTenantUseCase {
    ports: GetForTenantPorts,
}

impl GetForTenantUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: GetForTenantPorts) -> Self {
        Self { ports }
    }
}

impl Command for GetForTenantUseCase {
    type Caller = CallerContext;
    type Input = AuditExportId;
    type Output = Result<ExportAnswer, AppError>;

    /// Export `id` of the caller's tenant's log, with a link that
    /// downloads its file once while it is ready, recording
    /// `tenant.audit_log_export_downloaded` for each link handed out.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not export the audit log.
    /// - `AppError::NotFound` when the tenant has no such export; another
    ///   log's export answers the same.
    /// - `AppError::Internal` when the export cannot be read, the link
    ///   cannot be made or the hand-out cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: AuditExportId,
    ) -> Result<ExportAnswer, AppError> {
        let access = self
            .ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .audit_log_export()
            .map_err(AppError::from_domain)?;
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
    use ianua_domain::domains::audit::export::state::AuditExportStatus;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::audit::{FakeAuditExportStore, pending_export_of, written_export_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn get(
        exports: FakeAuditExportStore,
        id: AuditExportId,
        authorities: FakeTenantAuthorities,
    ) -> (Result<ExportAnswer, AppError>, Arc<FakeEventDispatcher>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = GetForTenantUseCase::new(GetForTenantPorts {
            exports: Arc::new(exports),
            tenant_authorities: Arc::new(authorities),
            ..GetForTenantPorts::fakes()
        });
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), id));
        (result, sink)
    }

    fn own_log() -> AuditLogOf {
        AuditLogOf::Tenant(test_ctx().tenant_id())
    }

    /// The worker is still writing Ann's export. She sees it pending, with
    /// no link and nothing recorded.
    #[test]
    fn a_pending_export_has_no_link() {
        let export = pending_export_of(own_log());
        let id = *export.id();

        let (result, sink) = get(
            FakeAuditExportStore::holding(export),
            id,
            FakeTenantAuthorities::holding_everything(),
        );

        let answer = result.unwrap();
        assert_eq!(answer.export.status(), AuditExportStatus::Pending);
        assert!(answer.download.is_none());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann's export is written. She gets a link, and the hand-out is
    /// recorded.
    #[test]
    fn a_written_export_answers_a_link() {
        let export = written_export_of(own_log());
        let id = *export.id();

        let (result, sink) = get(
            FakeAuditExportStore::holding(export),
            id,
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(result.unwrap().download.is_some());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["tenant.audit_log_export_downloaded"]
        );
    }

    /// A tenant's authorized caller cannot retrieve another tenant's
    /// export by its ID; it answers not found.
    #[test]
    fn another_tenants_export_is_not_found() {
        let export = written_export_of(AuditLogOf::Tenant(TenantId::new()));
        let id = *export.id();

        let (result, _) = get(
            FakeAuditExportStore::holding(export),
            id,
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Without audit rights, retrieving a tenant export is forbidden and
    /// no download event is recorded.
    #[test]
    fn a_caller_who_may_not_read_the_audit_log_is_refused() {
        let export = written_export_of(own_log());
        let id = *export.id();

        let (result, sink) = get(
            FakeAuditExportStore::holding(export),
            id,
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// The audit-log view right alone does not permit retrieving an export,
    /// and no download event is recorded.
    #[test]
    fn a_caller_who_may_only_view_the_audit_log_gets_no_file() {
        let export = written_export_of(own_log());
        let id = *export.id();

        let (result, sink) = get(
            FakeAuditExportStore::holding(export),
            id,
            FakeTenantAuthorities::holding(&[SystemPermission::ViewAuditLog]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }
}
