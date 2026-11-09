//! Request an export of the tenant's own audit log, written in the
//! background.

use std::sync::Arc;

use ianua_domain::domains::workflows::triggers::before::GuardedChange;
use ianua_domain::types::AuditExportId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::audit::AuditExportStore;
use crate::ports::scheduling::JobQueue;
use crate::ports::workflows::ChangeGuard;
use crate::services::guarded::ensure_rules_allow;
use crate::use_case::Command;
use crate::use_cases::audit::exports::desk::{ExportLimits, Opening, Selection, opened};

/// The ports [`RequestForTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestForTenantPorts {
    /// Keeps the exports.
    pub exports: Arc<dyn AuditExportStore>,
    /// Queues the job that writes each file.
    pub jobs: Arc<dyn JobQueue>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The company's "before" rules, asked before the audit trail leaves
    /// the company.
    pub guard: Arc<dyn ChangeGuard>,
}

/// Asks for an export of the caller's tenant's audit log.
pub struct RequestForTenantUseCase {
    ports: RequestForTenantPorts,
    limits: ExportLimits,
}

impl RequestForTenantUseCase {
    /// A use case working through `ports`, within `limits`.
    #[must_use]
    pub fn new(ports: RequestForTenantPorts, limits: ExportLimits) -> Self {
        Self { ports, limits }
    }
}

impl Command for RequestForTenantUseCase {
    type Caller = CallerContext;
    type Input = Selection;
    type Output = Result<AuditExportId, AppError>;

    /// Opens an export of the caller's tenant's own log holding what
    /// `request` asks for, queues the job that writes it, and records
    /// `tenant.audit_log_export_requested`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not export the audit log.
    /// - `AppError::TooManyRequests` when the tenant has as many exports
    ///   waiting as it may.
    /// - `AppError::Internal` on persistence, queue or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: Selection,
    ) -> Result<AuditExportId, AppError> {
        let access = self
            .ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .audit_log_export()
            .map_err(AppError::from_domain)?;
        let fields = [
            ("format", request.format.as_str().to_owned()),
            ("asked_by", ctx.actor().audit_label()),
        ];
        let guard = self.ports.guard.as_ref();
        let change = GuardedChange::AuditExported;
        ensure_rules_allow(guard, &ctx.tenant(), auditor, change, &fields).await?;
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
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::audit::FakeAuditExportStore;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::audit::exports::job::WRITE_EXPORT_JOB;

    struct Fixture {
        exports: Arc<FakeAuditExportStore>,
        jobs: Arc<FakeJobQueue>,
        audit: Arc<FakeEventDispatcher>,
        authorities: Arc<dyn TenantAuthorities>,
        guard: Arc<dyn ChangeGuard>,
        pending_per_log: u32,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                exports: Arc::new(FakeAuditExportStore::default()),
                jobs: Arc::new(FakeJobQueue::new()),
                audit: Arc::new(FakeEventDispatcher::new()),
                authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
                guard: crate::test_support::Fake::fake(),
                pending_per_log: 2,
            }
        }

        fn ask(self) -> (Result<AuditExportId, AppError>, Self) {
            let use_case = RequestForTenantUseCase::new(
                RequestForTenantPorts {
                    exports: self.exports.clone(),
                    jobs: self.jobs.clone(),
                    tenant_authorities: self.authorities.clone(),
                    guard: self.guard.clone(),
                },
                ExportLimits {
                    pending_per_log: NonZeroU32::new(self.pending_per_log).unwrap(),
                },
            );
            let request = Selection {
                filter: AuditExportFilter::default(),
                format: AuditExportFormat::Csv,
            };
            let result =
                block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), request));
            (result, self)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann, an auditor, asks for her tenant's log as CSV. The export waits
    /// for the worker, its job is queued, and the request is recorded.
    #[test]
    fn an_export_is_kept_queued_and_recorded() {
        let (result, fixture) = Fixture::new().ask();

        let id = result.unwrap();
        let kept = fixture.exports.stored(&id).unwrap();
        assert!(kept.is_pending());
        assert_eq!(kept.log(), AuditLogOf::Tenant(test_ctx().tenant_id()));
        assert!(fixture.jobs.holds(WRITE_EXPORT_JOB));
        assert_eq!(fixture.recorded(), ["tenant.audit_log_export_requested"]);
    }

    /// Ann's tenant already has two exports waiting, as many as it may.
    /// A third is refused, and nothing more is kept or queued.
    #[test]
    fn a_log_at_its_cap_of_waiting_exports_is_refused() {
        let (_, fixture) = Fixture::new().ask();
        let (_, fixture) = fixture.ask();

        let (result, fixture) = fixture.ask();

        assert!(matches!(result, Err(AppError::TooManyRequests(_))));
        assert_eq!(fixture.exports.count(), 2);
        assert_eq!(fixture.jobs.count(), 2);
    }

    /// Without audit rights, requesting a tenant export is forbidden; no
    /// export, writing job or request event is stored.
    #[test]
    fn a_caller_who_may_not_read_the_audit_log_is_refused() {
        let mut fixture = Fixture::new();
        fixture.authorities = Arc::new(FakeTenantAuthorities::holding(&[]));

        let (result, fixture) = fixture.ask();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.exports.count(), 0);
        assert_eq!(fixture.jobs.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// The audit-log view right alone cannot authorize an export; no
    /// export, writing job or request event is stored.
    #[test]
    fn a_caller_who_may_only_view_the_audit_log_is_refused() {
        let mut fixture = Fixture::new();
        fixture.authorities = Arc::new(FakeTenantAuthorities::holding(&[
            SystemPermission::ViewAuditLog,
        ]));

        let (result, fixture) = fixture.ask();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.exports.count(), 0);
        assert_eq!(fixture.jobs.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out session cannot request an audit-log export.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::new();
        fixture.authorities = Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = fixture.ask();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ann's company rule keeps the audit trail in the company. Tess asks
    /// for an export: the rule refuses it, nothing is kept and no file is
    /// written.
    #[test]
    fn a_company_rule_refusing_stops_the_export() {
        let mut fixture = Fixture::new();
        fixture.guard = Arc::new(crate::test_support::workflows::RefusingGuard);

        let (result, fixture) = fixture.ask();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.exports.count(), 0);
    }
}
