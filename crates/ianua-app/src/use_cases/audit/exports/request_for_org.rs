//! Request an export of the organization's audit log, across its tenants,
//! written in the background.

use std::sync::Arc;

use ianua_domain::types::AuditExportId;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::audit::AuditExportStore;
use crate::ports::organization::OrgTenantGrantStore;
use crate::ports::scheduling::JobQueue;
use crate::services::lookup::granted_tenants;
use crate::use_case::Command;
use crate::use_cases::audit::exports::desk::{ExportLimits, Opening, Selection, opened};

/// The ports [`RequestForOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestForOrgPorts {
    /// Keeps the exports.
    pub exports: Arc<dyn AuditExportStore>,
    /// Queues the job that writes each file.
    pub jobs: Arc<dyn JobQueue>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The tenants a member was let into, which decide what the file holds.
    pub tenant_grants: Arc<dyn OrgTenantGrantStore>,
}

/// Asks for an export of the caller's organization's audit log.
pub struct RequestForOrgUseCase {
    ports: RequestForOrgPorts,
    limits: ExportLimits,
}

impl RequestForOrgUseCase {
    /// A use case working through `ports`, within `limits`.
    #[must_use]
    pub fn new(ports: RequestForOrgPorts, limits: ExportLimits) -> Self {
        Self { ports, limits }
    }
}

impl Command for RequestForOrgUseCase {
    type Caller = OrgCaller;
    type Input = Selection;
    type Output = Result<AuditExportId, AppError>;

    /// Opens an export of `caller`'s organization's log holding what
    /// `request` asks for, of the organization's own records and those of
    /// the tenants `caller` reaches now, queues the job that writes it, and
    /// records
    /// `organization.audit_log_export_requested`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not export the audit log.
    /// - `AppError::TooManyRequests` when the organization has as many
    ///   exports waiting as it may.
    /// - `AppError::Internal` on persistence, queue or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: Selection,
    ) -> Result<AuditExportId, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let granted = granted_tenants(self.ports.tenant_grants.as_ref(), actor.member()).await?;
        let access = actor
            .control()?
            .audit_log_export(organization.id(), &granted)
            .map_err(AppError::from_domain)?;
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

    use ianua_domain::domains::audit::access::{AuditLogOf, LogReach};
    use ianua_domain::domains::audit::export::filter::{AuditExportFilter, AuditExportFormat};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::permission::{OrgAuditAction, OrgPermission};
    use ianua_domain::types::{Scope, TenantId};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::audit::FakeAuditExportStore;
    use crate::test_support::organization::{FakeOrgTenantGrantStore, platform_grant_to};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    fn ask(
        org_actors: FakeOrgActors,
        exports: Arc<FakeAuditExportStore>,
        audit: Arc<FakeEventDispatcher>,
    ) -> Result<AuditExportId, AppError> {
        ask_granted(org_actors, exports, audit, FakeOrgTenantGrantStore::empty())
    }

    fn ask_granted(
        org_actors: FakeOrgActors,
        exports: Arc<FakeAuditExportStore>,
        audit: Arc<FakeEventDispatcher>,
        grants: FakeOrgTenantGrantStore,
    ) -> Result<AuditExportId, AppError> {
        let use_case = RequestForOrgUseCase::new(
            RequestForOrgPorts {
                exports,
                org_actors: Arc::new(org_actors),
                tenant_grants: Arc::new(grants),
                ..RequestForOrgPorts::fakes()
            },
            ExportLimits {
                pending_per_log: NonZeroU32::MIN,
            },
        );
        let request = Selection {
            filter: AuditExportFilter::default(),
            format: AuditExportFormat::Json,
        };
        block_on(use_case.execute(&test_org_caller(), &test_auditor(audit), request))
    }

    /// Olga, an owner, asks for her organization's log as JSON. The export
    /// is of the organization's log, and the request is recorded there.
    #[test]
    fn an_owner_exports_the_organizations_log() {
        let exports = Arc::new(FakeAuditExportStore::default());
        let audit = Arc::new(FakeEventDispatcher::new());

        let id = ask(
            FakeOrgActors::in_role(OrgRole::Owner),
            exports.clone(),
            audit.clone(),
        )
        .unwrap();

        let kept = exports.stored(&id).unwrap();
        assert!(matches!(kept.log(), AuditLogOf::Organization(_)));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["organization.audit_log_export_requested"]
        );
    }

    /// Vera, a viewer, reads the organization's audit log, and exports it as
    /// she did before exporting needed a right of its own.
    #[test]
    fn a_viewer_still_exports_the_organizations_log() {
        let result = ask(
            FakeOrgActors::in_role(OrgRole::Viewer),
            Arc::new(FakeAuditExportStore::default()),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(result.is_ok());
    }

    /// Max, a member let into one tenant, exports the log. The file is
    /// narrowed to that tenant and the organization's own records, however
    /// little or much he asks for.
    #[test]
    fn a_members_export_holds_only_the_tenants_they_reach() {
        let exports = Arc::new(FakeAuditExportStore::default());
        let tenant = TenantId::new();

        let id = ask_granted(
            FakeOrgActors::in_role(OrgRole::Member),
            exports.clone(),
            Arc::new(FakeEventDispatcher::new()),
            FakeOrgTenantGrantStore::holding([platform_grant_to(
                *test_org_caller().member(),
                tenant,
            )]),
        )
        .unwrap();

        assert_eq!(
            *exports.stored(&id).unwrap().filter().reach(),
            LogReach::Tenants(vec![tenant])
        );
    }

    /// Vic, a viewer, exports the log. His file holds no tenant's records.
    #[test]
    fn a_viewers_export_holds_no_tenant() {
        let exports = Arc::new(FakeAuditExportStore::default());

        let id = ask(
            FakeOrgActors::in_role(OrgRole::Viewer),
            exports.clone(),
            Arc::new(FakeEventDispatcher::new()),
        )
        .unwrap();

        assert_eq!(
            *exports.stored(&id).unwrap().filter().reach(),
            LogReach::Tenants(Vec::new())
        );
    }

    /// A billing contact cannot request an audit-log export, and no export
    /// is stored.
    #[test]
    fn a_billing_contact_may_not_export_the_audit_log() {
        let exports = Arc::new(FakeAuditExportStore::default());

        let result = ask(
            FakeOrgActors::in_role(OrgRole::Billing),
            exports.clone(),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(exports.count(), 0);
    }

    /// An owner's key scoped only to viewing the audit log cannot export
    /// it, and no export is stored.
    #[test]
    fn a_key_that_may_only_view_the_audit_log_may_not_export_it() {
        let exports = Arc::new(FakeAuditExportStore::default());
        let viewing = OrgPermission::AuditLog(OrgAuditAction::View).to_string();

        let result = ask(
            FakeOrgActors::through_key(OrgRole::Owner, vec![Scope::new(viewing).unwrap()]),
            exports.clone(),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(exports.count(), 0);
    }

    /// An organization authority refusal prevents requesting an audit-log
    /// export, and no export is stored.
    #[test]
    fn a_member_who_may_not_read_the_audit_log_is_refused() {
        let exports = Arc::new(FakeAuditExportStore::default());

        let result = ask(
            FakeOrgActors::refusing(Refusal::Forbidden),
            exports.clone(),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(exports.count(), 0);
    }
}
