//! Get an export of the organization's audit log: where it stands, and a
//! link to its file once written.

use std::sync::Arc;

use ianua_domain::types::AuditExportId;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::audit::{AuditExportFiles, AuditExportStore};
use crate::ports::organization::OrgTenantGrantStore;
use crate::services::lookup::granted_tenants;
use crate::use_case::Command;
use crate::use_cases::audit::exports::desk::{Answering, ExportAnswer, answered};

/// The ports [`GetForOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetForOrgPorts {
    /// Loads the organization's request before a download link is issued.
    pub exports: Arc<dyn AuditExportStore>,
    /// Makes the link each file is fetched through.
    pub files: Arc<dyn AuditExportFiles>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The tenants a member was let into, asked again at every read.
    pub tenant_grants: Arc<dyn OrgTenantGrantStore>,
}

/// Answers an export of the caller's organization's audit log.
pub struct GetForOrgUseCase {
    ports: GetForOrgPorts,
}

impl GetForOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: GetForOrgPorts) -> Self {
        Self { ports }
    }
}

impl Command for GetForOrgUseCase {
    type Caller = OrgCaller;
    type Input = AuditExportId;
    type Output = Result<ExportAnswer, AppError>;

    /// Export `id` of `caller`'s organization's log, with a link that
    /// downloads its file once while it is ready, recording
    /// `organization.audit_log_export_downloaded` for each link handed out.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not export the audit log.
    /// - `AppError::NotFound` when the organization has no such export, or
    ///   it holds records of a tenant `caller` does not reach now.
    /// - `AppError::Internal` when the export cannot be read, the link
    ///   cannot be made or the hand-out cannot be recorded.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        id: AuditExportId,
    ) -> Result<ExportAnswer, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let granted = granted_tenants(self.ports.tenant_grants.as_ref(), actor.member()).await?;
        let access = actor
            .control()?
            .audit_log_export(organization.id(), &granted)
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
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::audit::{FakeAuditExportStore, written_export_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    fn get(
        exports: FakeAuditExportStore,
        id: AuditExportId,
        org_actors: FakeOrgActors,
    ) -> Result<ExportAnswer, AppError> {
        let use_case = GetForOrgUseCase::new(GetForOrgPorts {
            exports: Arc::new(exports),
            org_actors: Arc::new(org_actors),
            ..GetForOrgPorts::fakes()
        });
        let sink = Arc::new(FakeEventDispatcher::new());
        block_on(use_case.execute(&test_org_caller(), &test_auditor(sink), id))
    }

    /// A store holding a file of every tenant's records of the caller's
    /// organization, and its id.
    fn ann_s_export() -> (FakeAuditExportStore, AuditExportId) {
        let organization = test_org_caller().organization_id();
        let export = written_export_of(AuditLogOf::Organization(organization));
        let id = *export.id();
        (FakeAuditExportStore::holding(export), id)
    }

    /// An organization's owner cannot retrieve another organization's
    /// export by its ID; it answers not found.
    #[test]
    fn another_organizations_export_is_not_found() {
        let export = written_export_of(AuditLogOf::Organization(OrganizationId::new()));
        let id = *export.id();

        let result = get(
            FakeAuditExportStore::holding(export),
            id,
            FakeOrgActors::in_role(OrgRole::Owner),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann, the owner, asked for a file of every tenant's records. Vic, a
    /// viewer who may export the log, is told there is no such export, and
    /// gets no link; Ann gets hers.
    #[test]
    fn an_export_is_hidden_from_someone_who_reaches_less_than_it_holds() {
        let (vic_s, vic_s_id) = ann_s_export();
        let (ann_s, ann_s_id) = ann_s_export();

        let by_vic = get(vic_s, vic_s_id, FakeOrgActors::in_role(OrgRole::Viewer));
        let by_ann = get(ann_s, ann_s_id, FakeOrgActors::in_role(OrgRole::Owner));

        assert!(matches!(by_vic, Err(AppError::NotFound(_))));
        assert!(by_ann.unwrap().download.is_some());
    }

    /// An organization authority refusal prevents retrieving an export.
    #[test]
    fn a_refused_member_gets_no_export() {
        let export = written_export_of(AuditLogOf::Organization(OrganizationId::new()));
        let id = *export.id();

        let result = get(
            FakeAuditExportStore::holding(export),
            id,
            FakeOrgActors::refusing(Refusal::Forbidden),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
