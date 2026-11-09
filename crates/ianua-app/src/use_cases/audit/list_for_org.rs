//! Reading the organization's audit log, filtered and a page at a time.

use std::sync::Arc;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::listing::{PageRequest, SortOrder};
use crate::ports::audit::{AuditLogFilter, AuditLogPage, AuditLogSortField, OrgAuditLogStore};
use crate::ports::organization::OrgTenantGrantStore;
use crate::services::lookup::granted_tenants;
use crate::use_case::Query;

/// Which audit entries to return, in what order, and which slice of them.
pub struct ListForOrgRequest {
    /// Narrows the entries returned.
    pub filter: AuditLogFilter,
    /// The fields and directions to order by.
    pub sort: SortOrder<AuditLogSortField>,
    /// Which page of the ordered entries to return.
    pub page: PageRequest,
}

/// The ports [`ListForOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListForOrgPorts {
    /// The organization's audit records.
    pub audit_log: Arc<dyn OrgAuditLogStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The tenants a member was let into, which decide what they read.
    pub tenant_grants: Arc<dyn OrgTenantGrantStore>,
}

/// Lists the audit records of the caller's organization.
pub struct ListForOrgUseCase {
    ports: ListForOrgPorts,
}

impl ListForOrgUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListForOrgPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListForOrgUseCase {
    type Caller = OrgCaller;
    type Input = ListForOrgRequest;
    type Output = Result<AuditLogPage, AppError>;

    /// The page of the audit log of `caller`'s organization that `request`
    /// asks for: its own records and those of the tenants `caller` reaches.
    /// Asking for a tenant they do not reach reads as a tenant with no
    /// records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not read the audit log.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        request: ListForOrgRequest,
    ) -> Result<AuditLogPage, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let granted = granted_tenants(self.ports.tenant_grants.as_ref(), actor.member()).await?;
        let view = actor
            .control()?
            .audit_log_view(organization.id(), &granted)
            .map_err(AppError::from_domain)?;
        self.ports
            .audit_log
            .query(&view, &request.filter, &request.sort, &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::audit::access::{LogReach, OrgLogView};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::listing::{Limit, Page};
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{FakeOrgTenantGrantStore, platform_grant_to};
    use crate::test_support::{block_on, test_org_caller};

    /// Remembers whose audit log was asked for.
    #[derive(Default)]
    struct WatchedAuditLog {
        asked: Mutex<Vec<OrgLogView>>,
    }

    #[async_trait]
    impl OrgAuditLogStore for WatchedAuditLog {
        async fn query(
            &self,
            view: &OrgLogView,
            _: &AuditLogFilter,
            _: &SortOrder<AuditLogSortField>,
            page: &PageRequest,
        ) -> Result<AuditLogPage, DomainError> {
            self.asked.lock().unwrap().push(view.clone());
            Ok(Page::last(Vec::new(), page.limit()))
        }
    }

    fn request() -> ListForOrgRequest {
        ListForOrgRequest {
            filter: AuditLogFilter::default(),
            sort: SortOrder::default(),
            page: PageRequest::first(Limit::new(50).unwrap()),
        }
    }

    fn list_with(
        actors: FakeOrgActors,
        log: Arc<WatchedAuditLog>,
    ) -> Result<AuditLogPage, AppError> {
        list_granted(actors, log, FakeOrgTenantGrantStore::empty())
    }

    fn list_granted(
        actors: FakeOrgActors,
        log: Arc<WatchedAuditLog>,
        grants: FakeOrgTenantGrantStore,
    ) -> Result<AuditLogPage, AppError> {
        let use_case = ListForOrgUseCase::new(ListForOrgPorts {
            audit_log: log,
            org_actors: Arc::new(actors),
            tenant_grants: Arc::new(grants),
        });
        block_on(use_case.execute(&test_org_caller(), request()))
    }

    fn view(reach: LogReach) -> OrgLogView {
        OrgLogView::new(test_org_caller().organization_id(), reach)
    }

    /// The caller, granted `tenant`.
    fn granted(tenant: TenantId) -> FakeOrgTenantGrantStore {
        FakeOrgTenantGrantStore::holding([platform_grant_to(*test_org_caller().member(), tenant)])
    }

    /// Sam, a plain member let into one tenant, reads his own
    /// organization's log as far as that tenant.
    #[test]
    fn a_member_reads_their_own_organization_as_far_as_their_tenants() {
        let log = Arc::new(WatchedAuditLog::default());
        let tenant = TenantId::new();

        list_granted(
            FakeOrgActors::in_role(OrgRole::Member),
            log.clone(),
            granted(tenant),
        )
        .unwrap();

        assert_eq!(
            *log.asked.lock().unwrap(),
            vec![view(LogReach::Tenants(vec![tenant]))]
        );
    }

    /// Ann, the owner, reads every tenant's records.
    #[test]
    fn an_owner_reads_every_tenant() {
        let log = Arc::new(WatchedAuditLog::default());

        list_with(FakeOrgActors::in_role(OrgRole::Owner), log.clone()).unwrap();

        assert_eq!(*log.asked.lock().unwrap(), vec![view(LogReach::Every)]);
    }

    /// Vic, a viewer granted a tenant by mistake, still reaches none: he
    /// reads the organization's own records alone.
    #[test]
    fn a_viewer_reads_no_tenant_whatever_they_were_granted() {
        let log = Arc::new(WatchedAuditLog::default());

        list_granted(
            FakeOrgActors::in_role(OrgRole::Viewer),
            log.clone(),
            granted(TenantId::new()),
        )
        .unwrap();

        assert_eq!(
            *log.asked.lock().unwrap(),
            vec![view(LogReach::Tenants(Vec::new()))]
        );
    }

    /// An owner's key without the audit right is forbidden from reading
    /// the organization's log, and the store is not queried.
    #[test]
    fn a_key_without_the_audit_right_is_refused() {
        let log = Arc::new(WatchedAuditLog::default());

        let result = list_with(
            FakeOrgActors::through_key(OrgRole::Owner, Vec::new()),
            log.clone(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(log.asked.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot read the organization's audit log.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list_with(
            FakeOrgActors::refusing(Refusal::SignedOut),
            Arc::new(WatchedAuditLog::default()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An organization authority refusal prevents reading its audit log.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let result = list_with(
            FakeOrgActors::refusing(Refusal::Forbidden),
            Arc::new(WatchedAuditLog::default()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
