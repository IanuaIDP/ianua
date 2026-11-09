//! Reading a tenant's own audit log, filtered and a page at a time, for its
//! administrators.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::SystemPermission;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::audit::{AuditLogPage, TenantAuditLogStore};
use crate::use_case::Query;
use crate::use_cases::audit::ListForOrgRequest;

/// The ports [`ListForTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListForTenantPorts {
    /// The tenant's audit records.
    pub audit_log: Arc<dyn TenantAuditLogStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the audit records of the caller's tenant.
pub struct ListForTenantUseCase {
    ports: ListForTenantPorts,
}

impl ListForTenantUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListForTenantPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListForTenantUseCase {
    type Caller = CallerContext;
    type Input = ListForOrgRequest;
    type Output = Result<AuditLogPage, AppError>;

    /// The page of the audit log of the tenant `ctx` acts in that `request`
    /// asks for. A tenant named in the filter is ignored: the log read is
    /// always the caller's own tenant's.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the audit log.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListForOrgRequest,
    ) -> Result<AuditLogPage, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::ViewAuditLog)
            .map_err(AppError::from_domain)?;
        let mut filter = request.filter;
        filter.tenant_id = Some(ctx.tenant_id());
        self.ports
            .audit_log
            .query(&ctx.tenant(), &filter, &request.sort, &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::listing::{Limit, PageRequest, SortOrder};
    use crate::ports::audit::AuditLogFilter;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::audit::WatchedAuditLog;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{block_on, test_ctx};

    fn request(filter: AuditLogFilter) -> ListForOrgRequest {
        ListForOrgRequest {
            filter,
            sort: SortOrder::default(),
            page: PageRequest::first(Limit::new(50).unwrap()),
        }
    }

    fn list_as(
        ctx: &CallerContext,
        authorities: FakeTenantAuthorities,
        log: Arc<WatchedAuditLog>,
        filter: AuditLogFilter,
    ) -> Result<AuditLogPage, AppError> {
        let uc = ListForTenantUseCase::new(ListForTenantPorts {
            audit_log: log,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(uc.execute(ctx, request(filter)))
    }

    /// Ann, who may view the audit log, reads Acme's. Its own log is read.
    #[test]
    fn an_auditor_reads_their_tenants_log() {
        let log = Arc::new(WatchedAuditLog::default());

        list_as(
            &test_ctx(),
            FakeTenantAuthorities::holding(&[SystemPermission::ViewAuditLog]),
            log.clone(),
            AuditLogFilter::default(),
        )
        .unwrap();

        assert_eq!(log.asked()[0].0, Some(test_ctx().tenant_id()));
    }

    /// A filter naming another tenant is replaced with the caller's own
    /// tenant before querying the audit log.
    #[test]
    fn a_filter_naming_another_tenant_reads_only_the_callers() {
        let log = Arc::new(WatchedAuditLog::default());
        let filter = AuditLogFilter {
            tenant_id: Some(TenantId::new()),
            ..AuditLogFilter::default()
        };

        list_as(
            &test_ctx(),
            FakeTenantAuthorities::holding_everything(),
            log.clone(),
            filter,
        )
        .unwrap();

        assert_eq!(log.asked()[0].1.tenant_id, Some(test_ctx().tenant_id()));
    }

    /// Without the audit-log view right, reading the tenant's log is
    /// forbidden and the store is not queried.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let log = Arc::new(WatchedAuditLog::default());

        let result = list_as(
            &test_ctx(),
            FakeTenantAuthorities::holding(&[]),
            log.clone(),
            AuditLogFilter::default(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(log.asked().is_empty());
    }

    /// A signed-out session cannot read the tenant's audit log.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list_as(
            &test_ctx(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Arc::new(WatchedAuditLog::default()),
            AuditLogFilter::default(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot read a tenant's
    /// audit log.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let result = list_as(
            &operator_without_grant(),
            FakeTenantAuthorities::holding_everything(),
            Arc::new(WatchedAuditLog::default()),
            AuditLogFilter::default(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
