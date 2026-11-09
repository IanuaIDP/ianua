//! List audit streams: where a tenant's records are sent, and how each
//! stream is going.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ComplianceAction, SystemPermission};
use ianua_domain::domains::tenant::audit_streams::AuditStream;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::AuditStreamStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Where the tenant's streams are kept.
    pub stream_store: Arc<dyn AuditStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the caller's tenant's audit streams.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<AuditStream<ResolvedTenant>>, AppError>;

    /// Every audit stream of the tenant `ctx` acts in, oldest first. Their
    /// credentials stay sealed; the API shows only the kind of destination
    /// and where it points.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the tenant's
    ///   compliance settings.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<AuditStream<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Compliance(ComplianceAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .stream_store
            .list(&ctx.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::streaming::StreamFilter;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::tenant::{FakeAuditStreamStore, test_audit_stream};
    use crate::test_support::{block_on, test_ctx};

    fn listing(authorities: FakeTenantAuthorities) -> ListUseCase {
        let streams = FakeAuditStreamStore::holding(
            test_ctx().tenant_id(),
            [
                test_audit_stream("Splunk", StreamFilter::everything()),
                test_audit_stream("Datadog", StreamFilter::everything()),
            ],
        );
        ListUseCase::new(ListPorts {
            stream_store: Arc::new(streams),
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn list_as(
        uc: &ListUseCase,
        ctx: &CallerContext,
    ) -> Result<Vec<AuditStream<ResolvedTenant>>, AppError> {
        block_on(uc.execute(ctx, ()))
    }

    /// Ann, who may view compliance settings, lists Acme's two streams.
    #[test]
    fn a_compliance_viewer_lists_the_streams() {
        let uc = listing(FakeTenantAuthorities::holding(&[
            SystemPermission::Compliance(ComplianceAction::View),
        ]));

        let streams = list_as(&uc, &test_ctx()).unwrap();

        assert_eq!(streams.len(), 2);
    }

    /// A caller without compliance-view rights cannot list audit streams.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let uc = listing(FakeTenantAuthorities::holding(&[]));

        let result = list_as(&uc, &test_ctx());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list the tenant's audit streams.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = listing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = list_as(&uc, &test_ctx());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot list the tenant's
    /// audit streams.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let uc = listing(FakeTenantAuthorities::holding_everything());

        let result = list_as(&uc, &operator_without_grant());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
