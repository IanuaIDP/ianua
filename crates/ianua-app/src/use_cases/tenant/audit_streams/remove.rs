//! Remove audit stream: stop sending a tenant's records to a SIEM for
//! good, and forget where it was.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AuditStreamId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::AuditStreamStore;
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::tenant::audit_streams::lookup::{acting_tenant, existing_stream};

/// The ports [`RemoveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemovePorts {
    /// Tenants, for the one the stream belongs to.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Where the tenant's streams are kept.
    pub stream_store: Arc<dyn AuditStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes an audit stream, with its sealed credentials.
pub struct RemoveUseCase {
    ports: RemovePorts,
}

impl RemoveUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RemovePorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveUseCase {
    type Caller = CallerContext;
    type Input = AuditStreamId;
    type Output = Result<(), AppError>;

    /// Deletes the stream `stream_id` and records
    /// `tenant.audit_stream_removed`, naming the stream.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the tenant's
    ///   compliance settings.
    /// - `AppError::NotFound` when the tenant or the stream does not exist.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        stream_id: AuditStreamId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        TenantControl::new(&authority)
            .ensure_may(&ctx.tenant_id(), TenantArea::AuditStreaming)
            .map_err(AppError::from_domain)?;
        let scope = acting_tenant(self.ports.tenant_store.as_ref(), ctx).await?;
        let tenant = ctx.tenant();
        let store = self.ports.stream_store.as_ref();
        let mut stream = existing_stream(store, &tenant, &stream_id).await?;
        stream
            .remove(&scope, TenantControl::new(&authority))
            .map_err(AppError::from_domain)?;
        store.delete(&tenant, &stream_id).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), stream.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::streaming::StreamFilter;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::tenant::{
        FakeAuditStreamStore, FakeTenantStore, test_audit_stream, test_tenant_for_ctx,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: RemoveUseCase,
        streams: Arc<FakeAuditStreamStore>,
        audit: Arc<FakeEventDispatcher>,
        id: AuditStreamId,
    }

    impl Setup {
        fn over(authorities: FakeTenantAuthorities) -> Self {
            let stream = test_audit_stream("SIEM", StreamFilter::everything());
            let id = *stream.id();
            let streams = Arc::new(FakeAuditStreamStore::holding(
                test_ctx().tenant_id(),
                [stream],
            ));
            Self {
                uc: RemoveUseCase::new(RemovePorts {
                    tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    stream_store: streams.clone(),
                    tenant_authorities: Arc::new(authorities),
                }),
                streams,
                audit: Arc::new(FakeEventDispatcher::new()),
                id,
            }
        }

        fn remove(&self, id: AuditStreamId) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(&test_ctx(), &test_auditor(self.audit.clone()), id),
            )
        }

        fn kept(&self) -> usize {
            self.streams.count(test_ctx().tenant_id())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann removes the stream to the SIEM Acme stopped using. It is gone,
    /// and the removal recorded.
    #[test]
    fn a_removed_stream_is_gone() {
        let setup = Setup::over(FakeTenantAuthorities::holding_everything());

        setup.remove(setup.id).unwrap();

        assert_eq!(setup.kept(), 0);
        assert_eq!(setup.recorded(), vec!["tenant.audit_stream_removed"]);
    }

    /// Ann names a stream Acme does not have. It is not found, and the one
    /// it has stays.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let setup = Setup::over(FakeTenantAuthorities::holding_everything());

        let result = setup.remove(AuditStreamId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.kept(), 1);
    }

    /// A caller without compliance rights cannot remove the stream.
    /// The stored stream stays and no removal is recorded.
    #[test]
    fn a_caller_without_the_compliance_right_is_refused() {
        let setup = Setup::over(FakeTenantAuthorities::holding(&[]));

        let result = setup.remove(setup.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.kept(), 1);
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out session cannot remove the stream, which stays stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::over(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.remove(setup.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.kept(), 1);
    }
}
