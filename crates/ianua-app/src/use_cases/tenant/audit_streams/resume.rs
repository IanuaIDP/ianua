//! Resume audit stream: send a tenant's records to its SIEM again, after an
//! administrator paused the stream or failures paused it on its own.

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

/// The ports [`ResumeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResumePorts {
    /// Tenants, for the one the stream belongs to.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Where the tenant's streams are kept.
    pub stream_store: Arc<dyn AuditStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Starts a paused audit stream sending again.
pub struct ResumeUseCase {
    ports: ResumePorts,
}

impl ResumeUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ResumePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResumeUseCase {
    type Caller = CallerContext;
    type Input = AuditStreamId;
    type Output = Result<(), AppError>;

    /// Starts the stream `stream_id` sending again and records
    /// `tenant.audit_stream_resumed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the tenant's
    ///   compliance settings.
    /// - `AppError::NotFound` when the tenant or the stream does not exist.
    /// - `AppError::Conflict` when the stream is not paused.
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
            .resume(&scope, TenantControl::new(&authority))
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &stream).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), stream.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::streaming::StreamFilter;
    use ianua_domain::domains::tenant::audit_streams::{PauseReason, StreamState};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::tenant::{
        FakeAuditStreamStore, FakeTenantStore, audit_stream_in_state, test_tenant_for_ctx,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: ResumeUseCase,
        streams: Arc<FakeAuditStreamStore>,
        audit: Arc<FakeEventDispatcher>,
        id: AuditStreamId,
    }

    impl Setup {
        fn over(state: StreamState, authorities: FakeTenantAuthorities) -> Self {
            let stream = audit_stream_in_state("SIEM", StreamFilter::everything(), state);
            let id = *stream.id();
            let streams = Arc::new(FakeAuditStreamStore::holding(
                test_ctx().tenant_id(),
                [stream],
            ));
            Self {
                uc: ResumeUseCase::new(ResumePorts {
                    tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    stream_store: streams.clone(),
                    tenant_authorities: Arc::new(authorities),
                }),
                streams,
                audit: Arc::new(FakeEventDispatcher::new()),
                id,
            }
        }

        fn paused(authorities: FakeTenantAuthorities) -> Self {
            let paused = StreamState::Paused {
                reason: PauseReason::AfterFailures,
                at: ianua_domain::shared::clock::now(),
            };
            Self::over(paused, authorities)
        }

        fn resume(&self, id: AuditStreamId) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(&test_ctx(), &test_auditor(self.audit.clone()), id),
            )
        }

        fn is_sending(&self) -> bool {
            self.streams
                .stored(test_ctx().tenant_id(), &self.id)
                .unwrap()
                .is_sending()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Acme's collector refused records until the stream paused itself.
    /// Ann fixed the collector and resumes the stream. It sends again, and
    /// the resume is recorded.
    #[test]
    fn a_resumed_stream_sends_again() {
        let setup = Setup::paused(FakeTenantAuthorities::holding_everything());

        setup.resume(setup.id).unwrap();

        assert!(setup.is_sending());
        assert_eq!(setup.recorded(), vec!["tenant.audit_stream_resumed"]);
    }

    /// The stream is sending already. Resuming it is a conflict, and
    /// nothing is recorded.
    #[test]
    fn a_sending_stream_cannot_be_resumed() {
        let setup = Setup::over(
            StreamState::Active,
            FakeTenantAuthorities::holding_everything(),
        );

        let result = setup.resume(setup.id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Ann names a stream Acme does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let setup = Setup::paused(FakeTenantAuthorities::holding_everything());

        let result = setup.resume(AuditStreamId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without compliance rights cannot resume a stream paused after
    /// delivery failures. It stays paused and no resume is recorded.
    #[test]
    fn a_caller_without_the_compliance_right_is_refused() {
        let setup = Setup::paused(FakeTenantAuthorities::holding(&[]));

        let result = setup.resume(setup.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!setup.is_sending());
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out session cannot resume the stream, which stays paused.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::paused(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.resume(setup.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(!setup.is_sending());
    }
}
