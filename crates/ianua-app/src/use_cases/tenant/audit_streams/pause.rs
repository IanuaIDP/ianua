//! Pause audit stream: stop sending a tenant's records to a SIEM for now.

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

/// The ports [`PauseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PausePorts {
    /// Tenants, for the one the stream belongs to.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Where the tenant's streams are kept.
    pub stream_store: Arc<dyn AuditStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Stops an audit stream sending until it is resumed.
pub struct PauseUseCase {
    ports: PausePorts,
}

impl PauseUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: PausePorts) -> Self {
        Self { ports }
    }
}

impl Command for PauseUseCase {
    type Caller = CallerContext;
    type Input = AuditStreamId;
    type Output = Result<(), AppError>;

    /// Stops the stream `stream_id` sending and records
    /// `tenant.audit_stream_paused`. Records written while it is paused are
    /// not sent later.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the tenant's
    ///   compliance settings.
    /// - `AppError::NotFound` when the tenant or the stream does not exist.
    /// - `AppError::Conflict` when the stream is already paused.
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
            .pause(&scope, TenantControl::new(&authority))
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
        uc: PauseUseCase,
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
                uc: PauseUseCase::new(PausePorts {
                    tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    stream_store: streams.clone(),
                    tenant_authorities: Arc::new(authorities),
                }),
                streams,
                audit: Arc::new(FakeEventDispatcher::new()),
                id,
            }
        }

        fn pause(&self, id: AuditStreamId) -> Result<(), AppError> {
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

    /// Ann pauses the stream while Acme moves its SIEM. It stops sending,
    /// and the pause is recorded.
    #[test]
    fn a_paused_stream_stops_sending() {
        let setup = Setup::over(
            StreamState::Active,
            FakeTenantAuthorities::holding_everything(),
        );

        setup.pause(setup.id).unwrap();

        assert!(!setup.is_sending());
        assert_eq!(setup.recorded(), vec!["tenant.audit_stream_paused"]);
    }

    /// The stream is already paused. Pausing it again is a conflict, and
    /// nothing is recorded.
    #[test]
    fn a_paused_stream_cannot_be_paused_again() {
        let paused = StreamState::Paused {
            reason: PauseReason::ByAdministrator,
            at: ianua_domain::shared::clock::now(),
        };
        let setup = Setup::over(paused, FakeTenantAuthorities::holding_everything());

        let result = setup.pause(setup.id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Ann names a stream Acme does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let setup = Setup::over(
            StreamState::Active,
            FakeTenantAuthorities::holding_everything(),
        );

        let result = setup.pause(AuditStreamId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without compliance rights cannot pause an active stream.
    /// It keeps sending and no pause is recorded.
    #[test]
    fn a_caller_without_the_compliance_right_is_refused() {
        let setup = Setup::over(StreamState::Active, FakeTenantAuthorities::holding(&[]));

        let result = setup.pause(setup.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.is_sending());
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out session cannot pause the stream, which keeps sending.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::over(
            StreamState::Active,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.pause(setup.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.is_sending());
    }
}
