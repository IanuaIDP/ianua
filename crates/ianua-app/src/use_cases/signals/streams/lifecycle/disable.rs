//! Disable stream: switch a signal stream off for good.

use std::sync::Arc;

use ianua_domain::domains::signals::control::SignalsControlCheck as _;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::SignalStreamId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::signals::{SignalStreamStore, StreamChallenge};
use crate::use_case::Command;
use crate::use_cases::signals::lookup::existing_stream;

/// The ports [`DisableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DisablePorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Disables a signal stream.
pub struct DisableUseCase {
    ports: DisablePorts,
}

impl DisableUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DisablePorts) -> Self {
        Self { ports }
    }
}

impl Command for DisableUseCase {
    type Caller = CallerContext;
    type Input = SignalStreamId;
    type Output = Result<(), AppError>;

    /// Disables the stream and records `signals.stream_disabled`. The
    /// receiver gets nothing more through it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change signal
    ///   streams.
    /// - `AppError::NotFound` when the tenant has no such stream.
    /// - `AppError::Domain` when the stream is already disabled.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        stream_id: SignalStreamId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        authority
            .ensure_may_change_streams()
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut stream =
            existing_stream(self.ports.stream_store.as_ref(), &tenant, &stream_id).await?;
        stream.disable(&authority).map_err(AppError::from_domain)?;

        self.ports
            .stream_store
            .save(&tenant, &stream, StreamChallenge::Kept)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), stream.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
    use ianua_domain::domains::signals::stream::{StreamStatus, StreamVerificationStatus};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::signals::{FakeSignalStreamStore, test_stream};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded(status: StreamStatus) -> (Arc<FakeSignalStreamStore>, SignalStreamId) {
        let row = test_stream(status, StreamVerificationStatus::Verified);
        let id = row.id;
        let store = FakeSignalStreamStore::holding(test_ctx().tenant_id(), row);
        (Arc::new(store), id)
    }

    fn disable(
        store: &Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        id: SignalStreamId,
    ) -> Result<(), AppError> {
        let use_case = DisableUseCase::new(DisablePorts {
            stream_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id))
    }

    fn status_of(store: &FakeSignalStreamStore, id: &SignalStreamId) -> StreamStatus {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .status()
    }

    /// Ann retires the payroll app's stream. It is stored disabled and the
    /// change recorded.
    #[test]
    fn an_active_stream_is_disabled() {
        let (store, id) = seeded(StreamStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());

        disable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        )
        .unwrap();

        assert_eq!(status_of(&store, &id), StreamStatus::Disabled);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["signals.stream_disabled"]
        );
    }

    /// Ann disables a paused stream. It is disabled too.
    #[test]
    fn a_paused_stream_is_disabled() {
        let (store, id) = seeded(StreamStatus::Paused);
        let audit = Arc::new(FakeEventDispatcher::new());

        disable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        )
        .unwrap();

        assert_eq!(status_of(&store, &id), StreamStatus::Disabled);
    }

    /// Ann disables a stream that is already disabled. It is refused as a
    /// move the stream cannot make.
    #[test]
    fn a_disabled_stream_cannot_be_disabled_again() {
        let (store, id) = seeded(StreamStatus::Disabled);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = disable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let store = Arc::new(FakeSignalStreamStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = disable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            SignalStreamId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Disabling an unknown stream without stream change rights returns
    /// forbidden rather than exposing its absence.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_stream() {
        let store = Arc::new(FakeSignalStreamStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = disable(
            &store,
            FakeTenantAuthorities::holding(&[]),
            &audit,
            SignalStreamId::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Stream viewing rights do not permit disabling an active stream;
    /// the request is forbidden and the stream stays active.
    #[test]
    fn a_caller_without_the_signals_right_is_refused() {
        let (store, id) = seeded(StreamStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = disable(
            &store,
            FakeTenantAuthorities::holding(&[SystemPermission::Signals(SignalsAction::View)]),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&store, &id), StreamStatus::Active);
    }

    /// Disabling a stream with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded(StreamStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = disable(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
