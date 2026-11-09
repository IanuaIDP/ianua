//! Delete stream: permanently remove a disabled signal stream.

use std::sync::Arc;

use ianua_domain::domains::signals::control::SignalsControlCheck as _;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::SignalStreamId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::signals::SignalStreamStore;
use crate::use_case::Command;
use crate::use_cases::signals::lookup::existing_stream;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a disabled signal stream.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = SignalStreamId;
    type Output = Result<(), AppError>;

    /// Deletes the stream and records `signals.stream_deleted`. A stream
    /// that may still deliver is disabled first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change signal
    ///   streams.
    /// - `AppError::NotFound` when the tenant has no such stream.
    /// - `AppError::Conflict` unless the stream is disabled.
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
        stream.delete(&authority).map_err(AppError::from_domain)?;

        self.ports
            .stream_store
            .delete(&tenant, &stream_id)
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

    fn delete(
        store: &Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        id: SignalStreamId,
    ) -> Result<(), AppError> {
        let use_case = DeleteUseCase::new(DeletePorts {
            stream_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id))
    }

    /// Ann deletes a stream she disabled. It is gone and the deletion
    /// recorded.
    #[test]
    fn a_disabled_stream_is_deleted() {
        let (store, id) = seeded(StreamStatus::Disabled);
        let audit = Arc::new(FakeEventDispatcher::new());

        delete(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        )
        .unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["signals.stream_deleted"]
        );
    }

    /// Ann deletes a stream that is still active. It is refused as a
    /// conflict: she disables it first, so none is deleted while a receiver
    /// relies on it.
    #[test]
    fn an_active_stream_is_not_deleted() {
        let (store, id) = seeded(StreamStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(store.count(), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann deletes a paused stream. It is refused the same way: paused is
    /// not disabled.
    #[test]
    fn a_paused_stream_is_not_deleted() {
        let (store, id) = seeded(StreamStatus::Paused);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let store = Arc::new(FakeSignalStreamStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            SignalStreamId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Deleting an unknown stream without stream change rights returns
    /// forbidden rather than exposing its absence.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_stream() {
        let store = Arc::new(FakeSignalStreamStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            &store,
            FakeTenantAuthorities::holding(&[]),
            &audit,
            SignalStreamId::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Stream viewing rights do not permit deleting a disabled stream;
    /// the request is forbidden and the stream remains stored.
    #[test]
    fn a_caller_without_the_signals_right_is_refused() {
        let (store, id) = seeded(StreamStatus::Disabled);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            &store,
            FakeTenantAuthorities::holding(&[SystemPermission::Signals(SignalsAction::View)]),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
    }

    /// Deleting a stream with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded(StreamStatus::Disabled);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
