//! Get stream status: whether a signal stream is delivering, paused or
//! disabled, as a Shared Signals receiver reads it from `/status`.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
use ianua_domain::domains::signals::stream::StreamStatus;
use ianua_domain::types::SignalStreamId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::signals::SignalStreamStore;
use crate::use_case::Query;
use crate::use_cases::signals::lookup::existing_stream;

/// The ports [`GetStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetStatusPorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one of the tenant's signal streams' status.
pub struct GetStatusUseCase {
    ports: GetStatusPorts,
}

impl GetStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetStatusPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetStatusUseCase {
    type Caller = CallerContext;
    type Input = SignalStreamId;
    type Output = Result<StreamStatus, AppError>;

    /// The status of the tenant's stream `id`. A receiver changes it
    /// through the pause, resume and disable use cases.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view signal streams.
    /// - `AppError::NotFound` when the tenant has no such stream.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        id: SignalStreamId,
    ) -> Result<StreamStatus, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Signals(SignalsAction::View))
            .map_err(AppError::from_domain)?;
        let stream =
            existing_stream(self.ports.stream_store.as_ref(), &caller.tenant(), &id).await?;
        Ok(stream.status())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::signals::stream::StreamVerificationStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::signals::{FakeSignalStreamStore, test_stream};
    use crate::test_support::{block_on, test_ctx};

    /// The tenant's paused stream, and its id.
    fn seeded() -> (Arc<FakeSignalStreamStore>, SignalStreamId) {
        let row = test_stream(StreamStatus::Paused, StreamVerificationStatus::Verified);
        let id = row.id;
        let store = FakeSignalStreamStore::holding(test_ctx().tenant_id(), row);
        (Arc::new(store), id)
    }

    /// Reads `id`'s status for a caller holding `authorities`.
    fn status(
        store: Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
        id: SignalStreamId,
    ) -> Result<StreamStatus, AppError> {
        let use_case = GetStatusUseCase::new(GetStatusPorts {
            stream_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), id))
    }

    /// The payroll app reads its paused stream's status. It is told the
    /// stream is paused.
    #[test]
    fn a_viewer_reads_the_status() {
        let (store, id) = seeded();

        let result = status(
            store,
            FakeTenantAuthorities::holding(&[SystemPermission::Signals(SignalsAction::View)]),
            id,
        );

        assert_eq!(result.unwrap(), StreamStatus::Paused);
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let (store, _) = seeded();

        let result = status(
            store,
            FakeTenantAuthorities::holding_everything(),
            SignalStreamId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading a stream's status without signal viewing rights returns forbidden.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let (store, id) = seeded();

        let result = status(store, FakeTenantAuthorities::holding(&[]), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading a stream's status with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();

        let result = status(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
