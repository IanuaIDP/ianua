//! Get stream: read one signal stream.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
use ianua_domain::domains::signals::stream::SignalStream;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::SignalStreamId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::signals::SignalStreamStore;
use crate::use_case::Query;
use crate::use_cases::signals::lookup::existing_stream;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one of the tenant's signal streams.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = SignalStreamId;
    type Output = Result<SignalStream<ResolvedTenant>, AppError>;

    /// The tenant's stream `id`. It tells whether its endpoint is verified,
    /// never the challenge the endpoint was sent.
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
    ) -> Result<SignalStream<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Signals(SignalsAction::View))
            .map_err(AppError::from_domain)?;
        existing_stream(self.ports.stream_store.as_ref(), &caller.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::signals::stream::{StreamStatus, StreamVerificationStatus};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::signals::{FakeSignalStreamStore, test_stream};
    use crate::test_support::{block_on, test_ctx};

    fn seeded() -> (Arc<FakeSignalStreamStore>, SignalStreamId) {
        let row = test_stream(StreamStatus::Active, StreamVerificationStatus::Pending);
        let id = row.id;
        let store = FakeSignalStreamStore::holding(test_ctx().tenant_id(), row);
        (Arc::new(store), id)
    }

    fn get(
        store: Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
        id: SignalStreamId,
    ) -> Result<SignalStream<ResolvedTenant>, AppError> {
        let use_case = GetUseCase::new(GetPorts {
            stream_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), id))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Signals(SignalsAction::View)])
    }

    /// Ann may view the streams and opens the payroll app's. She sees it
    /// is still waiting on its endpoint.
    #[test]
    fn a_viewer_reads_a_stream() {
        let (store, id) = seeded();

        let stream = get(store, viewer(), id).unwrap();

        assert_eq!(stream.id(), &id);
        assert_eq!(stream.verification(), StreamVerificationStatus::Pending);
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let result = get(
            Arc::new(FakeSignalStreamStore::empty()),
            viewer(),
            SignalStreamId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading a stream without signal viewing rights returns forbidden.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let (store, id) = seeded();

        let result = get(store, FakeTenantAuthorities::holding(&[]), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading a stream with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();

        let result = get(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
