//! List stream deliveries: a page of one signal stream's delivery history.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
use ianua_domain::domains::signals::delivery::SignalDeliveryAttempt;
use ianua_domain::types::SignalStreamId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::signals::{SignalStreamStore, StreamDeliverySortField};
use crate::use_case::Query;
use crate::use_cases::signals::lookup::existing_stream;

/// Which stream's delivery history to list, in what order, and which page
/// of it.
pub struct ListStreamDeliveriesRequest {
    /// The stream whose delivery attempts to list.
    pub stream_id: SignalStreamId,
    /// The fields and directions to order by.
    pub sort: SortOrder<StreamDeliverySortField>,
    /// Which page of the ordered attempts to return.
    pub page: PageRequest,
}

/// The ports [`ListStreamDeliveriesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListStreamDeliveriesPorts {
    /// Where streams and their delivery attempts are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the delivery attempts of one of the tenant's signal streams.
pub struct ListStreamDeliveriesUseCase {
    ports: ListStreamDeliveriesPorts,
}

impl ListStreamDeliveriesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListStreamDeliveriesPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListStreamDeliveriesUseCase {
    type Caller = CallerContext;
    type Input = ListStreamDeliveriesRequest;
    type Output = Result<Page<SignalDeliveryAttempt>, AppError>;

    /// The page of the stream's delivery attempts `request` asks for.
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
        request: ListStreamDeliveriesRequest,
    ) -> Result<Page<SignalDeliveryAttempt>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Signals(SignalsAction::View))
            .map_err(AppError::from_domain)?;
        let ListStreamDeliveriesRequest {
            stream_id,
            sort,
            page,
        } = request;
        let tenant = caller.tenant();
        existing_stream(self.ports.stream_store.as_ref(), &tenant, &stream_id).await?;
        self.ports
            .stream_store
            .list_deliveries(&tenant, &stream_id, &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::signals::delivery::SignalDelivery;
    use ianua_domain::domains::signals::signal::SecuritySignalType;
    use ianua_domain::domains::signals::stream::{StreamStatus, StreamVerificationStatus};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{DeliveryOutcome, SignalDeliveryId, SignalId};

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::signals::{FakeSignalStreamStore, test_stream};
    use crate::test_support::{block_on, test_ctx};

    fn seeded() -> (Arc<FakeSignalStreamStore>, SignalStreamId) {
        let row = test_stream(StreamStatus::Active, StreamVerificationStatus::Verified);
        let id = row.id;
        let store = FakeSignalStreamStore::holding(test_ctx().tenant_id(), row);
        (Arc::new(store), id)
    }

    fn record(store: &FakeSignalStreamStore, stream_id: SignalStreamId, outcome: DeliveryOutcome) {
        let attempt = SignalDeliveryAttempt {
            id: SignalDeliveryId::new(),
            stream_id,
            signal_id: SignalId::new(),
            signal_type: SecuritySignalType::SessionRevoked,
            delivery: SignalDelivery::Pushed(outcome),
            duration_ms: 1,
            attempt_number: 0,
            attempted_at: clock::now(),
        };
        block_on(store.record_delivery(&test_ctx().tenant(), &attempt)).unwrap();
    }

    fn request(
        stream_id: SignalStreamId,
        sort: SortOrder<StreamDeliverySortField>,
    ) -> ListStreamDeliveriesRequest {
        ListStreamDeliveriesRequest {
            stream_id,
            sort,
            page: PageRequest::default(),
        }
    }

    fn list(
        store: Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
        request: ListStreamDeliveriesRequest,
    ) -> Result<Page<SignalDeliveryAttempt>, AppError> {
        let use_case = ListStreamDeliveriesUseCase::new(ListStreamDeliveriesPorts {
            stream_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), request))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Signals(SignalsAction::View)])
    }

    /// Ann opens the history of a stream nothing was sent to yet. It is
    /// empty.
    #[test]
    fn a_stream_without_deliveries_lists_none() {
        let (store, id) = seeded();

        let page = list(store, viewer(), request(id, SortOrder::default())).unwrap();

        assert!(page.is_empty());
    }

    /// Ann opens the history of a stream with one delivered and one failed
    /// push. Both are listed.
    #[test]
    fn recorded_attempts_are_listed() {
        let (store, id) = seeded();
        record(&store, id, DeliveryOutcome::Answered { code: 200 });
        record(&store, id, DeliveryOutcome::Answered { code: 500 });
        let sort = SortOrder::single(Sort::ascending(StreamDeliverySortField::Status));

        let page = list(store, viewer(), request(id, sort)).unwrap();

        assert_eq!(page.items.len(), 2);
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let result = list(
            Arc::new(FakeSignalStreamStore::empty()),
            viewer(),
            request(SignalStreamId::new(), SortOrder::default()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading stream delivery history without signal viewing rights returns forbidden.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let (store, id) = seeded();

        let result = list(
            store,
            FakeTenantAuthorities::holding(&[]),
            request(id, SortOrder::default()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading stream delivery history with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();

        let result = list(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            request(id, SortOrder::default()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
