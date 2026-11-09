//! List streams: a page of the tenant's signal streams.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
use ianua_domain::domains::signals::stream::{SignalStream, StreamStatus};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::signals::{SignalStreamStore, StreamSortField};
use crate::use_case::Query;

/// Which streams a listing keeps.
pub struct StreamFilter {
    /// Only streams in this status. `None` keeps every status.
    pub status: Option<StreamStatus>,
}

impl StreamFilter {
    /// Keeps every stream.
    #[must_use]
    pub fn all() -> Self {
        Self { status: None }
    }
}

/// Which streams to list, in what order, and which page of them.
pub struct ListRequest {
    /// Which streams to include.
    pub filter: StreamFilter,
    /// The fields and directions to order by.
    pub sort: SortOrder<StreamSortField>,
    /// Which page of the ordered streams to return.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's signal streams, filtered, ordered and paged.
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
    type Input = ListRequest;
    type Output = Result<Page<SignalStream<ResolvedTenant>>, AppError>;

    /// The page of streams `request` asks for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view signal streams.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<SignalStream<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Signals(SignalsAction::View))
            .map_err(AppError::from_domain)?;
        let ListRequest { filter, sort, page } = request;
        self.ports
            .stream_store
            .list_all(&caller.tenant(), filter.status, &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::signals::stream::StreamVerificationStatus;
    use ianua_domain::types::PublicHttpsUrl;

    use super::*;
    use crate::listing::Sort;
    use crate::ports::signals::StreamChallenge;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::signals::{FakeSignalStreamStore, test_stream};
    use crate::test_support::{block_on, test_ctx};

    fn store_with(streams: &[(&str, StreamStatus)]) -> Arc<FakeSignalStreamStore> {
        let store = Arc::new(FakeSignalStreamStore::empty());
        for (endpoint, status) in streams {
            let mut row = test_stream(*status, StreamVerificationStatus::Verified);
            row.endpoint = PublicHttpsUrl::new(*endpoint).unwrap();
            let stream = SignalStream::reconstitute(row).unwrap();
            block_on(store.save(&test_ctx().tenant(), &stream, StreamChallenge::Kept)).unwrap();
        }
        store
    }

    fn request(filter: StreamFilter, sort: SortOrder<StreamSortField>) -> ListRequest {
        ListRequest {
            filter,
            sort,
            page: PageRequest::default(),
        }
    }

    fn list(
        store: Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
        request: ListRequest,
    ) -> Result<Page<SignalStream<ResolvedTenant>>, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            stream_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), request))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Signals(SignalsAction::View)])
    }

    /// Ann lists the tenant's streams. She sees all three.
    #[test]
    fn every_stream_is_listed() {
        let active = StreamStatus::Active;
        let store = store_with(&[
            ("https://a.acme.com/sse", active),
            ("https://b.acme.com/sse", active),
            ("https://c.acme.com/sse", active),
        ]);

        let page = list(
            store,
            viewer(),
            request(StreamFilter::all(), SortOrder::default()),
        )
        .unwrap();

        assert_eq!(page.items.len(), 3);
    }

    /// Ann lists only the active streams. The paused one is left out.
    #[test]
    fn streams_are_filtered_by_status() {
        let store = store_with(&[
            ("https://a.acme.com/sse", StreamStatus::Active),
            ("https://b.acme.com/sse", StreamStatus::Paused),
        ]);
        let filter = StreamFilter {
            status: Some(StreamStatus::Active),
        };

        let page = list(store, viewer(), request(filter, SortOrder::default())).unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// Ann orders the streams by endpoint. They come back in that order.
    #[test]
    fn streams_are_ordered_by_endpoint_when_asked() {
        let active = StreamStatus::Active;
        let store = store_with(&[
            ("https://c.acme.com/sse", active),
            ("https://a.acme.com/sse", active),
            ("https://b.acme.com/sse", active),
        ]);
        let sort = SortOrder::single(Sort::ascending(StreamSortField::Endpoint));

        let page = list(store, viewer(), request(StreamFilter::all(), sort)).unwrap();

        let endpoints: Vec<&str> = page.items.iter().map(|s| s.endpoint().as_str()).collect();
        assert_eq!(
            endpoints,
            [
                "https://a.acme.com/sse",
                "https://b.acme.com/sse",
                "https://c.acme.com/sse",
            ]
        );
    }

    /// A tenant with no streams lists an empty page.
    #[test]
    fn a_tenant_without_streams_lists_none() {
        let page = list(
            store_with(&[]),
            viewer(),
            request(StreamFilter::all(), SortOrder::default()),
        )
        .unwrap();

        assert!(page.is_empty());
    }

    /// Listing streams without signal viewing rights returns forbidden.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = list(
            store_with(&[]),
            FakeTenantAuthorities::holding(&[]),
            request(StreamFilter::all(), SortOrder::default()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Listing streams with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(
            store_with(&[]),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            request(StreamFilter::all(), SortOrder::default()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
