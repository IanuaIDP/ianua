//! Bounded holder snapshots, visible to the same readers as their review.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_review::ReviewItem;
use ianua_domain::types::AccessReviewId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::authorization::AccessReviewStore;
use crate::use_case::Query;
use crate::use_cases::authorization::access_reviews::lookup::{
    ReviewReader, SEES_REVIEWS, owned_review,
};

/// The review and immutable snapshot position to continue reading.
pub struct ItemsRequest {
    /// The review whose holders the caller wants to read.
    pub id: AccessReviewId,
    /// The bounded page and optional continuation cursor.
    pub page: PageRequest,
}

/// The ports used to authorize and read a holder page.
#[derive(ianua_macros::Fakes)]
pub struct ItemsPorts {
    /// Reads the header and its independently paged holders.
    pub review_store: Arc<dyn AccessReviewStore>,
    /// Resolves the caller's current authority in the tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads holders only after the caller may read their owning review.
pub struct ItemsUseCase {
    ports: ItemsPorts,
}

impl ItemsUseCase {
    /// Builds the query over its authorization and snapshot ports.
    #[must_use]
    pub fn new(ports: ItemsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ItemsUseCase {
    type Caller = CallerContext;
    type Input = ItemsRequest;
    type Output = Result<Page<ReviewItem>, AppError>;

    /// Returns one page in immutable snapshot order.
    ///
    /// # Errors
    ///
    /// Refuses expired authority, hides absent or unreadable reviews, rejects
    /// invalid cursors and preserves storage failures.
    async fn execute(&self, ctx: &CallerContext, request: ItemsRequest) -> Self::Output {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let tenant = ctx.tenant();
        let review = owned_review(
            self.ports.review_store.as_ref(),
            &tenant,
            &request.id,
            ReviewReader {
                authority: &authority,
                besides: SEES_REVIEWS,
            },
        )
        .await?;
        self.ports
            .review_store
            .list_items(&tenant, &review, &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_review::ReviewScope;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{PrincipalRef, RoleId, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authorization::{FakeAccessReviewStore, open_review_of};
    use crate::test_support::{block_on, test_ctx};

    /// A separate twenty-one-row holder snapshot with an authorized reviewer.
    fn fixture() -> (ItemsPorts, Arc<FakeAccessReviewStore>, AccessReviewId) {
        let ctx = test_ctx();
        let holders: Vec<_> = (0..21).map(|_| PrincipalRef::User(UserId::new())).collect();
        let review = open_review_of(
            ReviewScope::Role(RoleId::new()),
            &holders,
            "caller@example.test",
            clock::now() + Duration::days(7),
        );
        let id = *review.id();
        let store = Arc::new(FakeAccessReviewStore::holding(ctx.tenant_id(), [review]));
        store.seed_items(
            ctx.tenant_id(),
            &store.stored(ctx.tenant_id(), &id).unwrap(),
            &holders,
        );
        let ports = ItemsPorts {
            review_store: store.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
        };
        (ports, store, id)
    }

    /// The default page materializes twenty holders rather than the entire
    /// snapshot and supplies a continuation for the remaining holder.
    #[test]
    fn holder_reads_are_bounded_by_the_requested_page() {
        let (ports, store, id) = fixture();
        let page = block_on(ItemsUseCase::new(ports).execute(
            &test_ctx(),
            ItemsRequest {
                id,
                page: PageRequest::default(),
            },
        ))
        .unwrap();
        assert_eq!(page.items.len(), 20);
        assert_eq!(page.items[0].position(), 1);
        assert_eq!(page.items[19].position(), 20);
        assert_eq!(store.item_batch_sizes(), vec![20]);
    }

    /// A failed review-header read returns a storage error without loading
    /// holder rows.
    #[test]
    fn a_header_read_failure_stops_before_holder_loading() {
        let (ports, store, id) = fixture();
        store.fail_reading(id);
        let result = block_on(ItemsUseCase::new(ports).execute(
            &test_ctx(),
            ItemsRequest {
                id,
                page: PageRequest::default(),
            },
        ));
        assert!(matches!(result, Err(AppError::Internal(_))));
        assert!(store.item_batch_sizes().is_empty());
    }
}
