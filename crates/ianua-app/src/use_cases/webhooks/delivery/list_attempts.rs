//! List delivery attempts: a page of one webhook subscription's delivery
//! history.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, WebhooksAction};
use ianua_domain::domains::webhooks::delivery::DeliveryAttempt;
use ianua_domain::types::WebhookSubscriptionId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::webhooks::{DeliveryAttemptSortField, WebhookStore};
use crate::use_case::Query;
use crate::use_cases::webhooks::lookup::existing_subscription;

/// The ports [`ListAttemptsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListAttemptsPorts {
    /// Where subscriptions and their delivery attempts are kept.
    pub webhook_store: Arc<dyn WebhookStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which subscription's delivery history to list, in what order and which
/// page of it.
pub struct ListAttemptsRequest {
    /// The subscription whose attempts to list.
    pub subscription_id: WebhookSubscriptionId,
    /// The field and direction to order by.
    pub sort: SortOrder<DeliveryAttemptSortField>,
    /// Which page of the ordered attempts to return.
    pub page: PageRequest,
}

/// Lists the delivery attempts of one of the tenant's webhook subscriptions.
pub struct ListAttemptsUseCase {
    ports: ListAttemptsPorts,
}

impl ListAttemptsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListAttemptsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListAttemptsUseCase {
    type Caller = CallerContext;
    type Input = ListAttemptsRequest;
    type Output = Result<Page<DeliveryAttempt>, AppError>;

    /// The page of the subscription's delivery attempts `request` asks for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view webhooks.
    /// - `AppError::NotFound` when the tenant has no such subscription.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        request: ListAttemptsRequest,
    ) -> Result<Page<DeliveryAttempt>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Webhooks(WebhooksAction::View))
            .map_err(AppError::from_domain)?;
        let ListAttemptsRequest {
            subscription_id,
            sort,
            page,
        } = request;
        let tenant = caller.tenant();
        existing_subscription(self.ports.webhook_store.as_ref(), &tenant, &subscription_id).await?;
        self.ports
            .webhook_store
            .list_delivery_attempts(&tenant, &subscription_id, &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::webhooks::retry_policy::WebhookRetryPolicy;
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::event_type::IdentityEvent;
    use ianua_domain::types::{DeliveryOutcome, WebhookDeliveryId, WebhookMessageId};

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::webhooks::{FakeWebhookStore, test_subscription};
    use crate::test_support::{block_on, test_ctx};

    fn seeded() -> (Arc<FakeWebhookStore>, WebhookSubscriptionId) {
        let subscription = test_subscription(
            "https://hooks.acme.com/events",
            WebhookSubscriptionStatus::Active,
        );
        let store = FakeWebhookStore::holding(test_ctx().tenant_id(), &subscription);
        (Arc::new(store), *subscription.id())
    }

    fn record_attempt(
        store: &FakeWebhookStore,
        subscription_id: WebhookSubscriptionId,
        attempt_number: u8,
    ) {
        let attempt = DeliveryAttempt {
            id: WebhookDeliveryId::new(),
            message_id: WebhookMessageId::new(),
            subscription_id,
            event_type: IdentityEvent::UserRegistered.into(),
            outcome: DeliveryOutcome::Answered { code: 200 },
            duration_ms: 1,
            attempt_number,
            attempted_at: clock::now(),
        };
        let limit = WebhookRetryPolicy::standard().disable_after_failures();
        block_on(store.record_delivery(&test_ctx().tenant(), &attempt, limit)).unwrap();
    }

    fn use_case(
        store: Arc<FakeWebhookStore>,
        authorities: FakeTenantAuthorities,
    ) -> ListAttemptsUseCase {
        ListAttemptsUseCase::new(ListAttemptsPorts {
            webhook_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::View)])
    }

    fn request(
        subscription_id: WebhookSubscriptionId,
        sort: SortOrder<DeliveryAttemptSortField>,
    ) -> ListAttemptsRequest {
        ListAttemptsRequest {
            subscription_id,
            sort,
            page: PageRequest::default(),
        }
    }

    /// Ann opens the history of a webhook nothing was sent to yet. It is
    /// empty.
    #[test]
    fn a_subscription_without_deliveries_lists_none() {
        let (store, id) = seeded();

        let page = block_on(
            use_case(store, viewer()).execute(&test_ctx(), request(id, SortOrder::default())),
        )
        .unwrap();

        assert!(page.is_empty());
    }

    /// Ann names a subscription the tenant does not have. It is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let result = block_on(
            use_case(Arc::new(FakeWebhookStore::empty()), viewer()).execute(
                &test_ctx(),
                request(WebhookSubscriptionId::new(), SortOrder::default()),
            ),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann orders a webhook's three attempts by their number. The first try
    /// comes first and the last try last.
    #[test]
    fn attempts_are_ordered_by_number_when_asked() {
        let (store, id) = seeded();
        record_attempt(&store, id, 2);
        record_attempt(&store, id, 0);
        record_attempt(&store, id, 1);
        let sort = SortOrder::single(Sort::ascending(DeliveryAttemptSortField::AttemptNumber));

        let page =
            block_on(use_case(store, viewer()).execute(&test_ctx(), request(id, sort))).unwrap();

        assert_eq!(page.items.len(), 3);
        assert_eq!(page.items[0].attempt_number, 0);
        assert_eq!(page.items[2].attempt_number, 2);
    }

    /// Reading delivery history without webhook viewing rights returns forbidden.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let (store, id) = seeded();

        let result = block_on(
            use_case(store, FakeTenantAuthorities::holding(&[]))
                .execute(&test_ctx(), request(id, SortOrder::default())),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading delivery history with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();

        let result = block_on(
            use_case(store, FakeTenantAuthorities::refusing(Refusal::SignedOut))
                .execute(&test_ctx(), request(id, SortOrder::default())),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
