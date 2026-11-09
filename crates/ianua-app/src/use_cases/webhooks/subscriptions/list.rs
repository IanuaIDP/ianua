//! List subscriptions: a page of the tenant's webhook subscriptions.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, WebhooksAction};
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::webhooks::{WebhookStore, WebhookSubscriptionSortField};
use crate::use_case::Query;

/// Which subscriptions a listing keeps.
pub struct SubscriptionFilter {
    /// Only subscriptions in this status. `None` keeps every status.
    pub status: Option<WebhookSubscriptionStatus>,
}

impl SubscriptionFilter {
    /// Keeps every subscription.
    #[must_use]
    pub fn all() -> Self {
        Self { status: None }
    }
}

/// Which subscriptions to list, in what order and which page of them.
pub struct ListRequest {
    /// Which subscriptions qualify.
    pub filter: SubscriptionFilter,
    /// The field and direction to order by.
    pub sort: SortOrder<WebhookSubscriptionSortField>,
    /// Which page of the ordered subscriptions to return.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Where subscriptions are kept.
    pub webhook_store: Arc<dyn WebhookStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's webhook subscriptions, filtered, ordered and paged.
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
    type Output = Result<Page<WebhookSubscription<ResolvedTenant>>, AppError>;

    /// The page of subscriptions `request` asks for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view webhooks.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<WebhookSubscription<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Webhooks(WebhooksAction::View))
            .map_err(AppError::from_domain)?;
        let ListRequest { filter, sort, page } = request;
        self.ports
            .webhook_store
            .list_all(&caller.tenant(), filter.status, &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::webhooks::{FakeWebhookStore, test_subscription};
    use crate::test_support::{block_on, test_ctx};

    fn use_case(store: Arc<FakeWebhookStore>, authorities: FakeTenantAuthorities) -> ListUseCase {
        ListUseCase::new(ListPorts {
            webhook_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::View)])
    }

    fn request(
        filter: SubscriptionFilter,
        sort: SortOrder<WebhookSubscriptionSortField>,
    ) -> ListRequest {
        ListRequest {
            filter,
            sort,
            page: PageRequest::default(),
        }
    }

    fn store_with(subscriptions: &[(&str, WebhookSubscriptionStatus)]) -> Arc<FakeWebhookStore> {
        let store = Arc::new(FakeWebhookStore::empty());
        for (url, status) in subscriptions {
            let subscription = test_subscription(url, *status);
            block_on(store.save(&test_ctx().tenant(), &subscription)).unwrap();
        }
        store
    }

    fn list(
        store: Arc<FakeWebhookStore>,
        request: ListRequest,
    ) -> Result<Page<WebhookSubscription<ResolvedTenant>>, AppError> {
        block_on(use_case(store, viewer()).execute(&test_ctx(), request))
    }

    /// Ann lists the tenant's webhooks. She sees all three.
    #[test]
    fn every_subscription_is_listed() {
        let active = WebhookSubscriptionStatus::Active;
        let store = store_with(&[
            ("https://hooks.acme.com/a", active),
            ("https://hooks.acme.com/b", active),
            ("https://hooks.acme.com/c", active),
        ]);

        let page = list(
            store,
            request(SubscriptionFilter::all(), SortOrder::default()),
        )
        .unwrap();

        assert_eq!(page.items.len(), 3);
    }

    /// Ann orders the webhooks by URL. The order she asks for wins over the
    /// default newest first.
    #[test]
    fn subscriptions_are_ordered_by_url_when_asked() {
        let active = WebhookSubscriptionStatus::Active;
        let store = store_with(&[
            ("https://hooks.acme.com/b", active),
            ("https://hooks.acme.com/a", active),
        ]);
        let order = SortOrder::single(Sort::ascending(WebhookSubscriptionSortField::Url));

        let page = list(store, request(SubscriptionFilter::all(), order)).unwrap();

        assert_eq!(page.items[0].url().as_str(), "https://hooks.acme.com/a");
        assert_eq!(page.items[1].url().as_str(), "https://hooks.acme.com/b");
    }

    /// Ann lists only the active webhooks. The paused one is left out.
    #[test]
    fn subscriptions_are_filtered_by_status() {
        let store = store_with(&[
            (
                "https://hooks.acme.com/a",
                WebhookSubscriptionStatus::Active,
            ),
            (
                "https://hooks.acme.com/b",
                WebhookSubscriptionStatus::Paused,
            ),
        ]);
        let filter = SubscriptionFilter {
            status: Some(WebhookSubscriptionStatus::Active),
        };

        let page = list(store, request(filter, SortOrder::default())).unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// A tenant with no webhooks lists an empty page.
    #[test]
    fn a_tenant_without_subscriptions_lists_none() {
        let page = list(
            store_with(&[]),
            request(SubscriptionFilter::all(), SortOrder::default()),
        )
        .unwrap();

        assert!(page.is_empty());
    }

    /// Listing subscriptions without webhook viewing rights returns forbidden.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = block_on(
            use_case(store_with(&[]), FakeTenantAuthorities::holding(&[])).execute(
                &test_ctx(),
                request(SubscriptionFilter::all(), SortOrder::default()),
            ),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Listing subscriptions with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = block_on(
            use_case(
                store_with(&[]),
                FakeTenantAuthorities::refusing(Refusal::SignedOut),
            )
            .execute(
                &test_ctx(),
                request(SubscriptionFilter::all(), SortOrder::default()),
            ),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
