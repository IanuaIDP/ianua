//! List subscriptions: retrieve subscriptions by topic or service.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::ConsumerId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::messaging::{SubscriptionSortField, SubscriptionStore};
use crate::use_case::Query;

/// Ports needed by the list subscriptions use case.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Port for subscription persistence.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a page of subscriptions selected by topic or service.
pub struct ListUseCase {
    ports: ListPorts,
}

/// Filter for listing subscriptions.
pub enum SubscriptionFilter {
    /// All subscriptions for a topic.
    ByTopic(TopicName),
    /// All subscriptions for a service.
    ByService(ConsumerId),
}

/// Which subscriptions to list, in what order, and which page of them.
pub struct ListRequest {
    /// Whose subscriptions: a topic's or a service's.
    pub filter: SubscriptionFilter,
    /// The field and direction to order by.
    pub sort: SortOrder<SubscriptionSortField>,
    /// Which page of the ordered subscriptions to return.
    pub page: PageRequest,
}

impl ListUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }

    /// Fetches the matching page from the store for the active filter.
    async fn fetch(
        &self,
        ctx: &CallerContext,
        request: &ListRequest,
    ) -> Result<Page<Subscription<ResolvedTenant>>, AppError> {
        let store = self.ports.subscription_store.as_ref();
        let page = &request.page;
        match &request.filter {
            SubscriptionFilter::ByTopic(name) => {
                store
                    .list_by_topic(&ctx.tenant(), name, &request.sort, page)
                    .await
            }
            SubscriptionFilter::ByService(id) => {
                store
                    .list_by_service(&ctx.tenant(), id, &request.sort, page)
                    .await
            }
        }
        .map_err(AppError::from_domain)
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Page<Subscription<ResolvedTenant>>, AppError>;

    /// Lists subscriptions matching the filter with ordering and pagination.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view messaging.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<Subscription<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Messaging(MessagingAction::View))
            .map_err(AppError::from_domain)?;
        self.fetch(ctx, &request).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{billing_sync, consumer_named};
    use crate::test_support::messaging::{FakeSubscriptionStore, subscription_of, topic_named};
    use crate::test_support::{block_on, test_ctx};

    fn request(filter: SubscriptionFilter) -> ListRequest {
        ListRequest {
            filter,
            sort: SortOrder::default(),
            page: PageRequest::default(),
        }
    }

    fn use_case_over(store: Arc<FakeSubscriptionStore>) -> ListUseCase {
        ListUseCase::new(ListPorts {
            subscription_store: store,
            ..ListPorts::fakes()
        })
    }

    /// "billing-sync" subscribes to `orders.created` and "cron-job" to
    /// `orders.shipped`. Listing by `orders.created` finds only the first.
    #[test]
    fn listing_by_topic_finds_that_topics_subscriptions() {
        let cron_job = consumer_named("cron-job", DataClassLevel::Internal);
        let store = FakeSubscriptionStore::of_test_tenant([
            subscription_of(&billing_sync(), &topic_named("orders.created")),
            subscription_of(&cron_job, &topic_named("orders.shipped")),
        ]);
        let by_topic = SubscriptionFilter::ByTopic(TopicName::new("orders.created").unwrap());

        let page = block_on(use_case_over(store).execute(&test_ctx(), request(by_topic))).unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].topic_name().as_str(), "orders.created");
    }

    /// "billing-sync" and "cron-job" each subscribe to a topic. Listing by
    /// "billing-sync" finds only its own.
    #[test]
    fn listing_by_service_finds_that_services_subscriptions() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let cron_job = consumer_named("cron-job", DataClassLevel::Internal);
        let store = FakeSubscriptionStore::of_test_tenant([
            subscription_of(&consumer, &topic_named("orders.created")),
            subscription_of(&cron_job, &topic_named("orders.shipped")),
        ]);

        let page = block_on(
            use_case_over(store).execute(&test_ctx(), request(SubscriptionFilter::ByService(id))),
        )
        .unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].consumer_id(), &id);
    }

    /// A topic nobody subscribes to lists no subscription.
    #[test]
    fn a_topic_without_subscriptions_lists_none() {
        let by_topic = SubscriptionFilter::ByTopic(TopicName::new("orders.created").unwrap());

        let page = block_on(
            use_case_over(Arc::new(FakeSubscriptionStore::empty()))
                .execute(&test_ctx(), request(by_topic)),
        )
        .unwrap();

        assert!(page.is_empty());
    }

    /// "billing-sync" subscribes to three topics. Ann lists them by topic
    /// name, last first.
    #[test]
    fn a_services_subscriptions_are_ordered_as_asked() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = FakeSubscriptionStore::of_test_tenant(
            ["a.one", "c.three", "b.two"]
                .map(|name| subscription_of(&consumer, &topic_named(name))),
        );
        let ordered = ListRequest {
            sort: SortOrder::single(Sort::descending(SubscriptionSortField::TopicName)),
            ..request(SubscriptionFilter::ByService(id))
        };

        let page = block_on(use_case_over(store).execute(&test_ctx(), ordered)).unwrap();

        let names: Vec<&str> = page.items.iter().map(|s| s.topic_name().as_str()).collect();
        assert_eq!(names, ["c.three", "b.two", "a.one"]);
    }

    /// Listing a topic's subscriptions without messaging view rights
    /// returns a forbidden error.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ListPorts::fakes()
        });
        let by_topic = SubscriptionFilter::ByTopic(TopicName::new("orders.created").unwrap());

        let result = block_on(use_case.execute(&test_ctx(), request(by_topic)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives an unauthenticated error when listing
    /// a topic's subscriptions.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ListPorts::fakes()
        });
        let by_topic = SubscriptionFilter::ByTopic(TopicName::new("orders.created").unwrap());

        let result = block_on(use_case.execute(&test_ctx(), request(by_topic)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
