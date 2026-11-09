//! List topics: retrieve all topics for a tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::messaging::{TopicSortField, TopicStore};
use crate::use_case::Query;

/// The order and page of topics to list.
pub struct ListRequest {
    /// The field and direction to order by.
    pub sort: SortOrder<TopicSortField>,
    /// Which page of the ordered topics to return.
    pub page: PageRequest,
}

/// Ports needed by the list topics use case.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Port for topic persistence.
    pub topic_store: Arc<dyn TopicStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a sorted page of message destinations in the caller's tenant.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Page<Topic<ResolvedTenant>>, AppError>;

    /// Lists topics for the tenant with ordering and pagination.
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
    ) -> Result<Page<Topic<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Messaging(MessagingAction::View))
            .map_err(AppError::from_domain)?;
        let ListRequest { sort, page } = request;
        self.ports
            .topic_store
            .list_all(&ctx.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{FakeTopicStore, topic_named};
    use crate::test_support::{block_on, test_ctx};

    fn request(sort: SortOrder<TopicSortField>) -> ListRequest {
        ListRequest {
            sort,
            page: PageRequest::default(),
        }
    }

    fn three_topics() -> Arc<FakeTopicStore> {
        let store = Arc::new(FakeTopicStore::empty());
        for i in 0..3 {
            block_on(store.save(&test_ctx().tenant(), &topic_named(&format!("topic.{i}"))))
                .unwrap();
        }
        store
    }

    fn use_case_over(store: Arc<FakeTopicStore>) -> ListUseCase {
        ListUseCase::new(ListPorts {
            topic_store: store,
            ..ListPorts::fakes()
        })
    }

    /// Acme has three topics. Ann lists them and sees all three.
    #[test]
    fn every_topic_of_the_tenant_is_listed() {
        let use_case = use_case_over(three_topics());

        let page = block_on(use_case.execute(&test_ctx(), request(SortOrder::default()))).unwrap();

        assert_eq!(page.items.len(), 3);
    }

    /// A tenant without topics lists none.
    #[test]
    fn a_tenant_without_topics_lists_none() {
        let use_case = use_case_over(Arc::new(FakeTopicStore::empty()));

        let page = block_on(use_case.execute(&test_ctx(), request(SortOrder::default()))).unwrap();

        assert!(page.is_empty());
    }

    /// Ann lists the topics by name, last first.
    #[test]
    fn topics_are_ordered_as_asked() {
        let use_case = use_case_over(three_topics());
        let sort = SortOrder::single(Sort::descending(TopicSortField::TopicName));

        let page = block_on(use_case.execute(&test_ctx(), request(sort))).unwrap();

        let names: Vec<&str> = page.items.iter().map(|t| t.topic_name().as_str()).collect();
        assert_eq!(names, ["topic.2", "topic.1", "topic.0"]);
    }

    /// Listing a tenant's topics without messaging view rights returns a
    /// forbidden error.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            topic_store: three_topics(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ListPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives an unauthenticated error when listing topics.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            topic_store: three_topics(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ListPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
