//! Delete topic: remove a topic and all its subscriptions.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::control::MessagingControl;
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::TopicId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::messaging::{MessageConsumer, SubscriptionStore, TopicStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::messaging::bus::close_consumer;
use crate::use_cases::messaging::lookup::existing_topic;

/// How many subscriptions are read at a time while gathering a topic's.
const SUBSCRIPTION_PAGE: u32 = 500;

/// Ports needed by the delete topic use case.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Port for topic persistence.
    pub topic_store: Arc<dyn TopicStore>,
    /// Port for subscription persistence (cascading delete).
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// The bus consumers the subscriptions read through.
    pub message_consumer: Arc<dyn MessageConsumer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a message destination and all services subscribed to it.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }

    /// Every subscription to `topic`, read page by page.
    async fn subscriptions_to(
        &self,
        tenant: &ScopedTenant,
        topic: &Topic<ResolvedTenant>,
    ) -> Result<Vec<Subscription<ResolvedTenant>>, AppError> {
        let sort = SortOrder::default();
        let mut gathered = Vec::new();
        let mut next = Some(PageRequest::first(Limit::internal(SUBSCRIPTION_PAGE)));
        while let Some(asked) = next.take() {
            let found = self
                .ports
                .subscription_store
                .list_by_topic(tenant, topic.topic_name(), &sort, &asked)
                .await
                .or_internal()?;
            next = asked.following(&found);
            gathered.extend(found.items);
        }
        Ok(gathered)
    }

    /// Deletes every one of `subscriptions`, with the bus consumer it reads
    /// through.
    async fn remove_subscriptions(
        &self,
        tenant: &ScopedTenant,
        subscriptions: &[Subscription<ResolvedTenant>],
    ) -> Result<(), AppError> {
        for subscription in subscriptions {
            close_consumer(
                self.ports.message_consumer.as_ref(),
                self.ports.subscription_store.as_ref(),
                tenant,
                subscription,
            )
            .await?;
            self.ports
                .subscription_store
                .delete(tenant, subscription.id())
                .await
                .or_internal()?;
        }
        Ok(())
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = TopicId;
    type Output = Result<(), AppError>;

    /// Deletes a topic, every subscription to it and the bus consumers they
    /// read through. Records `messaging.topic_deleted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the topic doesn't exist.
    /// - `AppError::Forbidden` when the caller may not delete in messaging.
    /// - `AppError::Conflict` while the topic is still active (pause or
    ///   archive it first).
    /// - `AppError::Internal` on persistence, bus or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        topic_id: TopicId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = MessagingControl::new(&authority);
        control
            .ensure_may(MessagingAction::Delete)
            .map_err(AppError::from_domain)?;
        let mut topic = existing_topic(self.ports.topic_store.as_ref(), &tenant, &topic_id).await?;
        topic.delete(&control).map_err(AppError::from_domain)?;
        let subscriptions = self.subscriptions_to(&tenant, &topic).await?;
        self.remove_subscriptions(&tenant, &subscriptions).await?;

        self.ports
            .topic_store
            .delete(&tenant, &topic_id)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), topic.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{
        FakeMessageConsumer, FakeSubscriptionStore, FakeTopicStore, archived_topic,
        enrolled_subscription, paused_topic, topic_named, topics_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::messaging::bus::consumer_name;

    fn run(
        use_case: &DeleteUseCase,
        topic_id: TopicId,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result =
            block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), topic_id));
        (result, audit)
    }

    fn holding(store: Arc<FakeTopicStore>, authorities: FakeTenantAuthorities) -> DeleteUseCase {
        DeleteUseCase::new(DeletePorts {
            topic_store: store,
            tenant_authorities: Arc::new(authorities),
            ..DeletePorts::fakes()
        })
    }

    /// Ann deletes `old.topic`, which she archived. It is gone, and that is
    /// on record.
    #[test]
    fn an_archived_topic_is_deleted_and_recorded() {
        let topic = archived_topic("old.topic");
        let id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let use_case = holding(store.clone(), FakeTenantAuthorities::holding_everything());

        let (result, audit) = run(&use_case, id);

        result.unwrap();
        assert_eq!(store.count(), 0);
        assert_eq!(audit.records.lock().unwrap()[0], "messaging.topic_deleted");
    }

    /// Ann paused `orders.v1` once nothing published to it any more. Now
    /// that topics can be paused, she deletes it, and it is gone.
    #[test]
    fn a_paused_topic_is_deleted() {
        let topic = paused_topic("orders.v1");
        let id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let use_case = holding(store.clone(), FakeTenantAuthorities::holding_everything());

        let (result, _) = run(&use_case, id);

        result.unwrap();
        assert_eq!(store.count(), 0);
    }

    /// Two services subscribe to `old.topic`. Deleting it removes both
    /// subscriptions and the bus consumers they read through.
    #[test]
    fn deleting_a_topic_removes_its_subscriptions_and_their_bus_consumers() {
        let topic = archived_topic("old.topic");
        let id = *topic.id();
        let tenant = test_ctx().tenant();
        let subscriptions = Arc::new(FakeSubscriptionStore::empty());
        let bus = Arc::new(FakeMessageConsumer::empty());
        for _ in 0..2 {
            let subscription = enrolled_subscription(&topic_named("old.topic"));
            bus.open(*tenant, &consumer_name(&subscription));
            block_on(subscriptions.save(&tenant, &subscription)).unwrap();
        }
        let use_case = DeleteUseCase::new(DeletePorts {
            topic_store: topics_of_test_tenant(topic),
            subscription_store: subscriptions.clone(),
            message_consumer: bus.clone(),
            ..DeletePorts::fakes()
        });

        let (result, _) = run(&use_case, id);

        result.unwrap();
        assert_eq!(subscriptions.count(), 0);
        assert!(bus.open_in(*tenant).is_empty());
    }

    /// Deleting an active topic returns a conflict, keeps the topic and
    /// records no deletion event.
    #[test]
    fn an_active_topic_is_not_deleted() {
        let topic = topic_named("payments.settled");
        let id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let use_case = holding(store.clone(), FakeTenantAuthorities::holding_everything());

        let (result, audit) = run(&use_case, id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(store.count(), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Publishing rights do not permit deleting an archived topic; the
    /// forbidden request keeps the topic.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let topic = archived_topic("old.topic");
        let id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let publisher = FakeTenantAuthorities::holding(&[SystemPermission::Messaging(
            MessagingAction::Publish,
        )]);

        let (result, _) = run(&holding(store.clone(), publisher), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
    }

    /// A signed-out caller receives an unauthenticated error when deleting
    /// an archived topic.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let topic = archived_topic("old.topic");
        let id = *topic.id();
        let refusing = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let (result, _) = run(&holding(topics_of_test_tenant(topic), refusing), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A topic the tenant does not have is not found.
    #[test]
    fn an_unknown_topic_is_not_found() {
        let use_case = holding(
            Arc::new(FakeTopicStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, _) = run(&use_case, TopicId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
