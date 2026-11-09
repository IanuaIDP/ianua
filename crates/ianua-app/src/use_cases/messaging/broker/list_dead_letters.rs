//! List dead letters: the messages a subscription set aside once their
//! deliveries were spent.

use std::sync::Arc;

use ianua_domain::types::MessageSubscriptionId;

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::messaging::{DeadLetter, DeadLetters, SubscriptionStore, TopicStore};
use crate::use_case::Query;
use crate::use_cases::messaging::broker::consuming::consumed_subscription;
use crate::use_cases::messaging::bus::consumer_name;
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};
use crate::use_cases::messaging::lookup::existing_named_topic;

/// Whose dead letters, and which page of them.
pub struct ListDeadLettersRequest {
    /// The subscription that set them aside.
    pub subscription_id: MessageSubscriptionId,
    /// Which page, oldest first.
    pub page: PageRequest,
}

/// The ports [`ListDeadLettersUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListDeadLettersPorts {
    /// Where subscriptions are kept.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// The topics, whose class each read is checked against now.
    pub topic_store: Arc<dyn TopicStore>,
    /// Where the bus keeps dead letters.
    pub dead_letters: Arc<dyn DeadLetters>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// What a consumer's roles give it, once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
}

/// Lists a subscription's dead letters.
pub struct ListDeadLettersUseCase {
    ports: ListDeadLettersPorts,
}

impl ListDeadLettersUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ListDeadLettersPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListDeadLettersUseCase {
    type Caller = MessagingCaller;
    type Input = ListDeadLettersRequest;
    type Output = Result<Page<DeadLetter>, AppError>;

    /// A page of the subscription's dead letters, with what they carry. They
    /// are the topic's messages, so this asks what pulling does: the
    /// consume right, a consumer's own subscription, and a clearance up to
    /// the topic's class as it stands now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or consumer
    ///   credential no longer counts.
    /// - `AppError::Forbidden` when the person, or the consumer's roles, may
    ///   not consume, or the topic's class is above the caller's clearance.
    /// - `AppError::NotFound` if the subscription or its topic doesn't
    ///   exist, or the subscription is another service's and a consumer
    ///   asks.
    /// - `AppError::Internal` on storage or bus failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        request: ListDeadLettersRequest,
    ) -> Result<Page<DeadLetter>, AppError> {
        let tenant = caller.tenant();
        let actor = MessagingActor::of(
            caller,
            self.ports.tenant_authorities.as_ref(),
            self.ports.consumers.as_ref(),
        )
        .await?;
        let store = self.ports.subscription_store.as_ref();
        let sub = consumed_subscription(store, &tenant, &actor, &request.subscription_id).await?;
        let topic =
            existing_named_topic(self.ports.topic_store.as_ref(), &tenant, sub.topic_name())
                .await?;
        actor.reading(|reader| topic.ensure_readable_by(reader))?;

        self.ports
            .dead_letters
            .list(
                &tenant,
                &consumer_name(&sub),
                topic.retention(),
                &request.page,
            )
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::consumers::consumer::Consumer;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::messaging::subscription::Subscription;
    use ianua_domain::domains::messaging::topic::Topic;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{
        billing_sync, consumer_named, key_caller, sign_in_of, test_key_digest,
    };
    use crate::test_support::messaging::{
        FakeMessageConsumer, FakeSubscriptionStore, dead_letter, subscription_of, topic_classed,
        topic_named, topics_of_test_tenant,
    };
    use crate::test_support::{block_on, test_ctx};

    const CONSUME: SystemPermission = SystemPermission::Messaging(MessagingAction::Consume);

    struct Bench {
        use_case: ListDeadLettersUseCase,
        id: MessageSubscriptionId,
    }

    /// `sub` on `topic`, with two dead letters set aside.
    fn bench(
        topic: Topic<ResolvedTenant>,
        sub: Subscription<ResolvedTenant>,
        caller_consumer: Consumer<ResolvedTenant>,
        people: FakeTenantAuthorities,
    ) -> Bench {
        let id = *sub.id();
        let bus = Arc::new(FakeMessageConsumer::empty());
        bus.set_aside(&consumer_name(&sub), dead_letter(1));
        bus.set_aside(&consumer_name(&sub), dead_letter(2));
        let use_case = ListDeadLettersUseCase::new(ListDeadLettersPorts {
            subscription_store: FakeSubscriptionStore::of_test_tenant([sub]),
            topic_store: topics_of_test_tenant(topic),
            dead_letters: bus,
            tenant_authorities: Arc::new(people),
            consumers: sign_in_of(caller_consumer, &[CONSUME]),
        });
        Bench { use_case, id }
    }

    /// "billing-sync"'s own subscription to `orders.created`.
    fn own(people: FakeTenantAuthorities) -> Bench {
        let consumer = billing_sync();
        let topic = topic_named("orders.created");
        let sub = subscription_of(&consumer, &topic);
        bench(topic, sub, consumer, people)
    }

    fn list(bench: &Bench, caller: &MessagingCaller) -> Result<Page<DeadLetter>, AppError> {
        let request = ListDeadLettersRequest {
            subscription_id: bench.id,
            page: PageRequest::default(),
        };
        block_on(bench.use_case.execute(caller, request))
    }

    fn itself() -> MessagingCaller {
        MessagingCaller::Consumer(key_caller(test_key_digest()))
    }

    fn person() -> MessagingCaller {
        MessagingCaller::Person(test_ctx())
    }

    /// Ann looks at the orders "billing-sync" could never take. Both are
    /// listed.
    #[test]
    fn a_subscriptions_dead_letters_are_listed() {
        let bench = own(FakeTenantAuthorities::holding(&[CONSUME]));

        let page = list(&bench, &person()).unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(!page.has_next());
    }

    /// Billing's consumer receives not found when listing payroll's dead letters.
    #[test]
    fn a_consumer_reading_another_services_dead_letters_is_not_found() {
        let payroll = consumer_named("payroll", DataClassLevel::Internal);
        let topic = topic_named("payments.settled");
        let sub = subscription_of(&payroll, &topic);
        let bench = bench(
            topic,
            sub,
            billing_sync(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = list(&bench, &itself());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A person with consume permission but internal clearance is forbidden
    /// from listing dead letters on a confidential payroll topic.
    #[test]
    fn dead_letters_above_the_callers_clearance_are_refused() {
        let payroll = consumer_named("payroll", DataClassLevel::Confidential);
        let topic = topic_classed("salaries.paid", DataClassLevel::Confidential);
        let sub = subscription_of(&payroll, &topic);
        let bench = bench(
            topic,
            sub,
            payroll,
            FakeTenantAuthorities::holding(&[CONSUME]),
        );

        let result = list(&bench, &person());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Messaging-view permission alone cannot list a subscription's dead letters.
    #[test]
    fn a_person_who_may_not_consume_is_refused() {
        let bench = own(FakeTenantAuthorities::holding(&[
            SystemPermission::Messaging(MessagingAction::View),
        ]));

        let result = list(&bench, &person());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out person receives unauthenticated when listing dead letters.
    #[test]
    fn a_signed_out_person_is_refused() {
        let bench = own(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = list(&bench, &person());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A subscription the tenant does not have is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let bench = Bench {
            id: MessageSubscriptionId::new(),
            ..own(FakeTenantAuthorities::holding_everything())
        };

        let result = list(&bench, &person());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
