//! Pull messages: hand out messages from a subscription, each waiting for
//! its acknowledgement.

use std::sync::Arc;

use ianua_domain::domains::messaging::delivery::MessageFate;
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::MessageSubscriptionId;

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{
    ConsumerRead, MessageConsumer, PendingMessage, SubscriptionStore, TopicStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::messaging::broker::consuming::{consumed_subscription, ensure_active};
use crate::use_cases::messaging::bus::consumer_name;
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};
use crate::use_cases::messaging::lookup::existing_named_topic;
use crate::use_cases::messaging::settling::{fate_on_arrival, set_aside};

/// Which subscription to pull from, and how many messages at most.
pub struct PullMessagesRequest {
    /// The subscription whose consumer is read.
    pub subscription_id: MessageSubscriptionId,
    /// The most messages to return.
    pub max_messages: usize,
}

/// Ports needed by the pull messages use case.
#[derive(ianua_macros::Fakes)]
pub struct PullMessagesPorts {
    /// Port for subscription lookup.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// The topics, whose class each pull is checked against now.
    pub topic_store: Arc<dyn TopicStore>,
    /// Port for pulling from the bus.
    pub message_consumer: Arc<dyn MessageConsumer>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// What a consumer's roles give it, once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
}

/// A subscription a reader may pull from, with the rule its topic keeps
/// messages by now.
struct ReadableSubscription {
    /// The subscription read.
    subscription: Subscription<ResolvedTenant>,
    /// How long the topic keeps its messages, as stored now.
    retention: RetentionPolicy,
}

/// Hands out subscription messages that wait for the caller's acknowledgement.
pub struct PullMessagesUseCase {
    ports: PullMessagesPorts,
}

impl PullMessagesUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: PullMessagesPorts) -> Self {
        Self { ports }
    }

    /// The active subscription `id` that `actor` may read from, on a topic
    /// classed within the actor's clearance now.
    async fn readable_subscription(
        &self,
        tenant: &ScopedTenant,
        actor: &MessagingActor,
        id: &MessageSubscriptionId,
    ) -> Result<ReadableSubscription, AppError> {
        let sub = consumed_subscription(self.ports.subscription_store.as_ref(), tenant, actor, id)
            .await?;
        ensure_active(&sub)?;
        let topic =
            existing_named_topic(self.ports.topic_store.as_ref(), tenant, sub.topic_name()).await?;
        actor.reading(|reader| topic.ensure_readable_by(reader))?;
        Ok(ReadableSubscription {
            retention: topic.retention(),
            subscription: sub,
        })
    }

    /// Up to `max_messages` of the waiting messages `readable`'s topic
    /// still keeps. A message whose deliveries are spent is set aside on the
    /// way instead of handed out.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the bus refuses.
    async fn handed_out(
        &self,
        tenant: &ScopedTenant,
        readable: &ReadableSubscription,
        max_messages: usize,
    ) -> Result<Vec<PendingMessage>, AppError> {
        let bus = self.ports.message_consumer.as_ref();
        let sub = &readable.subscription;
        let name = consumer_name(sub);
        let read = ConsumerRead {
            topic_name: sub.topic_name(),
            consumer_name: &name,
            retention: readable.retention,
        };
        let fetched = bus
            .fetch_pending(tenant, read, max_messages)
            .await
            .or_internal()?;
        let mut kept = Vec::with_capacity(fetched.len());
        for message in fetched {
            match fate_on_arrival(sub, &message) {
                MessageFate::Redeliver => kept.push(message),
                MessageFate::DeadLetter => set_aside(bus, tenant, sub, &message.receipt).await?,
            }
        }
        Ok(kept)
    }
}

impl Query for PullMessagesUseCase {
    type Caller = MessagingCaller;
    type Input = PullMessagesRequest;
    type Output = Result<Vec<PendingMessage>, AppError>;

    /// Hands out up to `max_messages` from the subscription's consumer, each
    /// with the receipt that acknowledges or refuses it. Nothing is taken
    /// until it is acknowledged: a message not acknowledged within the
    /// subscription's deadline comes round again, and one whose deliveries
    /// are spent is set aside as a dead letter instead of handed out.
    ///
    /// Pulling hands out the service's messages, so it needs the consume
    /// right, and a consumer pulls only from its own subscriptions. The
    /// topic's class is checked against the caller's clearance on every
    /// pull, since it may have been raised after the subscription was made.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or consumer
    ///   credential no longer counts.
    /// - `AppError::Forbidden` when the person, or the consumer's roles, may
    ///   not consume, the subscription is paused, or the topic's class is
    ///   above the caller's clearance.
    /// - `AppError::NotFound` if the subscription or its topic doesn't
    ///   exist, or the subscription is another service's and a consumer
    ///   asks.
    /// - `AppError::Internal` on bus failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        request: PullMessagesRequest,
    ) -> Result<Vec<PendingMessage>, AppError> {
        let tenant = caller.tenant();
        let actor = MessagingActor::of(
            caller,
            self.ports.tenant_authorities.as_ref(),
            self.ports.consumers.as_ref(),
        )
        .await?;
        let readable = self
            .readable_subscription(&tenant, &actor, &request.subscription_id)
            .await?;
        self.handed_out(&tenant, &readable, request.max_messages)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        DataAccessAction, MessagingAction, SystemPermission,
    };
    use ianua_domain::domains::consumers::consumer::Consumer;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::messaging::topic::Topic;

    use super::*;
    use crate::ports::messaging::DeliveryReceipt;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{
        billing_sync, consumer_named, key_caller, sign_in_of, test_key_digest,
    };
    use crate::test_support::messaging::{
        FakeMessageConsumer, FakeSubscriptionStore, Settlement, messaging_admin,
        paused_subscription_of, pending_message, subscription_of, topic_classed, topic_named,
        topics_of_test_tenant,
    };
    use crate::test_support::{block_on, test_ctx};

    const CONSUME: SystemPermission = SystemPermission::Messaging(MessagingAction::Consume);

    struct Bench {
        use_case: PullMessagesUseCase,
        bus: Arc<FakeMessageConsumer>,
        id: MessageSubscriptionId,
    }

    /// `sub`, on an internal topic of its name, with one message waiting.
    fn bench(
        sub: Subscription<ResolvedTenant>,
        caller_consumer: Consumer<ResolvedTenant>,
        people: FakeTenantAuthorities,
    ) -> Bench {
        let topic = topic_named(sub.topic_name().as_str());
        bench_on(
            topic,
            sub,
            caller_consumer,
            people,
            vec![pending_message("r-1", 1)],
        )
    }

    /// `sub`, on `topic` as it stands now, with `waiting` on the bus.
    fn bench_on(
        topic: Topic<ResolvedTenant>,
        sub: Subscription<ResolvedTenant>,
        caller_consumer: Consumer<ResolvedTenant>,
        people: FakeTenantAuthorities,
        waiting: Vec<PendingMessage>,
    ) -> Bench {
        let id = *sub.id();
        let bus = Arc::new(FakeMessageConsumer::holding(waiting));
        bus.open(test_ctx().tenant_id(), &consumer_name(&sub));
        let use_case = PullMessagesUseCase::new(PullMessagesPorts {
            subscription_store: FakeSubscriptionStore::of_test_tenant([sub]),
            topic_store: topics_of_test_tenant(topic),
            message_consumer: bus.clone(),
            tenant_authorities: Arc::new(people),
            consumers: sign_in_of(caller_consumer, &[CONSUME]),
        });
        Bench { use_case, bus, id }
    }

    fn pull(bench: &Bench, caller: &MessagingCaller) -> Result<Vec<PendingMessage>, AppError> {
        let request = PullMessagesRequest {
            subscription_id: bench.id,
            max_messages: 10,
        };
        block_on(bench.use_case.execute(caller, request))
    }

    fn person() -> MessagingCaller {
        MessagingCaller::Person(test_ctx())
    }

    fn itself() -> MessagingCaller {
        MessagingCaller::Consumer(key_caller(test_key_digest()))
    }

    /// Ann may consume. She pulls from "billing-sync"'s subscription and
    /// gets the message waiting there, with the receipt that acknowledges
    /// it. It stays on the bus until she does.
    #[test]
    fn a_person_with_the_consume_right_is_handed_waiting_messages() {
        let sub = subscription_of(&billing_sync(), &topic_named("orders.created"));
        let bench = bench(
            sub,
            billing_sync(),
            FakeTenantAuthorities::holding(&[CONSUME]),
        );

        let messages = pull(&bench, &person()).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].receipt, DeliveryReceipt::new("r-1"));
        assert_eq!(bench.bus.pending().len(), 1);
        assert!(bench.bus.settled().is_empty());
    }

    /// "billing-sync" pulls from its own subscription with its own key.
    #[test]
    fn a_consumer_pulls_from_its_own_subscription() {
        let consumer = billing_sync();
        let sub = subscription_of(&consumer, &topic_named("orders.created"));
        let bench = bench(
            sub,
            consumer,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let messages = pull(&bench, &itself()).unwrap();

        assert_eq!(messages.len(), 1);
    }

    /// A sixth delivery exceeds the standard limit and is set aside as a
    /// dead letter, while a fresh message in the same pull is handed out.
    #[test]
    fn a_message_whose_deliveries_are_spent_is_set_aside() {
        let consumer = billing_sync();
        let topic = topic_named("orders.created");
        let sub = subscription_of(&consumer, &topic);
        let name = consumer_name(&sub);
        let waiting = vec![pending_message("poison", 6), pending_message("fresh", 1)];
        let bench = bench_on(
            topic,
            sub,
            consumer,
            FakeTenantAuthorities::holding_everything(),
            waiting,
        );

        let messages = pull(&bench, &person()).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].receipt, DeliveryReceipt::new("fresh"));
        assert_eq!(
            bench.bus.settled(),
            [(DeliveryReceipt::new("poison"), Settlement::DeadLettered)]
        );
        assert_eq!(bench.bus.dead_letters_of(&name).len(), 1);
    }

    /// Its fifth delivery is still its own: a message delivered four times
    /// unacknowledged is handed out once more.
    #[test]
    fn a_message_with_a_delivery_left_is_handed_out() {
        let consumer = billing_sync();
        let topic = topic_named("orders.created");
        let sub = subscription_of(&consumer, &topic);
        let bench = bench_on(
            topic,
            sub,
            consumer,
            FakeTenantAuthorities::holding_everything(),
            vec![pending_message("last-chance", 5)],
        );

        let messages = pull(&bench, &person()).unwrap();

        assert_eq!(messages.len(), 1);
        assert!(bench.bus.settled().is_empty());
    }

    /// Billing's consumer receives not found when pulling payroll's subscription.
    #[test]
    fn a_consumer_pulling_another_services_subscription_is_not_found() {
        let payroll = consumer_named("payroll", DataClassLevel::Internal);
        let sub = subscription_of(&payroll, &topic_named("payments.settled"));
        let bench = bench(
            sub,
            billing_sync(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = pull(&bench, &itself());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Messaging-view permission alone cannot pull a subscription's messages.
    #[test]
    fn a_person_who_may_only_view_is_refused() {
        let sub = subscription_of(&billing_sync(), &topic_named("orders.created"));
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::View)]);
        let bench = bench(sub, billing_sync(), viewer);

        let result = pull(&bench, &person());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out person receives unauthenticated when pulling messages.
    #[test]
    fn a_signed_out_person_is_refused() {
        let sub = subscription_of(&billing_sync(), &topic_named("orders.created"));
        let bench = bench(
            sub,
            billing_sync(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = pull(&bench, &person());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Pulling a paused subscription is forbidden even for a fully authorized person.
    #[test]
    fn a_paused_subscription_is_not_pulled_from() {
        let sub = paused_subscription_of(&billing_sync(), &topic_named("orders.created"));
        let bench = bench(
            sub,
            billing_sync(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = pull(&bench, &person());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Raising a topic to restricted after an internal-clearance consumer
    /// subscribes makes that consumer's next pull forbidden.
    #[test]
    fn a_consumer_below_a_raised_topics_class_pulls_nothing() {
        let consumer = billing_sync();
        let mut topic = topic_named("payroll.events");
        let sub = subscription_of(&consumer, &topic);
        topic
            .raise_data_class(DataClassLevel::Restricted, &messaging_admin())
            .unwrap();
        let bench = bench_on(
            topic,
            sub,
            consumer,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            vec![pending_message("r-1", 1)],
        );

        let result = pull(&bench, &itself());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A confidential topic refuses a person with internal clearance, while
    /// a person with consume permission and confidential clearance receives
    /// its waiting message.
    #[test]
    fn a_person_pulls_only_within_their_clearance() {
        let payroll = || consumer_named("payroll", DataClassLevel::Confidential);
        let topic = || topic_classed("salaries.paid", DataClassLevel::Confidential);
        let sub = || subscription_of(&payroll(), &topic());
        let waiting = || vec![pending_message("r-1", 1)];
        let sam = bench_on(
            topic(),
            sub(),
            payroll(),
            FakeTenantAuthorities::holding(&[CONSUME]),
            waiting(),
        );
        let fay = bench_on(
            topic(),
            sub(),
            payroll(),
            FakeTenantAuthorities::holding(&[
                CONSUME,
                SystemPermission::Data(DataAccessAction::Confidential),
            ]),
            waiting(),
        );

        let by_sam = pull(&sam, &person());
        let by_fay = pull(&fay, &person());

        assert!(matches!(by_sam, Err(AppError::Forbidden(_))));
        assert_eq!(by_fay.unwrap().len(), 1);
    }

    /// A subscription the tenant does not have is not found.
    #[test]
    fn pulling_from_an_unknown_subscription_is_not_found() {
        let sub = subscription_of(&billing_sync(), &topic_named("orders.created"));
        let bench = Bench {
            id: MessageSubscriptionId::new(),
            ..bench(
                sub,
                billing_sync(),
                FakeTenantAuthorities::holding_everything(),
            )
        };

        let result = pull(&bench, &person());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
