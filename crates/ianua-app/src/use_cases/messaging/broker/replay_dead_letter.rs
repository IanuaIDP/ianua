//! Replay dead letter: put a message a subscription set aside back in
//! front of its service, once whatever made it fail is fixed.

use std::sync::Arc;

use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::MessageSubscriptionId;

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{
    ConsumerRead, DeadLetterId, DeadLetters, Replay, SubscriptionStore, TopicStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::messaging::broker::consuming::consumed_subscription;
use crate::use_cases::messaging::bus::consumer_name;
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};
use crate::use_cases::messaging::lookup::existing_named_topic;

/// Which dead letter of which subscription is replayed.
pub struct ReplayDeadLetterRequest {
    /// The subscription that set it aside.
    pub subscription_id: MessageSubscriptionId,
    /// The set-aside delivery to return for another attempt.
    pub dead_letter_id: DeadLetterId,
}

/// The ports [`ReplayDeadLetterUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReplayDeadLetterPorts {
    /// Where subscriptions are kept.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// The topics, whose keeping limit a dead letter is held to.
    pub topic_store: Arc<dyn TopicStore>,
    /// Where the bus keeps dead letters.
    pub dead_letters: Arc<dyn DeadLetters>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// What a consumer's roles give it, once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
}

/// Returns a set-aside delivery to its subscription for another attempt.
pub struct ReplayDeadLetterUseCase {
    ports: ReplayDeadLetterPorts,
}

impl ReplayDeadLetterUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReplayDeadLetterPorts) -> Self {
        Self { ports }
    }

    /// Puts dead letter `id` back for `sub`, if its topic still keeps it.
    async fn replay(
        &self,
        tenant: &ScopedTenant,
        sub: &Subscription<ResolvedTenant>,
        id: DeadLetterId,
    ) -> Result<(), AppError> {
        let topics = self.ports.topic_store.as_ref();
        let topic = existing_named_topic(topics, tenant, sub.topic_name()).await?;
        let name = consumer_name(sub);
        let read = ConsumerRead {
            topic_name: sub.topic_name(),
            consumer_name: &name,
            retention: topic.retention(),
        };
        let replay = self
            .ports
            .dead_letters
            .replay(tenant, read, id)
            .await
            .or_internal()?;
        ensure_replayed(replay)
    }
}

impl Command for ReplayDeadLetterUseCase {
    type Caller = MessagingCaller;
    type Input = ReplayDeadLetterRequest;
    type Output = Result<(), AppError>;

    /// Puts the dead letter back on the subscription's consumer alone, with
    /// a fresh count of deliveries, removes it from the dead letters and
    /// records `messaging.dead_letter_replayed`. No other subscription of
    /// the topic sees it twice.
    ///
    /// A replay hands the service a message it once gave up on, such as a
    /// payment, so unlike acknowledging or refusing a delivery, which is
    /// the message flow itself, it is put on record.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or consumer
    ///   credential no longer counts.
    /// - `AppError::Forbidden` when the person, or the consumer's roles, may
    ///   not consume.
    /// - `AppError::NotFound` if the subscription or its topic doesn't exist,
    ///   the subscription is another service's and a consumer asks, or it
    ///   holds no such dead letter, or none still inside its topic's limit.
    /// - `AppError::Internal` on storage, bus or audit failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        auditor: &RequestAuditor,
        request: ReplayDeadLetterRequest,
    ) -> Result<(), AppError> {
        let tenant = caller.tenant();
        let actor = MessagingActor::of(
            caller,
            self.ports.tenant_authorities.as_ref(),
            self.ports.consumers.as_ref(),
        )
        .await?;
        let store = self.ports.subscription_store.as_ref();
        let mut sub =
            consumed_subscription(store, &tenant, &actor, &request.subscription_id).await?;
        actor.reading(|reader| sub.replay_dead_letter(reader))?;
        self.replay(&tenant, &sub, request.dead_letter_id).await?;

        auditor
            .dispatch_by(&actor.actor(), sub.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Refuses a replay of a dead letter the subscription does not hold.
///
/// # Errors
///
/// `AppError::NotFound` when there was nothing to replay.
fn ensure_replayed(replay: Replay) -> Result<(), AppError> {
    match replay {
        Replay::Requeued => Ok(()),
        Replay::NotHeld => Err(AppError::NotFound(message!(
            "messaging-dead-letter-not-found",
            "dead letter not found"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::consumers::consumer::Consumer;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::messaging::subscription::Subscription;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{
        billing_sync, consumer_named, key_caller, sign_in_of, test_key_digest,
    };
    use crate::test_support::messaging::{
        FakeMessageConsumer, FakeSubscriptionStore, dead_letter, subscription_of, topic_named,
        topics_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const CONSUME: SystemPermission = SystemPermission::Messaging(MessagingAction::Consume);

    struct Bench {
        use_case: ReplayDeadLetterUseCase,
        bus: Arc<FakeMessageConsumer>,
        audit: Arc<FakeEventDispatcher>,
        id: MessageSubscriptionId,
        consumer_name: String,
    }

    /// `sub` holding dead letter 1.
    fn bench(
        sub: Subscription<ResolvedTenant>,
        caller_consumer: Consumer<ResolvedTenant>,
        people: FakeTenantAuthorities,
    ) -> Bench {
        let id = *sub.id();
        let name = consumer_name(&sub);
        let bus = Arc::new(FakeMessageConsumer::empty());
        bus.set_aside(&name, dead_letter(1));
        let use_case = ReplayDeadLetterUseCase::new(ReplayDeadLetterPorts {
            subscription_store: FakeSubscriptionStore::of_test_tenant([sub]),
            topic_store: topics_of_test_tenant(topic_named("orders.created")),
            dead_letters: bus.clone(),
            tenant_authorities: Arc::new(people),
            consumers: sign_in_of(caller_consumer, &[CONSUME]),
        });
        Bench {
            use_case,
            bus,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
            consumer_name: name,
        }
    }

    /// "billing-sync"'s own subscription to `orders.created`.
    fn own(people: FakeTenantAuthorities) -> Bench {
        let consumer = billing_sync();
        bench(
            subscription_of(&consumer, &topic_named("orders.created")),
            consumer,
            people,
        )
    }

    fn replay(bench: &Bench, caller: &MessagingCaller, sequence: u64) -> Result<(), AppError> {
        let request = ReplayDeadLetterRequest {
            subscription_id: bench.id,
            dead_letter_id: DeadLetterId::new(sequence),
        };
        let auditor = test_auditor(bench.audit.clone());
        block_on(bench.use_case.execute(caller, &auditor, request))
    }

    fn recorded(bench: &Bench) -> Vec<String> {
        bench.audit.records.lock().unwrap().clone()
    }

    fn itself() -> MessagingCaller {
        MessagingCaller::Consumer(key_caller(test_key_digest()))
    }

    fn person() -> MessagingCaller {
        MessagingCaller::Person(test_ctx())
    }

    /// Ann fixed the bug that made "billing-sync" fail on an order, and
    /// replays it. It waits on the bus again, is no longer a dead letter,
    /// and the replay is recorded.
    #[test]
    fn a_replayed_dead_letter_is_delivered_again_and_recorded() {
        let bench = own(FakeTenantAuthorities::holding(&[CONSUME]));

        let result = replay(&bench, &person(), 1);

        result.unwrap();
        assert_eq!(bench.bus.pending().len(), 1);
        assert!(bench.bus.dead_letters_of(&bench.consumer_name).is_empty());
        assert_eq!(recorded(&bench), ["messaging.dead_letter_replayed"]);
    }

    /// "billing-sync" replays its own dead letter with its own key. The
    /// record names the service.
    #[test]
    fn a_consumer_replays_its_own_dead_letter() {
        let bench = own(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = replay(&bench, &itself(), 1);

        result.unwrap();
        assert_eq!(recorded(&bench), ["messaging.dead_letter_replayed"]);
    }

    /// A dead letter the subscription does not hold is not found, and
    /// nothing is recorded.
    #[test]
    fn an_unknown_dead_letter_is_not_found() {
        let bench = own(FakeTenantAuthorities::holding_everything());

        let result = replay(&bench, &person(), 9);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(bench.bus.pending().is_empty());
        assert!(recorded(&bench).is_empty());
    }

    /// Billing's consumer cannot replay payroll's dead letter. The request
    /// returns not found and leaves the letter set aside.
    #[test]
    fn a_consumer_replaying_another_services_dead_letter_is_not_found() {
        let payroll = consumer_named("payroll", DataClassLevel::Internal);
        let bench = bench(
            subscription_of(&payroll, &topic_named("payments.settled")),
            billing_sync(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = replay(&bench, &itself(), 1);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.bus.dead_letters_of(&bench.consumer_name).len(), 1);
    }

    /// Messaging-view permission alone cannot replay a dead letter, which
    /// remains set aside with no audit event.
    #[test]
    fn a_person_who_may_not_consume_is_refused() {
        let bench = own(FakeTenantAuthorities::holding(&[
            SystemPermission::Messaging(MessagingAction::View),
        ]));

        let result = replay(&bench, &person(), 1);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.bus.dead_letters_of(&bench.consumer_name).len(), 1);
        assert!(recorded(&bench).is_empty());
    }

    /// A signed-out person receives unauthenticated when replaying a dead letter.
    #[test]
    fn a_signed_out_person_is_refused() {
        let bench = own(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = replay(&bench, &person(), 1);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A subscription the tenant does not have is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let bench = Bench {
            id: MessageSubscriptionId::new(),
            ..own(FakeTenantAuthorities::holding_everything())
        };

        let result = replay(&bench, &person(), 1);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A replay is held to the keeping limit of the subscription's topic,
    /// as the topic stands now.
    #[test]
    fn a_replay_is_held_to_its_topics_limit() {
        let bench = own(FakeTenantAuthorities::holding(&[CONSUME]));

        replay(&bench, &person(), 1).unwrap();

        assert_eq!(
            bench.bus.dead_letter_limits(),
            [topic_named("orders.created").retention()]
        );
    }
}
