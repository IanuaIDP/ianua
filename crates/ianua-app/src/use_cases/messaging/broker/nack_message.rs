//! Refuse message: a service could not take a message it was handed. It is
//! delivered again, or set aside once its deliveries are spent.

use std::sync::Arc;

use ianua_domain::domains::messaging::delivery::MessageFate;
use ianua_domain::types::MessageSubscriptionId;

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::error::AppError;
use crate::ports::messaging::{DeliveryReceipt, MessageConsumer, SubscriptionStore};
use crate::use_case::Query;
use crate::use_cases::messaging::broker::consuming::{consumed_subscription, existing_delivery};
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};
use crate::use_cases::messaging::settling::settle_refused;

/// Which delivery of which subscription is refused.
pub struct NackMessageRequest {
    /// The subscription the message was pulled from.
    pub subscription_id: MessageSubscriptionId,
    /// The receipt it was handed out with.
    pub receipt: DeliveryReceipt,
}

/// The ports [`NackMessageUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct NackMessagePorts {
    /// Where subscriptions are kept.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// The bus the message waits on.
    pub message_consumer: Arc<dyn MessageConsumer>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// What a consumer's roles give it, once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
}

/// Refuses one delivery.
pub struct NackMessageUseCase {
    ports: NackMessagePorts,
}

impl NackMessageUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: NackMessagePorts) -> Self {
        Self { ports }
    }
}

impl Query for NackMessageUseCase {
    type Caller = MessagingCaller;
    type Input = NackMessageRequest;
    type Output = Result<MessageFate, AppError>;

    /// Refuses the delivery the receipt names. The subscription's
    /// acknowledgement policy decides, from how often the bus has delivered
    /// it, whether it comes round again at once or is set aside as a dead
    /// letter. Returns which.
    ///
    /// Nothing is put on record: refusing a delivery is the message flow
    /// itself, as many times a second as the service reads, not a change an
    /// administrator makes. Replaying a dead letter is, and is recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or consumer
    ///   credential no longer counts.
    /// - `AppError::Forbidden` when the person, or the consumer's roles, may
    ///   not consume.
    /// - `AppError::NotFound` if the subscription doesn't exist, is another
    ///   service's and a consumer asks, or the delivery no longer waits.
    /// - `AppError::Internal` on storage or bus failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        request: NackMessageRequest,
    ) -> Result<MessageFate, AppError> {
        let tenant = caller.tenant();
        let actor = MessagingActor::of(
            caller,
            self.ports.tenant_authorities.as_ref(),
            self.ports.consumers.as_ref(),
        )
        .await?;
        let store = self.ports.subscription_store.as_ref();
        let sub = consumed_subscription(store, &tenant, &actor, &request.subscription_id).await?;
        let bus = self.ports.message_consumer.as_ref();
        let delivery = existing_delivery(bus, &tenant, &sub, &request.receipt).await?;

        settle_refused(bus, &tenant, &sub, &request.receipt, delivery.delivered).await
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
        FakeMessageConsumer, FakeSubscriptionStore, Settlement, pending_message, subscription_of,
        topic_named,
    };
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::messaging::bus::consumer_name;

    const CONSUME: SystemPermission = SystemPermission::Messaging(MessagingAction::Consume);

    struct Bench {
        use_case: NackMessageUseCase,
        bus: Arc<FakeMessageConsumer>,
        id: MessageSubscriptionId,
        consumer_name: String,
    }

    /// `sub` with one message handed out under receipt `r-1` for its
    /// `delivered`th time.
    fn bench(
        sub: Subscription<ResolvedTenant>,
        caller_consumer: Consumer<ResolvedTenant>,
        people: FakeTenantAuthorities,
        delivered: u32,
    ) -> Bench {
        let id = *sub.id();
        let name = consumer_name(&sub);
        let bus = Arc::new(FakeMessageConsumer::holding(vec![pending_message(
            "r-1", delivered,
        )]));
        bus.open(test_ctx().tenant_id(), &name);
        let use_case = NackMessageUseCase::new(NackMessagePorts {
            subscription_store: FakeSubscriptionStore::of_test_tenant([sub]),
            message_consumer: bus.clone(),
            tenant_authorities: Arc::new(people),
            consumers: sign_in_of(caller_consumer, &[CONSUME]),
        });
        Bench {
            use_case,
            bus,
            id,
            consumer_name: name,
        }
    }

    /// "billing-sync"'s own subscription to `orders.created`, its message
    /// handed out for its `delivered`th time.
    fn own(delivered: u32) -> Bench {
        let consumer = billing_sync();
        bench(
            subscription_of(&consumer, &topic_named("orders.created")),
            consumer,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            delivered,
        )
    }

    fn nack(
        bench: &Bench,
        caller: &MessagingCaller,
        receipt: &str,
    ) -> Result<MessageFate, AppError> {
        let request = NackMessageRequest {
            subscription_id: bench.id,
            receipt: DeliveryReceipt::new(receipt),
        };
        block_on(bench.use_case.execute(caller, request))
    }

    fn itself() -> MessagingCaller {
        MessagingCaller::Consumer(key_caller(test_key_digest()))
    }

    fn person() -> MessagingCaller {
        MessagingCaller::Person(test_ctx())
    }

    /// "billing-sync"'s database is down, so it refuses the order on its
    /// second delivery. The order comes round again at once, and nothing is
    /// put on record.
    #[test]
    fn a_refused_message_with_deliveries_left_is_delivered_again() {
        let bench = own(2);

        let result = nack(&bench, &itself(), "r-1");

        assert_eq!(result.unwrap(), MessageFate::Redeliver);
        assert_eq!(
            bench.bus.settled(),
            [(DeliveryReceipt::new("r-1"), Settlement::Redelivered)]
        );
    }

    /// Refusing the fifth delivery reaches the standard retry limit and
    /// stores the message as a dead letter.
    #[test]
    fn a_message_refused_on_its_last_delivery_is_set_aside() {
        let bench = own(5);

        let result = nack(&bench, &itself(), "r-1");

        assert_eq!(result.unwrap(), MessageFate::DeadLetter);
        assert_eq!(bench.bus.dead_letters_of(&bench.consumer_name).len(), 1);
    }

    /// A refusal for a delivery that no longer waits is not found.
    #[test]
    fn a_delivery_no_longer_waiting_is_not_found() {
        let bench = own(1);

        let result = nack(&bench, &itself(), "expired");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(bench.bus.settled().is_empty());
    }

    /// Billing's consumer cannot refuse a delivery from payroll's
    /// subscription. The request returns not found and settles nothing.
    #[test]
    fn a_consumer_refusing_another_services_message_is_not_found() {
        let payroll = consumer_named("payroll", DataClassLevel::Internal);
        let bench = bench(
            subscription_of(&payroll, &topic_named("payments.settled")),
            billing_sync(),
            FakeTenantAuthorities::holding_everything(),
            5,
        );

        let result = nack(&bench, &itself(), "r-1");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(bench.bus.settled().is_empty());
    }

    /// A person with only messaging-view permission cannot refuse a
    /// delivery, and nothing is settled.
    #[test]
    fn a_person_who_may_not_consume_is_refused() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::View)]);
        let bench = bench(
            subscription_of(&billing_sync(), &topic_named("orders.created")),
            billing_sync(),
            viewer,
            1,
        );

        let result = nack(&bench, &person(), "r-1");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(bench.bus.settled().is_empty());
    }

    /// A signed-out person receives unauthenticated when refusing a delivery.
    #[test]
    fn a_signed_out_person_is_refused() {
        let bench = own(1);

        let result = nack(&bench, &person(), "r-1");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A subscription the tenant does not have is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let bench = Bench {
            id: MessageSubscriptionId::new(),
            ..own(1)
        };

        let result = nack(&bench, &itself(), "r-1");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
