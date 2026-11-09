//! Acknowledge message: a service took a message it was handed, so it is
//! not delivered again.

use std::sync::Arc;

use ianua_domain::types::MessageSubscriptionId;

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{DeliveryReceipt, MessageConsumer, SubscriptionStore};
use crate::use_case::Query;
use crate::use_cases::messaging::broker::consuming::{consumed_subscription, existing_delivery};
use crate::use_cases::messaging::bus::consumer_name;
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};

/// Which delivery of which subscription is acknowledged.
pub struct AckMessageRequest {
    /// The subscription the message was pulled from.
    pub subscription_id: MessageSubscriptionId,
    /// The receipt it was handed out with.
    pub receipt: DeliveryReceipt,
}

/// The ports [`AckMessageUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AckMessagePorts {
    /// Where subscriptions are kept.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// The bus the message waits on.
    pub message_consumer: Arc<dyn MessageConsumer>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// What a consumer's roles give it, once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
}

/// Acknowledges one delivery.
pub struct AckMessageUseCase {
    ports: AckMessagePorts,
}

impl AckMessageUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AckMessagePorts) -> Self {
        Self { ports }
    }
}

impl Query for AckMessageUseCase {
    type Caller = MessagingCaller;
    type Input = AckMessageRequest;
    type Output = Result<(), AppError>;

    /// Acknowledges the delivery the receipt names, so the message is taken
    /// and never delivered again.
    ///
    /// Nothing is put on record: acknowledging a delivery is the message
    /// flow itself, as many times a second as the service reads, and
    /// changes no record of the tenant's. Replaying a dead letter is an
    /// administrator's change, and is recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or consumer
    ///   credential no longer counts.
    /// - `AppError::Forbidden` when the person, or the consumer's roles, may
    ///   not consume.
    /// - `AppError::NotFound` if the subscription doesn't exist, is another
    ///   service's and a consumer asks, or the delivery no longer waits:
    ///   already settled, past its deadline, or never this subscription's.
    /// - `AppError::Internal` on storage or bus failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        request: AckMessageRequest,
    ) -> Result<(), AppError> {
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
        existing_delivery(bus, &tenant, &sub, &request.receipt).await?;

        bus.acknowledge(
            &tenant,
            sub.topic_name(),
            &consumer_name(&sub),
            &request.receipt,
        )
        .await
        .or_internal()
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

    const CONSUME: SystemPermission = SystemPermission::Messaging(MessagingAction::Consume);

    struct Bench {
        use_case: AckMessageUseCase,
        bus: Arc<FakeMessageConsumer>,
        id: MessageSubscriptionId,
    }

    /// `sub` with one message handed out under receipt `r-1`.
    fn bench(
        sub: Subscription<ResolvedTenant>,
        caller_consumer: Consumer<ResolvedTenant>,
        people: FakeTenantAuthorities,
    ) -> Bench {
        let id = *sub.id();
        let bus = Arc::new(FakeMessageConsumer::holding(vec![pending_message(
            "r-1", 1,
        )]));
        bus.open(test_ctx().tenant_id(), &consumer_name(&sub));
        let use_case = AckMessageUseCase::new(AckMessagePorts {
            subscription_store: FakeSubscriptionStore::of_test_tenant([sub]),
            message_consumer: bus.clone(),
            tenant_authorities: Arc::new(people),
            consumers: sign_in_of(caller_consumer, &[CONSUME]),
        });
        Bench { use_case, bus, id }
    }

    fn ack(bench: &Bench, caller: &MessagingCaller, receipt: &str) -> Result<(), AppError> {
        let request = AckMessageRequest {
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

    /// "billing-sync" handled the order it pulled and acknowledges it. The
    /// message is taken and waits no more, and nothing is put on record.
    #[test]
    fn an_acknowledged_message_is_taken() {
        let consumer = billing_sync();
        let bench = bench(
            subscription_of(&consumer, &topic_named("orders.created")),
            consumer,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = ack(&bench, &itself(), "r-1");

        result.unwrap();
        assert_eq!(
            bench.bus.settled(),
            [(DeliveryReceipt::new("r-1"), Settlement::Acknowledged)]
        );
        assert!(bench.bus.pending().is_empty());
    }

    /// The receipt's deadline passed, so the message went round again. The
    /// late acknowledgement is not found and settles nothing.
    #[test]
    fn a_delivery_no_longer_waiting_is_not_found() {
        let consumer = billing_sync();
        let bench = bench(
            subscription_of(&consumer, &topic_named("orders.created")),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );

        let result = ack(&bench, &itself(), "expired");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(bench.bus.settled().is_empty());
    }

    /// Billing's consumer cannot acknowledge a delivery from payroll's
    /// subscription. The request returns not found and settles nothing.
    #[test]
    fn a_consumer_acknowledging_another_services_message_is_not_found() {
        let payroll = consumer_named("payroll", DataClassLevel::Internal);
        let bench = bench(
            subscription_of(&payroll, &topic_named("payments.settled")),
            billing_sync(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = ack(&bench, &itself(), "r-1");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(bench.bus.settled().is_empty());
    }

    /// A person with only messaging-view permission cannot acknowledge a
    /// delivery, and nothing is settled.
    #[test]
    fn a_person_who_may_not_consume_is_refused() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::View)]);
        let bench = bench(
            subscription_of(&billing_sync(), &topic_named("orders.created")),
            billing_sync(),
            viewer,
        );

        let result = ack(&bench, &person(), "r-1");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(bench.bus.settled().is_empty());
    }

    /// A signed-out person receives unauthenticated when acknowledging a delivery.
    #[test]
    fn a_signed_out_person_is_refused() {
        let bench = bench(
            subscription_of(&billing_sync(), &topic_named("orders.created")),
            billing_sync(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = ack(&bench, &person(), "r-1");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A subscription the tenant does not have is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let bench = Bench {
            id: MessageSubscriptionId::new(),
            ..bench(
                subscription_of(&billing_sync(), &topic_named("orders.created")),
                billing_sync(),
                FakeTenantAuthorities::holding_everything(),
            )
        };

        let result = ack(&bench, &person(), "r-1");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
