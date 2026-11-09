//! Push message: post one message a push subscription handed out to its
//! service's endpoint, and settle it by how the post ended.

use std::sync::Arc;

use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::messaging::delivery::{MessageFate, PushEndpoint, SubscriptionDelivery};
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::MessageSubscriptionId;

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::consumers::ConsumerStore;
use crate::ports::messaging::{
    MessageConsumer, OutgoingPush, PendingMessage, PushDeliverer, PushOutcome, SubscriptionStore,
    TopicStore,
};
use crate::services::sealing::opened_secrets;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::messaging::bus::consumer_name;
use crate::use_cases::messaging::lookup::existing_subscription;
use crate::use_cases::messaging::push_secret::push_secret_place;
use crate::use_cases::messaging::settling::{fate_on_arrival, set_aside, settle_refused};

/// A pending delivery paired with the subscription whose endpoint receives it.
pub struct PushMessageRequest {
    /// The push subscription it was fetched for.
    pub subscription_id: MessageSubscriptionId,
    /// The message, as the subscription's consumer handed it out.
    pub message: PendingMessage,
}

/// What came of one push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushReport {
    /// The subscription is paused: nothing was posted, and the message
    /// waits for its deadline.
    Waiting,
    /// The service is gone, disabled, or no longer cleared for the topic's
    /// data: nothing was posted, and the message waits for its deadline.
    Withheld,
    /// The topic's age limit passed while the message waited its turn:
    /// nothing was posted, and it is taken.
    Expired,
    /// The endpoint took it, and it is acknowledged.
    Taken,
    /// The post failed, and the message comes round again or was set aside.
    Failed(MessageFate),
    /// Its deliveries were spent before this one, so it was set aside
    /// without a post.
    SetAside,
}

/// The ports [`PushMessageUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PushMessagePorts {
    /// Where subscriptions are kept.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// The topics, whose class each push is checked against now.
    pub topic_store: Arc<dyn TopicStore>,
    /// The tenant's services, each checked as it is stored now.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// The bus the message waits on.
    pub message_consumer: Arc<dyn MessageConsumer>,
    /// Posts the signed message, refusing internal addresses.
    pub deliverer: Arc<dyn PushDeliverer>,
    /// Opens the subscription's sealed signing secrets.
    pub encryptor: Arc<dyn SecretEncryptor>,
}

/// Pushes one message to one subscription's endpoint.
pub struct PushMessageUseCase {
    ports: PushMessagePorts,
}

impl PushMessageUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PushMessagePorts) -> Self {
        Self { ports }
    }

    /// The topic `sub`'s service may still be pushed the messages of: it
    /// and the topic still exist, it is enabled, and it is cleared for the
    /// topic's class as both are stored now. `None` withholds the push,
    /// and is logged by the subscription's id.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a store fails.
    async fn pushable_topic(
        &self,
        tenant: &ScopedTenant,
        sub: &Subscription<ResolvedTenant>,
    ) -> Result<Option<Topic<ResolvedTenant>>, AppError> {
        let Some((topic, service)) = self.stored_ends(tenant, sub).await? else {
            tracing::warn!(
                subscription_id = %sub.id(),
                "a push to a missing topic or service was withheld"
            );
            return Ok(None);
        };
        let Err(refusal) = sub.ensure_pushable(&topic, &service) else {
            return Ok(Some(topic));
        };
        tracing::warn!(
            subscription_id = %sub.id(),
            error = %refusal,
            "a push was withheld"
        );
        Ok(None)
    }

    /// Ends `message`, whose age limit passed while it waited, without a
    /// post.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the bus refuses.
    async fn taken_unposted(
        &self,
        tenant: &ScopedTenant,
        sub: &Subscription<ResolvedTenant>,
        message: &PendingMessage,
    ) -> Result<PushReport, AppError> {
        self.ports
            .message_consumer
            .acknowledge(
                tenant,
                sub.topic_name(),
                &consumer_name(sub),
                &message.receipt,
            )
            .await
            .or_internal()?;
        Ok(PushReport::Expired)
    }

    /// The topic `sub` consumes and the service it delivers to, as both are
    /// stored now, or `None` when either is gone.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a store fails.
    async fn stored_ends(
        &self,
        tenant: &ScopedTenant,
        sub: &Subscription<ResolvedTenant>,
    ) -> Result<Option<(Topic<ResolvedTenant>, Consumer<ResolvedTenant>)>, AppError> {
        let topic = self
            .ports
            .topic_store
            .find_by_name(tenant, sub.topic_name())
            .await
            .or_internal()?;
        let service = self
            .ports
            .consumer_store
            .find_by_id(tenant, sub.consumer_id())
            .await
            .or_internal()?;
        Ok(topic.zip(service))
    }

    /// Posts `message` to `endpoint`, signed with every secret that still
    /// signs, giving the endpoint the subscription's acknowledgement
    /// deadline to answer. A post the deliverer refuses, such as to an
    /// address that resolves inside the platform, counts as failed.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a secret cannot be opened.
    async fn posted(
        &self,
        tenant: &ScopedTenant,
        sub: &Subscription<ResolvedTenant>,
        endpoint: &PushEndpoint,
        message: &PendingMessage,
    ) -> Result<PushOutcome, AppError> {
        let secrets = opened_secrets(
            self.ports.encryptor.as_ref(),
            endpoint.signing_secrets(clock::now()),
            &push_secret_place(tenant, sub.id()),
        )
        .await?;
        let push = OutgoingPush {
            url: endpoint.url(),
            message: &message.message,
            secrets: &secrets,
            timeout: sub.ack_policy().ack_deadline(),
        };
        let posted = self.ports.deliverer.push(push).await;
        Ok(posted.unwrap_or_else(|refusal| {
            tracing::warn!(
                subscription_id = %sub.id(),
                error = %refusal,
                "a push was refused before it was sent"
            );
            PushOutcome::Failed
        }))
    }

    /// Settles `message` by how its post ended: acknowledged when taken,
    /// otherwise delivered again or set aside as the policy decides.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the bus refuses.
    async fn settled(
        &self,
        tenant: &ScopedTenant,
        sub: &Subscription<ResolvedTenant>,
        message: &PendingMessage,
        outcome: PushOutcome,
    ) -> Result<PushReport, AppError> {
        let bus = self.ports.message_consumer.as_ref();
        match outcome {
            PushOutcome::Accepted => {
                bus.acknowledge(
                    tenant,
                    sub.topic_name(),
                    &consumer_name(sub),
                    &message.receipt,
                )
                .await
                .or_internal()?;
                Ok(PushReport::Taken)
            }
            PushOutcome::Failed => {
                let fate =
                    settle_refused(bus, tenant, sub, &message.receipt, message.delivered).await?;
                Ok(PushReport::Failed(fate))
            }
        }
    }
}

impl Query for PushMessageUseCase {
    type Caller = ScopedTenant;
    type Input = PushMessageRequest;
    type Output = Result<PushReport, AppError>;

    /// Posts the message to the subscription's endpoint and settles it: an
    /// accepted post acknowledges it; a failed one leaves it to the
    /// subscription's policy, which delivers it again or sets it aside. A
    /// message whose deliveries were already spent is set aside without a
    /// post, and a paused subscription posts nothing. A message that aged
    /// past the topic's limit while waiting its turn in the batch is taken
    /// without a post.
    ///
    /// A push has no caller whose clearance a pull would check, so the
    /// service is checked on every push instead: one since disabled, or no
    /// longer cleared for the topic's class, is posted nothing. Settling
    /// changes no record of the tenant's, so nothing is put on record.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant has no such subscription.
    /// - `AppError::Conflict` when the subscription is pulled.
    /// - `AppError::Internal` on storage, secret or bus failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: PushMessageRequest,
    ) -> Result<PushReport, AppError> {
        let store = self.ports.subscription_store.as_ref();
        let sub = existing_subscription(store, tenant, &request.subscription_id).await?;
        let endpoint = pushed_endpoint(&sub)?;
        if !sub.is_active() {
            return Ok(PushReport::Waiting);
        }
        let message = request.message;
        if fate_on_arrival(&sub, &message) == MessageFate::DeadLetter {
            let bus = self.ports.message_consumer.as_ref();
            set_aside(bus, tenant, &sub, &message.receipt).await?;
            return Ok(PushReport::SetAside);
        }
        let Some(topic) = self.pushable_topic(tenant, &sub).await? else {
            return Ok(PushReport::Withheld);
        };
        if topic
            .retention()
            .has_aged_out(message.message.published_at, clock::now())
        {
            return self.taken_unposted(tenant, &sub, &message).await;
        }

        let outcome = self.posted(tenant, &sub, endpoint, &message).await?;
        self.settled(tenant, &sub, &message, outcome).await
    }
}

/// Where `sub` pushes to.
///
/// # Errors
///
/// `AppError::Conflict` when the subscription is pulled, not pushed.
fn pushed_endpoint(sub: &Subscription<ResolvedTenant>) -> Result<&PushEndpoint, AppError> {
    let SubscriptionDelivery::Push(endpoint) = sub.delivery() else {
        return Err(AppError::Conflict(message!(
            "messaging-a-pulled-subscription-is-not-pushed",
            "a pulled subscription is not pushed"
        )));
    };
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::messaging::delivery::AckPolicy;
    use ianua_domain::domains::messaging::topic::RetentionPolicy;
    use ianua_domain::types::{Lifetime, RotationOverlap};

    use super::*;
    use crate::ports::messaging::DeliveryReceipt;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::consumers::{
        FakeConsumerStore, billing_sync, consumers_of_test_tenant, switched_off,
    };
    use crate::test_support::messaging::{
        FakeMessageConsumer, FakePushDeliverer, FakeSubscriptionStore, Settlement,
        TEST_PUSH_SECRET, TEST_PUSH_URL, messaging_admin, pending_message, push_secret_place,
        push_subscription_of, subscription_of, topic_classed, topic_named, topics_of_test_tenant,
    };
    use crate::test_support::{block_on, test_ctx};

    struct Bench {
        use_case: PushMessageUseCase,
        bus: Arc<FakeMessageConsumer>,
        deliverer: Arc<FakePushDeliverer>,
        id: MessageSubscriptionId,
        consumer_name: String,
    }

    /// What a push is checked against: the topic and the service as they
    /// are stored now.
    struct Stored {
        topic: Topic<ResolvedTenant>,
        service: Consumer<ResolvedTenant>,
    }

    /// `sub` with one message waiting under receipt `r-1`, posted through
    /// `deliverer`, its topic and service as `stored` holds them.
    fn bench(
        sub: Subscription<ResolvedTenant>,
        stored: Stored,
        deliverer: FakePushDeliverer,
    ) -> Bench {
        let id = *sub.id();
        let name = consumer_name(&sub);
        let bus = Arc::new(FakeMessageConsumer::holding(vec![pending_message(
            "r-1", 1,
        )]));
        bus.open(test_ctx().tenant_id(), &name);
        let deliverer = Arc::new(deliverer);
        let use_case = PushMessageUseCase::new(PushMessagePorts {
            subscription_store: FakeSubscriptionStore::of_test_tenant([sub]),
            topic_store: topics_of_test_tenant(stored.topic),
            consumer_store: consumers_of_test_tenant(stored.service),
            message_consumer: bus.clone(),
            deliverer: deliverer.clone(),
            encryptor: Arc::new(FakeEncryptor),
        });
        Bench {
            use_case,
            bus,
            deliverer,
            id,
            consumer_name: name,
        }
    }

    /// "billing-sync"'s push subscription to `orders.created`, with the
    /// topic and the service as they were when it was made.
    fn pushed() -> (Subscription<ResolvedTenant>, Stored) {
        let (topic, service) = (topic_named("orders.created"), billing_sync());
        let sub = push_subscription_of(&service, &topic);
        (sub, Stored { topic, service })
    }

    /// [`pushed`], posted through `deliverer`.
    fn pushing(deliverer: FakePushDeliverer) -> Bench {
        let (sub, stored) = pushed();
        bench(sub, stored, deliverer)
    }

    fn push(bench: &Bench, delivered: u32) -> Result<PushReport, AppError> {
        let request = PushMessageRequest {
            subscription_id: bench.id,
            message: pending_message("r-1", delivered),
        };
        block_on(bench.use_case.execute(&test_ctx().tenant(), request))
    }

    /// An order is posted to "billing-sync"'s endpoint, signed with its
    /// secret, with the thirty seconds the standard policy gives. The
    /// endpoint takes it, so it is acknowledged; nothing is put on record.
    #[test]
    fn an_accepted_push_is_acknowledged() {
        let bench = pushing(FakePushDeliverer::answering(PushOutcome::Accepted));

        let result = push(&bench, 1);

        assert_eq!(result.unwrap(), PushReport::Taken);
        let made = bench.deliverer.made();
        assert_eq!(made.len(), 1);
        assert_eq!(made[0].url, TEST_PUSH_URL);
        assert_eq!(made[0].secrets, [TEST_PUSH_SECRET]);
        assert_eq!(made[0].timeout, AckPolicy::standard().ack_deadline());
        assert_eq!(
            bench.bus.settled(),
            [(DeliveryReceipt::new("r-1"), Settlement::Acknowledged)]
        );
    }

    /// `orders.created` keeps its messages a minute. An order published
    /// two minutes ago reaches its turn in the batch: it is not posted, and
    /// it is taken so it does not come round again.
    #[test]
    fn a_message_past_its_limit_is_taken_without_a_post() {
        let (sub, mut stored) = pushed();
        let minute = RetentionPolicy::Duration(NonZeroU32::new(60).unwrap());
        let admin = messaging_admin();
        stored.topic.change_retention(minute, &admin).unwrap();
        let bench = bench(
            sub,
            stored,
            FakePushDeliverer::answering(PushOutcome::Accepted),
        );
        let mut message = pending_message("r-1", 1);
        message.message.published_at = clock::now() - time::Duration::minutes(2);

        let report = block_on(bench.use_case.execute(
            &test_ctx().tenant(),
            PushMessageRequest {
                subscription_id: bench.id,
                message,
            },
        ));

        assert_eq!(report.unwrap(), PushReport::Expired);
        assert!(bench.deliverer.made().is_empty());
        assert_eq!(
            bench.bus.settled(),
            [(DeliveryReceipt::new("r-1"), Settlement::Acknowledged)]
        );
    }

    /// Ann rotated the push secret with a day's overlap. Until it ends,
    /// each push is signed with the new secret and the old one, so
    /// "billing-sync" still on the old one accepts it.
    #[test]
    fn a_push_during_a_rotation_overlap_is_signed_with_both_secrets() {
        let (mut sub, stored) = pushed();
        let day = RotationOverlap::For(Lifetime::seconds(86_400).unwrap());
        sub.rotate_push_secret(
            FakeEncryptor::sealed_for("new-push-secret", &push_secret_place(sub.id())),
            day,
            &messaging_admin(),
        )
        .unwrap();
        let bench = bench(
            sub,
            stored,
            FakePushDeliverer::answering(PushOutcome::Accepted),
        );

        push(&bench, 1).unwrap();

        assert_eq!(
            bench.deliverer.made()[0].secrets,
            ["new-push-secret", TEST_PUSH_SECRET]
        );
    }

    /// A stored topic now above its subscriber's clearance withholds the
    /// push without posting or settling the message.
    #[test]
    fn a_push_to_a_service_no_longer_cleared_is_withheld() {
        let (sub, stored) = pushed();
        let raised = Stored {
            topic: topic_classed("orders.created", DataClassLevel::Restricted),
            ..stored
        };
        let bench = bench(
            sub,
            raised,
            FakePushDeliverer::answering(PushOutcome::Accepted),
        );

        let result = push(&bench, 1);

        assert_eq!(result.unwrap(), PushReport::Withheld);
        assert!(bench.deliverer.made().is_empty());
        assert!(bench.bus.settled().is_empty());
    }

    /// Disabling a service after it subscribes withholds its next push and
    /// makes no post.
    #[test]
    fn a_push_to_a_disabled_service_is_withheld() {
        let service = billing_sync();
        let topic = topic_named("orders.created");
        let sub = push_subscription_of(&service, &topic);
        let service = switched_off(service);
        let bench = bench(
            sub,
            Stored { topic, service },
            FakePushDeliverer::answering(PushOutcome::Accepted),
        );

        let result = push(&bench, 1);

        assert_eq!(result.unwrap(), PushReport::Withheld);
        assert!(bench.deliverer.made().is_empty());
    }

    /// A subscription whose service is absent withholds its push and makes
    /// no post to the stored endpoint.
    #[test]
    fn a_push_to_a_service_that_is_gone_is_withheld() {
        let (sub, stored) = pushed();
        let mut bench = bench(
            sub,
            stored,
            FakePushDeliverer::answering(PushOutcome::Accepted),
        );
        bench.use_case.ports.consumer_store = Arc::new(FakeConsumerStore::empty());

        let result = push(&bench, 1);

        assert_eq!(result.unwrap(), PushReport::Withheld);
        assert!(bench.deliverer.made().is_empty());
    }

    /// "billing-sync"'s endpoint is down on the order's second delivery. The
    /// order comes round again.
    #[test]
    fn a_failed_push_with_deliveries_left_comes_round_again() {
        let bench = pushing(FakePushDeliverer::answering(PushOutcome::Failed));

        let result = push(&bench, 2);

        assert_eq!(result.unwrap(), PushReport::Failed(MessageFate::Redeliver));
        assert_eq!(
            bench.bus.settled(),
            [(DeliveryReceipt::new("r-1"), Settlement::Redelivered)]
        );
    }

    /// A failed fifth push reaches the standard delivery limit and stores
    /// the message as a dead letter.
    #[test]
    fn a_push_failing_its_last_delivery_is_set_aside() {
        let bench = pushing(FakePushDeliverer::answering(PushOutcome::Failed));

        let result = push(&bench, 5);

        assert_eq!(result.unwrap(), PushReport::Failed(MessageFate::DeadLetter));
        assert_eq!(bench.bus.dead_letters_of(&bench.consumer_name).len(), 1);
    }

    /// A deliverer rejecting the endpoint address makes no post and reports
    /// the push as failed with redelivery due.
    #[test]
    fn a_push_to_an_internal_address_is_refused_and_counted() {
        let bench = pushing(FakePushDeliverer::refusing_address());

        let result = push(&bench, 1);

        assert_eq!(result.unwrap(), PushReport::Failed(MessageFate::Redeliver));
        assert!(bench.deliverer.made().is_empty());
    }

    /// A sixth delivery already exceeds the standard limit and is stored
    /// as a dead letter without posting it.
    #[test]
    fn a_message_whose_deliveries_are_spent_is_set_aside_without_a_post() {
        let bench = pushing(FakePushDeliverer::answering(PushOutcome::Accepted));

        let result = push(&bench, 6);

        assert_eq!(result.unwrap(), PushReport::SetAside);
        assert!(bench.deliverer.made().is_empty());
        assert_eq!(bench.bus.dead_letters_of(&bench.consumer_name).len(), 1);
    }

    /// Ann paused the subscription while the service is down. Nothing is
    /// posted and nothing is settled.
    #[test]
    fn a_paused_subscription_posts_nothing() {
        let (mut sub, stored) = pushed();
        sub.pause(&messaging_admin()).unwrap();
        let bench = bench(
            sub,
            stored,
            FakePushDeliverer::answering(PushOutcome::Accepted),
        );

        let result = push(&bench, 1);

        assert_eq!(result.unwrap(), PushReport::Waiting);
        assert!(bench.deliverer.made().is_empty());
        assert!(bench.bus.settled().is_empty());
    }

    /// A pulled subscription is not pushed: it is refused as a conflict and
    /// nothing is posted.
    #[test]
    fn a_pulled_subscription_is_not_pushed() {
        let (_, stored) = pushed();
        let sub = subscription_of(&stored.service, &stored.topic);
        let bench = bench(
            sub,
            stored,
            FakePushDeliverer::answering(PushOutcome::Accepted),
        );

        let result = push(&bench, 1);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(bench.deliverer.made().is_empty());
    }

    /// A subscription the tenant does not have is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let bench = Bench {
            id: MessageSubscriptionId::new(),
            ..pushing(FakePushDeliverer::answering(PushOutcome::Accepted))
        };

        let result = push(&bench, 1);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
