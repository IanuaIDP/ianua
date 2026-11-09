//! Create subscription: subscribe a service to a topic.

use std::sync::Arc;

use ianua_domain::domains::consumers::authority::ConsumerAuthority;
use ianua_domain::domains::messaging::control::MessagingControl;
use ianua_domain::domains::messaging::delivery::{AckPolicy, SubscriptionDelivery};
use ianua_domain::domains::messaging::message_type::MessageFilter;
use ianua_domain::domains::messaging::subscription::{
    ConsumerGroup, CreateSubscriptionParams, Subscriber, Subscription,
};
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConsumerId, MessageSubscriptionId, PublicHttpsUrl, Setting};

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::authentication::{SealedFor, SecretEncryptor};
use crate::ports::consumers::ConsumerStore;
use crate::ports::limits::{LimitEnforcer, PlanLimitsSource, ResourceKind};
use crate::ports::messaging::{
    MessageConsumer, PushSecretGenerator, SubscriptionStore, TopicStore,
};
use crate::services::lookup::existing_consumer;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::messaging::bus::{close_consumer, open_consumer};
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};
use crate::use_cases::messaging::lookup::existing_named_topic;
use crate::use_cases::messaging::push_secret::{fresh_push_secret, push_secret_place};

/// How many of a service's subscriptions are read at a time while looking
/// for one to the same topic.
const SUBSCRIPTION_PAGE: u32 = 500;

/// How the new subscription's messages are to reach its service.
pub enum DeliveryChoice {
    /// The service pulls them.
    Pull,
    /// They are posted to this address, signed with a secret made for the
    /// subscription.
    Push(PublicHttpsUrl),
}

/// Request to create a new subscription.
pub struct CreateRequest {
    /// The topic to subscribe to.
    pub topic_name: TopicName,
    /// The service subscribed: one of the tenant's, for a person, or the
    /// consumer calling, for a consumer.
    pub subscriber: ConsumerId,
    /// Consumer group name (services in the same group share load).
    pub consumer_group: Setting<ConsumerGroup>,
    /// How messages are delivered.
    pub delivery: DeliveryChoice,
    /// How long a message waits for its acknowledgement, and after how many
    /// deliveries it is set aside.
    pub ack_policy: AckPolicy,
    /// Optional filter on message types.
    pub filter: Setting<MessageFilter>,
}

/// How the new subscription delivers, with what its maker sees once.
pub enum CreatedDelivery {
    /// It is pulled, and has no secret.
    Pull,
    /// It is pushed, signed with this secret. Shown now and never again.
    Push {
        /// The raw signing secret, for the service to check pushes with.
        signing_secret: Secret,
    },
}

/// A subscription just made.
pub struct CreatedSubscription {
    /// The new subscription.
    pub subscription_id: MessageSubscriptionId,
    /// How it delivers, with its push secret shown once.
    pub delivery: CreatedDelivery,
}

/// Ports needed by the create subscription use case.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Port for topic lookup.
    pub topic_store: Arc<dyn TopicStore>,
    /// Port for subscription persistence.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// Port for creating bus consumers.
    pub message_consumer: Arc<dyn MessageConsumer>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The tenant's consumers, which a person enrols.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What a consumer's roles give it once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
    /// Makes a push subscription's signing secret.
    pub push_secrets: Arc<dyn PushSecretGenerator>,
    /// Seals the push secret before it is stored.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Reads the tenant's plan, which a consumer's call does not carry.
    pub plan_limits: Arc<dyn PlanLimitsSource>,
    /// Counts the tenant's subscriptions against its plan.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
}

/// Connects a service to a topic under the caller's messaging authority.
pub struct CreateUseCase {
    ports: CreatePorts,
}

/// Who subscribes, in which tenant, and to which topic.
struct Subscribing<'a> {
    /// The tenant the subscription is made in.
    tenant: &'a ScopedTenant,
    /// The person or consumer subscribing.
    actor: &'a MessagingActor,
    /// The topic subscribed to.
    topic: &'a Topic<ResolvedTenant>,
}

impl CreateUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// The subscription `req` asks for, made by `actor`, with what its
    /// maker is shown of how it delivers.
    async fn new_subscription(
        &self,
        tenant: &ScopedTenant,
        actor: &MessagingActor,
        topic: &Topic<ResolvedTenant>,
        req: CreateRequest,
    ) -> Result<(Subscription<ResolvedTenant>, CreatedDelivery), AppError> {
        let id = MessageSubscriptionId::new();
        let place = push_secret_place(tenant, &id);
        let (delivery, shown) = self.delivery_for(req.delivery, &place).await?;
        let params = CreateSubscriptionParams {
            id,
            consumer_group: req.consumer_group,
            delivery,
            ack_policy: req.ack_policy,
            filter: req.filter,
        };
        let to = Subscribing {
            tenant,
            actor,
            topic,
        };
        let made = self.subscribed(to, &req.subscriber, params).await?;
        Ok((made, shown))
    }

    /// How a subscription delivers when `choice` is made: a push gets a
    /// fresh secret, sealed for the subscription at `place` and shown once.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when no secret can be made or sealed.
    async fn delivery_for(
        &self,
        choice: DeliveryChoice,
        place: &SealedFor,
    ) -> Result<(SubscriptionDelivery, CreatedDelivery), AppError> {
        let DeliveryChoice::Push(url) = choice else {
            return Ok((SubscriptionDelivery::Pull, CreatedDelivery::Pull));
        };
        let fresh = fresh_push_secret(
            self.ports.push_secrets.as_ref(),
            self.ports.encryptor.as_ref(),
            place,
        )
        .await?;
        let (endpoint, signing_secret) = fresh.endpoint_at(url);
        Ok((
            SubscriptionDelivery::Push(endpoint),
            CreatedDelivery::Push { signing_secret },
        ))
    }

    /// `subscriber` subscribed to the topic `to` names by its actor: a
    /// person enrolling one of the tenant's services, or a consumer
    /// subscribing itself.
    async fn subscribed(
        &self,
        to: Subscribing<'_>,
        subscriber: &ConsumerId,
        params: CreateSubscriptionParams,
    ) -> Result<Subscription<ResolvedTenant>, AppError> {
        let Subscribing {
            tenant,
            actor,
            topic,
        } = to;
        let made = match actor {
            MessagingActor::Consumer(authority) => {
                ensure_subscribes_itself(authority, subscriber)?;
                Subscription::create(topic, params, Subscriber::Itself(authority))
            }
            MessagingActor::Person(authority) => {
                let consumer =
                    existing_consumer(self.ports.consumer_store.as_ref(), tenant, subscriber)
                        .await?;
                let by = MessagingControl::new(authority);
                let enrolled = Subscriber::Enrolled {
                    by: &by,
                    consumer: &consumer,
                };
                Subscription::create(topic, params, enrolled)
            }
        };
        made.map_err(AppError::from_domain)
    }

    /// Refuses one more subscription once the tenant's plan holds as many
    /// as it allows. The plan is read for the tenant, as a consumer calling
    /// with its own credential brings none.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the plan's limit is reached.
    /// - `AppError::NotFound` when the tenant or its organization is gone.
    /// - `AppError::Internal` when the plan or the count cannot be read.
    async fn ensure_within_plan(&self, tenant: &ScopedTenant) -> Result<(), AppError> {
        let plan = self
            .ports
            .plan_limits
            .for_tenant(tenant)
            .await
            .map_err(AppError::from_domain)?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(&plan, tenant, ResourceKind::MessageSubscriptions)
            .await
            .map_err(AppError::from_domain)
    }

    /// Refuses a second subscription by the same service to the same topic.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` if the service is already subscribed.
    /// - `AppError::Internal` on storage failure.
    async fn ensure_not_subscribed(
        &self,
        tenant: &ScopedTenant,
        subscription: &Subscription<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let sort = SortOrder::default();
        let mut next = Some(PageRequest::first(Limit::internal(SUBSCRIPTION_PAGE)));
        while let Some(asked) = next.take() {
            let found = self
                .ports
                .subscription_store
                .list_by_service(tenant, subscription.consumer_id(), &sort, &asked)
                .await
                .or_internal()?;
            if found
                .items
                .iter()
                .any(|held| held.topic_name() == subscription.topic_name())
            {
                return Err(AppError::Conflict(message!(
                    "messaging-service-already-subscribed-to",
                    format!(
                        "service already subscribed to '{}'",
                        subscription.topic_name()
                    )
                )));
            }
            next = asked.following(&found);
        }
        Ok(())
    }

    /// Refuses a subscription joining a consumer group whose subscriptions
    /// filter or acknowledge otherwise, as the group reads through one
    /// consumer.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when the group reads otherwise.
    /// - `AppError::Internal` on storage failure.
    async fn ensure_fits_group(
        &self,
        tenant: &ScopedTenant,
        subscription: &Subscription<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let Some(group) = subscription.consumer_group() else {
            return Ok(());
        };
        let member = self
            .ports
            .subscription_store
            .other_in_group(tenant, subscription.topic_name(), group, subscription.id())
            .await
            .or_internal()?;
        let Some(member) = member else {
            return Ok(());
        };
        subscription
            .ensure_reads_like(&member)
            .map_err(AppError::from_domain)
    }

    /// Opens the bus consumer `subscription` reads through, then saves the
    /// subscription, removing the consumer again if the save fails.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the bus or the store refuses.
    async fn keep_with_bus_consumer(
        &self,
        tenant: &ScopedTenant,
        subscription: &Subscription<ResolvedTenant>,
    ) -> Result<(), AppError> {
        open_consumer(self.ports.message_consumer.as_ref(), tenant, subscription).await?;
        let saved = self
            .ports
            .subscription_store
            .save(tenant, subscription)
            .await;
        let Err(failure) = saved else {
            return Ok(());
        };
        self.abandon(tenant, subscription).await;
        Err(AppError::internal(failure))
    }

    /// Removes the bus consumer of a subscription that could not be saved,
    /// so none is left behind. A failure here only leaves an idle consumer,
    /// which making the subscription again reuses, so it is logged.
    async fn abandon(&self, tenant: &ScopedTenant, subscription: &Subscription<ResolvedTenant>) {
        let closed = close_consumer(
            self.ports.message_consumer.as_ref(),
            self.ports.subscription_store.as_ref(),
            tenant,
            subscription,
        )
        .await;
        if let Err(failure) = closed {
            tracing::warn!(
                subscription_id = %subscription.id(),
                error = %failure,
                "an unsaved subscription's bus consumer could not be removed"
            );
        }
    }
}

impl Command for CreateUseCase {
    type Caller = MessagingCaller;
    type Input = CreateRequest;
    type Output = Result<CreatedSubscription, AppError>;

    /// Creates a subscription for a service to a topic and its bus consumer.
    /// The bus consumer is made first, waiting as long as the policy says
    /// for each acknowledgement, and removed again if the subscription
    /// cannot be saved, so a saved subscription always has one. A push
    /// subscription gets a fresh signing secret, stored sealed and shown
    /// here once; the record never holds it. Records
    /// `messaging.subscription_created`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid session/key/consumer credential; `NotFound` for a missing topic/service.
    /// - `AppError::Forbidden` for missing creation rights, a consumer's foreign service, a disabled service, insufficient clearance or a full plan.
    /// - `AppError::Domain` for an archived topic; `Conflict` for an existing subscription or incompatible consumer-group filtering/acknowledgement.
    /// - `AppError::Internal` on persistence, bus, secret or audit failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        auditor: &RequestAuditor,
        req: CreateRequest,
    ) -> Result<CreatedSubscription, AppError> {
        let tenant = caller.tenant();
        let actor = MessagingActor::of(
            caller,
            self.ports.tenant_authorities.as_ref(),
            self.ports.consumers.as_ref(),
        )
        .await?;
        let topic =
            existing_named_topic(self.ports.topic_store.as_ref(), &tenant, &req.topic_name).await?;
        let (mut subscription, delivery) =
            self.new_subscription(&tenant, &actor, &topic, req).await?;
        self.ensure_within_plan(&tenant).await?;
        self.ensure_not_subscribed(&tenant, &subscription).await?;
        self.ensure_fits_group(&tenant, &subscription).await?;
        self.keep_with_bus_consumer(&tenant, &subscription).await?;

        auditor
            .dispatch_by(&actor.actor(), subscription.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(CreatedSubscription {
            subscription_id: *subscription.id(),
            delivery,
        })
    }
}

/// Refuses a consumer subscribing a service other than itself.
///
/// # Errors
///
/// `AppError::Forbidden` when `subscriber` is another service.
fn ensure_subscribes_itself(
    authority: &ConsumerAuthority,
    subscriber: &ConsumerId,
) -> Result<(), AppError> {
    if authority.id() != subscriber {
        return Err(AppError::Forbidden(message!(
            "messaging-a-service-subscribes-only-itself",
            "a service subscribes only itself"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::consumers::consumer::Consumer;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::Seconds;

    use super::*;
    use crate::ports::messaging::Acknowledgement;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::consumers::{
        billing_sync, consumers_of_test_tenant, disabled_billing_sync, key_caller, sign_in_of,
        test_key_digest,
    };
    use crate::test_support::messaging::{
        FakeMessageConsumer, FakePushSecretGenerator, FakeSubscriptionStore, FakeTopicStore,
        TEST_PUSH_URL, archived_topic, grouped_subscription_of, push_secret_place,
        stored_subscription, subscription_of, topic_classed, topic_named, topics_of_test_tenant,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeLimitEnforcer, RejectingLimitEnforcer, block_on,
        test_auditor, test_ctx,
    };
    use crate::use_cases::messaging::bus::consumer_name;

    const CREATE: SystemPermission = SystemPermission::Messaging(MessagingAction::Create);

    struct Bench {
        use_case: CreateUseCase,
        subscriptions: Arc<FakeSubscriptionStore>,
        bus: Arc<FakeMessageConsumer>,
    }

    fn bench(
        topic: Topic<ResolvedTenant>,
        consumer: Consumer<ResolvedTenant>,
        people: FakeTenantAuthorities,
    ) -> Bench {
        bench_over(topics_of_test_tenant(topic), consumer, people)
    }

    fn bench_over(
        topics: Arc<FakeTopicStore>,
        consumer: Consumer<ResolvedTenant>,
        people: FakeTenantAuthorities,
    ) -> Bench {
        bench_limited(topics, consumer, people, Arc::new(FakeLimitEnforcer))
    }

    fn bench_limited(
        topics: Arc<FakeTopicStore>,
        consumer: Consumer<ResolvedTenant>,
        people: FakeTenantAuthorities,
        limits: Arc<dyn LimitEnforcer>,
    ) -> Bench {
        let subscriptions = Arc::new(FakeSubscriptionStore::empty());
        let bus = Arc::new(FakeMessageConsumer::empty());
        let use_case = CreateUseCase::new(CreatePorts {
            topic_store: topics,
            subscription_store: subscriptions.clone(),
            message_consumer: bus.clone(),
            tenant_authorities: Arc::new(people),
            consumer_store: consumers_of_test_tenant(consumer.clone()),
            consumers: sign_in_of(consumer, &[CREATE]),
            push_secrets: Arc::new(FakePushSecretGenerator::new()),
            encryptor: Arc::new(FakeEncryptor),
            plan_limits: Fake::fake(),
            limit_enforcer: limits,
        });
        Bench {
            use_case,
            subscriptions,
            bus,
        }
    }

    fn request(topic: &str, subscriber: ConsumerId) -> CreateRequest {
        CreateRequest {
            topic_name: TopicName::new(topic).unwrap(),
            subscriber,
            consumer_group: Setting::Unset,
            delivery: DeliveryChoice::Pull,
            ack_policy: AckPolicy::standard(),
            filter: Setting::Unset,
        }
    }

    fn push_request(topic: &str, subscriber: ConsumerId) -> CreateRequest {
        CreateRequest {
            delivery: DeliveryChoice::Push(PublicHttpsUrl::new(TEST_PUSH_URL).unwrap()),
            ..request(topic, subscriber)
        }
    }

    fn person() -> MessagingCaller {
        MessagingCaller::Person(test_ctx())
    }

    fn itself() -> MessagingCaller {
        MessagingCaller::Consumer(key_caller(test_key_digest()))
    }

    fn run(
        bench: &Bench,
        caller: &MessagingCaller,
        req: CreateRequest,
    ) -> (
        Result<CreatedSubscription, AppError>,
        Arc<FakeEventDispatcher>,
    ) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(
            bench
                .use_case
                .execute(caller, &test_auditor(audit.clone()), req),
        );
        (result, audit)
    }

    /// Ann subscribes "billing-sync" to `orders.created`. The subscription
    /// is kept, its bus consumer is open, and it is on record.
    #[test]
    fn a_person_subscribes_a_service_and_it_is_recorded() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench(
            topic_named("orders.created"),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, audit) = run(&bench, &person(), request("orders.created", id));

        result.unwrap();
        assert_eq!(bench.subscriptions.count(), 1);
        assert_eq!(bench.bus.open_in(test_ctx().tenant_id()).len(), 1);
        assert_eq!(
            audit.records.lock().unwrap()[0],
            "messaging.subscription_created"
        );
    }

    fn grouped_request(subscriber: ConsumerId, filter: Setting<MessageFilter>) -> CreateRequest {
        CreateRequest {
            consumer_group: Setting::Set(ConsumerGroup::new("payment-workers").unwrap()),
            filter,
            ..request("orders.created", subscriber)
        }
    }

    fn bench_with_group_member() -> (Bench, ConsumerId) {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench(
            topic_named("orders.created"),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );
        let member = grouped_subscription_of(
            &billing_sync(),
            &topic_named("orders.created"),
            "payment-workers",
        );
        block_on(bench.subscriptions.save(&test_ctx().tenant(), &member)).unwrap();
        bench
            .bus
            .open(test_ctx().tenant_id(), &consumer_name(&member));
        (bench, id)
    }

    /// A second payment worker joins the group. It reads through the
    /// group's one consumer, so no second consumer is opened.
    #[test]
    fn a_service_joining_a_group_shares_its_consumer() {
        let (bench, id) = bench_with_group_member();

        let (result, _) = run(&bench, &person(), grouped_request(id, Setting::Unset));

        result.unwrap();
        assert_eq!(bench.subscriptions.count(), 2);
        assert_eq!(bench.bus.open_in(test_ctx().tenant_id()).len(), 1);
    }

    /// Joining an unfiltered consumer group with a refund filter returns a
    /// conflict and leaves only the existing subscription stored.
    #[test]
    fn a_service_joining_a_group_with_another_filter_is_refused() {
        let (bench, id) = bench_with_group_member();
        let refunds = Setting::Set(MessageFilter::new("order.refund").unwrap());

        let (result, _) = run(&bench, &person(), grouped_request(id, refunds));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(bench.subscriptions.count(), 1);
    }

    /// Ann has "billing-sync"'s orders pushed to its endpoint. She is shown
    /// the new signing secret once; the subscription keeps it only sealed.
    #[test]
    fn a_push_subscription_shows_its_secret_once_and_keeps_it_sealed() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench(
            topic_named("orders.created"),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, _) = run(&bench, &person(), push_request("orders.created", id));

        let created = result.unwrap();
        let CreatedDelivery::Push { signing_secret } = created.delivery else {
            panic!("a push subscription shows its secret");
        };
        assert_eq!(signing_secret.expose(), "push-secret-1");
        let stored = stored_subscription(&bench.subscriptions, &created.subscription_id);
        let SubscriptionDelivery::Push(endpoint) = stored.delivery() else {
            panic!("the subscription is pushed");
        };
        assert_eq!(endpoint.url().as_str(), TEST_PUSH_URL);
        assert_eq!(
            endpoint.signing_secret(),
            &FakeEncryptor::sealed_for(
                "push-secret-1",
                &push_secret_place(&created.subscription_id)
            )
        );
    }

    /// A pulled subscription signs nothing, so no secret is shown.
    #[test]
    fn a_pull_subscription_shows_no_secret() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench(
            topic_named("orders.created"),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, _) = run(&bench, &person(), request("orders.created", id));

        assert!(matches!(result.unwrap().delivery, CreatedDelivery::Pull));
    }

    /// Ann gives the subscription a minute for each acknowledgement and ten
    /// deliveries. Its bus consumer waits that minute before handing a
    /// message out again.
    #[test]
    fn the_bus_consumer_waits_as_long_as_the_policy_says() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench(
            topic_named("orders.created"),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );
        let req = CreateRequest {
            ack_policy: AckPolicy::new(Seconds::new(60), 10).unwrap(),
            ..request("orders.created", id)
        };

        let (result, _) = run(&bench, &person(), req);

        let stored = stored_subscription(&bench.subscriptions, &result.unwrap().subscription_id);
        assert_eq!(stored.ack_policy().max_deliveries(), 10);
        assert_eq!(
            bench.bus.acknowledgement_of(&consumer_name(&stored)),
            Some(Acknowledgement::Explicit {
                deadline: Seconds::new(60)
            })
        );
    }

    /// "billing-sync" holds a role that may create in messaging. It
    /// subscribes itself with its own key.
    #[test]
    fn a_consumer_subscribes_itself() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench(
            topic_named("orders.created"),
            consumer,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let (result, _) = run(&bench, &itself(), request("orders.created", id));

        let stored = block_on(
            bench
                .subscriptions
                .find_by_id(&test_ctx().tenant(), &result.unwrap().subscription_id),
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored.consumer_id(), &id);
    }

    /// An authenticated consumer cannot subscribe another service; the
    /// forbidden request saves no subscription.
    #[test]
    fn a_consumer_subscribing_another_service_is_refused() {
        let bench = bench(
            topic_named("orders.created"),
            billing_sync(),
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, _) = run(
            &bench,
            &itself(),
            request("orders.created", ConsumerId::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.subscriptions.count(), 0);
    }

    /// A consumer cleared for internal data cannot subscribe itself to a
    /// restricted topic; the forbidden request opens no bus consumer.
    #[test]
    fn a_topic_above_the_services_clearance_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench(
            topic_classed("payroll.salaries", DataClassLevel::Restricted),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, _) = run(&bench, &itself(), request("payroll.salaries", id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(bench.bus.open_in(test_ctx().tenant_id()).is_empty());
    }

    /// Enrolling a disabled service in a topic returns a forbidden error.
    #[test]
    fn a_disabled_service_is_subscribed_to_nothing() {
        let consumer = disabled_billing_sync();
        let id = *consumer.id();
        let bench = bench(
            topic_named("orders.created"),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, _) = run(&bench, &person(), request("orders.created", id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A person with messaging view rights cannot enroll a service in a
    /// topic; the forbidden request saves no subscription.
    #[test]
    fn a_person_without_the_create_right_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::View)]);
        let bench = bench(topic_named("orders.created"), consumer, viewer);

        let (result, _) = run(&bench, &person(), request("orders.created", id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.subscriptions.count(), 0);
    }

    /// A signed-out person receives an unauthenticated error when enrolling
    /// a service in a topic.
    #[test]
    fn a_signed_out_person_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench(
            topic_named("orders.created"),
            consumer,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let (result, _) = run(&bench, &person(), request("orders.created", id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A topic the tenant does not have is not found.
    #[test]
    fn subscribing_to_an_unknown_topic_is_not_found() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench_over(
            Arc::new(FakeTopicStore::empty()),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, _) = run(&bench, &person(), request("ghost.topic", id));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A service the tenant does not have is not found.
    #[test]
    fn subscribing_an_unknown_service_is_not_found() {
        let bench = bench(
            topic_named("orders.created"),
            billing_sync(),
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, _) = run(
            &bench,
            &person(),
            request("orders.created", ConsumerId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// "billing-sync" already subscribes to `orders.created`. A second
    /// subscription is refused as a conflict.
    #[test]
    fn a_second_subscription_to_the_same_topic_is_a_conflict() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let topic = topic_named("orders.created");
        let existing = subscription_of(&consumer, &topic);
        let bench = bench(topic, consumer, FakeTenantAuthorities::holding_everything());
        block_on(bench.subscriptions.save(&test_ctx().tenant(), &existing)).unwrap();

        let (result, _) = run(&bench, &person(), request("orders.created", id));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(bench.subscriptions.count(), 1);
    }

    /// Acme's tenant already holds as many subscriptions as its plan allows.
    /// "billing-sync" subscribing itself to one more is refused, and no bus
    /// consumer is opened.
    #[test]
    fn a_subscription_past_the_plan_limit_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench_limited(
            topics_of_test_tenant(topic_named("orders.created")),
            consumer,
            FakeTenantAuthorities::holding_everything(),
            Arc::new(RejectingLimitEnforcer),
        );

        let (result, audit) = run(&bench, &itself(), request("orders.created", id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.subscriptions.count(), 0);
        assert!(bench.bus.open_in(test_ctx().tenant_id()).is_empty());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Enrolling a service in an archived topic returns an invalid-transition
    /// domain error.
    #[test]
    fn an_archived_topic_takes_no_subscription() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let bench = bench(
            archived_topic("old.topic"),
            consumer,
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, _) = run(&bench, &person(), request("old.topic", id));

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::InvalidTransition(_)))
        ));
    }
}
