//! A service's subscription to a topic.
//!
//! A subscription says how a service receives messages from a topic. Many
//! services can subscribe to the same topic. The message transport keeps
//! how far each one has read, not this module.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::MessagingAction;
use crate::domains::consumers::authority::ConsumerAuthority;
use crate::domains::consumers::consumer::Consumer;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::messaging::control::{MessagingControl, MessagingCreator, MessagingReader};
use crate::domains::messaging::delivery::{AckPolicy, SubscriptionDelivery};
use crate::domains::messaging::events::{
    DeadLetterReplayed, SubscriptionCreated, SubscriptionDeleted, SubscriptionPaused,
    SubscriptionResumed, SubscriptionSecretRotated,
};
use crate::domains::messaging::message_type::MessageFilter;
use crate::domains::messaging::topic::Topic;
use crate::domains::messaging::topic_name::TopicName;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{
    ConsumerId, EventLabel, MessageSubscriptionId, RotationOverlap, SealedSecret, Setting,
};

/// How messages are delivered to the subscriber, without where a push
/// goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeliveryMode {
    /// Messages are posted to the service's push endpoint.
    Push,
    /// The service asks the API for new messages.
    Pull,
}

/// Determines whether messages may be delivered, wait, or have ended delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SubscriptionStatus {
    /// Receiving messages.
    Active,
    /// Messages wait and are not delivered.
    Paused,
}

impl SubscriptionStatus {
    /// Moves to `to`. Active moves to paused and paused to active, nothing
    /// else.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] when the subscription is already in `to`.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!(
                (from, to),
                (Self::Active, Self::Paused) | (Self::Paused, Self::Active)
            )
        })
    }
}

/// What a new subscription is created from, beside the topic itself.
pub struct CreateSubscriptionParams {
    /// The id the subscription is kept under, chosen before it is made so
    /// a push secret can be sealed for it.
    pub id: MessageSubscriptionId,
    /// Consumer group name. Services in the same group share the messages.
    pub consumer_group: Setting<ConsumerGroup>,
    /// How messages are delivered, with where a push goes.
    pub delivery: SubscriptionDelivery,
    /// How long a message waits for its acknowledgement, and when it is
    /// set aside.
    pub ack_policy: AckPolicy,
    /// Optional filter, a dot-separated prefix the message type must start
    /// with.
    pub filter: Setting<MessageFilter>,
}

/// A subscription as storage holds it.
pub struct SubscriptionRow {
    /// Unique identifier.
    pub id: MessageSubscriptionId,
    /// The topic subscribed to.
    pub topic_name: TopicName,
    /// The subscribing service.
    pub consumer_id: ConsumerId,
    /// Consumer group name.
    pub consumer_group: Setting<ConsumerGroup>,
    /// How messages are delivered, with where a push goes.
    pub delivery: SubscriptionDelivery,
    /// How long a message waits for its acknowledgement, and when it is
    /// set aside.
    pub ack_policy: AckPolicy,
    /// Optional filter expression.
    pub filter: Setting<MessageFilter>,
    /// Current status.
    pub status: SubscriptionStatus,
    /// When created.
    pub created_at: OffsetDateTime,
    /// When last paused or resumed.
    pub updated_at: OffsetDateTime,
}

/// A service's subscription to a messaging topic.
///
/// Subscribers in one consumer group share the messages between them.
/// Without a consumer group, each subscriber gets every message.
#[derive(Debug)]
pub struct Subscription<T: TenantScope> {
    id: MessageSubscriptionId,
    topic_name: TopicName,
    consumer_id: ConsumerId,
    consumer_group: Setting<ConsumerGroup>,
    delivery: SubscriptionDelivery,
    ack_policy: AckPolicy,
    filter: Setting<MessageFilter>,
    status: SubscriptionStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Subscription<T> {
    /// Subscribes the service `subscriber` names to `topic`, as a new active
    /// subscription. Raises `messaging.subscription_created`.
    ///
    /// The topic's class must not be above the service's clearance, as the
    /// consumer stores it. A billing service cleared for internal data never
    /// subscribes to a topic of restricted salaries, whoever subscribes it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person, or the service's
    ///   roles, do not give the right to create in messaging.
    /// - [`DomainError::Forbidden`] when a person subscribes a disabled
    ///   service.
    /// - [`DomainError::InvalidTransition`] when the topic is archived.
    /// - [`DomainError::Forbidden`] when the topic's class is above the
    ///   service's clearance.
    pub fn create(
        topic: &Topic<T>,
        params: CreateSubscriptionParams,
        subscriber: Subscriber<'_, T>,
    ) -> Result<Self, DomainError> {
        let (consumer_id, clearance) = subscriber.ensure_may_subscribe()?;
        ensure_subscribable(topic, clearance)?;
        let now = crate::shared::clock::now();
        let mut subscription = Self {
            id: params.id,
            topic_name: topic.topic_name().clone(),
            consumer_id,
            consumer_group: params.consumer_group,
            delivery: params.delivery,
            ack_policy: params.ack_policy,
            filter: params.filter,
            status: SubscriptionStatus::Active,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        subscription.raised.raise(SubscriptionCreated {
            subscription_id: subscription.id,
            subscription_label: subscription.label(),
            topic_name: subscription.topic_name.clone(),
            occurred_at: now,
        });
        Ok(subscription)
    }

    /// Rebuilds a subscription from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it changed before
    ///   it was created.
    pub fn reconstitute(row: SubscriptionRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            topic_name: row.topic_name,
            consumer_id: row.consumer_id,
            consumer_group: row.consumer_group,
            delivery: row.delivery,
            ack_policy: row.ack_policy,
            filter: row.filter,
            status: row.status,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &SubscriptionRow) -> Result<(), DomainError> {
        RowCheck::of("message subscription")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &MessageSubscriptionId {
        &self.id
    }

    /// The topic subscribed to.
    #[must_use]
    pub fn topic_name(&self) -> &TopicName {
        &self.topic_name
    }

    /// The subscribing service.
    #[must_use]
    pub fn consumer_id(&self) -> &ConsumerId {
        &self.consumer_id
    }

    /// Consumer group name.
    #[must_use]
    pub fn consumer_group(&self) -> Option<&ConsumerGroup> {
        self.consumer_group.value()
    }

    /// How messages are delivered.
    #[must_use]
    pub fn delivery_mode(&self) -> DeliveryMode {
        match self.delivery {
            SubscriptionDelivery::Pull => DeliveryMode::Pull,
            SubscriptionDelivery::Push(_) => DeliveryMode::Push,
        }
    }

    /// How messages are delivered, with where a push goes and what signs
    /// it.
    #[must_use]
    pub fn delivery(&self) -> &SubscriptionDelivery {
        &self.delivery
    }

    /// How long a message waits for its acknowledgement, and when it is
    /// set aside as a dead letter.
    #[must_use]
    pub fn ack_policy(&self) -> &AckPolicy {
        &self.ack_policy
    }

    /// Optional filter expression.
    #[must_use]
    pub fn filter(&self) -> Option<&MessageFilter> {
        self.filter.value()
    }

    /// Refuses this subscription joining the group `member` belongs to
    /// unless the two read alike. A group reads through one consumer, so its
    /// subscriptions take the same message types and wait as long for each
    /// acknowledgement; a member that read otherwise would quietly read as
    /// the first one does.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] when `member` is of another group or topic,
    /// or filters or acknowledges otherwise.
    pub fn ensure_reads_like<U: TenantScope>(
        &self,
        member: &Subscription<U>,
    ) -> Result<(), DomainError> {
        let same_group = self.topic_name == member.topic_name
            && self.consumer_group() == member.consumer_group();
        let reads_alike = self.filter() == member.filter() && self.ack_policy == member.ack_policy;
        match same_group && reads_alike {
            true => Ok(()),
            false => Err(DomainError::conflict(message!(
                "messaging-a-consumer-group-s-subscriptions-filter",
                "a consumer group's subscriptions filter and acknowledge alike"
            ))),
        }
    }

    /// Current status.
    #[must_use]
    pub fn status(&self) -> SubscriptionStatus {
        self.status
    }

    /// Whether this subscription is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == SubscriptionStatus::Active
    }

    /// Pauses the subscription. Messages wait and are not delivered. It
    /// stops a service hearing what it depends on, so this needs the full
    /// messaging right. Raises `messaging.subscription_paused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   messaging.
    /// - [`DomainError::InvalidTransition`] when it is already paused.
    pub fn pause(&mut self, control: &MessagingControl<'_>) -> Result<(), DomainError> {
        self.move_to(SubscriptionStatus::Paused, control)?;
        self.raised.raise(SubscriptionPaused {
            subscription_id: self.id,
            subscription_label: self.label(),
            topic_name: self.topic_name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Resumes the subscription. Raises `messaging.subscription_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   messaging.
    /// - [`DomainError::InvalidTransition`] when it is already active.
    pub fn resume(&mut self, control: &MessagingControl<'_>) -> Result<(), DomainError> {
        self.move_to(SubscriptionStatus::Active, control)?;
        self.raised.raise(SubscriptionResumed {
            subscription_id: self.id,
            subscription_label: self.label(),
            topic_name: self.topic_name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Replaces the secret pushes are signed with, keeping the old one
    /// signing beside it for `overlap`. Raises
    /// `messaging.subscription_secret_rotated`.
    ///
    /// Whoever sets the secret can sign messages the service takes for the
    /// topic's own. So this needs the full messaging right. A rotation
    /// during an overlap ends the older secret at once: only the secret
    /// just replaced keeps signing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   messaging.
    /// - [`DomainError::Conflict`] when the subscription is pulled, so it
    ///   signs nothing.
    /// - [`DomainError::Validation`] when `overlap` is longer than seven
    ///   days.
    pub fn rotate_push_secret(
        &mut self,
        new_secret: SealedSecret,
        overlap: RotationOverlap,
        control: &MessagingControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Manage)?;
        let SubscriptionDelivery::Push(endpoint) = &self.delivery else {
            return Err(DomainError::conflict(message!(
                "messaging-a-pulled-subscription-has-no-push",
                "a pulled subscription has no push secret"
            )));
        };
        let now = crate::shared::clock::now();
        let rotated = endpoint.rotated(new_secret, overlap, now)?;
        let old_secret_ends_at = rotated.previous_secret().ends(now);
        self.delivery = SubscriptionDelivery::Push(rotated);
        self.updated_at = now;
        self.raised.raise(SubscriptionSecretRotated {
            subscription_id: self.id,
            subscription_label: self.label(),
            topic_name: self.topic_name.clone(),
            old_secret_ends_at,
            occurred_at: now,
        });
        Ok(())
    }

    /// Refuses pushing `topic`'s messages to `service`, the subscriber as it
    /// is stored now, unless it is still enabled and still cleared for the
    /// topic's class.
    ///
    /// A pull is checked against the caller's clearance on every pull. A
    /// push has no caller, so the service is checked when each message goes
    /// out: "billing-sync", cleared for internal data, subscribed by push
    /// to `payroll.events` while it was internal. Fay has raised it to
    /// restricted since, or Ann disabled the service after its key leaked.
    /// Without this check, salaries go on being posted to it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `service` is not this
    ///   subscription's subscriber, `topic` is not the topic it consumes,
    ///   the service is disabled, or the topic's class is above the
    ///   service's clearance.
    pub fn ensure_pushable(
        &self,
        topic: &Topic<T>,
        service: &Consumer<T>,
    ) -> Result<(), DomainError> {
        if service.id() != &self.consumer_id || topic.topic_name() != &self.topic_name {
            return Err(DomainError::forbidden(message!(
                "messaging-the-push-names-another-service-or",
                "the push names another service or topic than the subscription"
            )));
        }
        if !service.is_active() {
            return Err(DomainError::forbidden(message!(
                "messaging-a-disabled-service-is-pushed-nothing",
                "a disabled service is pushed nothing"
            )));
        }
        if topic.data_class() > service.clearance() {
            return Err(DomainError::forbidden(message!(
                "messaging-the-topic-carries-data-the-service",
                "the topic carries data the service is no longer cleared for"
            )));
        }
        Ok(())
    }

    /// Puts one of this subscription's dead letters back in front of its
    /// service, once `by` may consume. Raises
    /// `messaging.dead_letter_replayed`.
    ///
    /// The bus moves the message; the domain decides who may and keeps
    /// that it happened. Replaying hands the service a message it gave up
    /// on once, such as a payment, so who replayed what stays on record.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person, or the consumer's
    ///   roles, do not give the right to consume.
    pub fn replay_dead_letter(&mut self, by: MessagingReader<'_>) -> Result<(), DomainError> {
        by.ensure_may_consume()?;
        self.raised.raise(DeadLetterReplayed {
            subscription_id: self.id,
            subscription_label: self.label(),
            topic_name: self.topic_name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Deletes this subscription once the person may delete in messaging.
    /// Raises `messaging.subscription_deleted`, taken once the subscription
    /// is removed from storage.
    ///
    /// Deleting it drops the messages waiting for the service. Sam may
    /// publish to topics. Without this check, he deletes the payroll
    /// service's subscription and it never hears of another payment.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not delete in
    ///   messaging.
    pub fn delete(&mut self, control: &MessagingControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Delete)?;
        self.raised.raise(SubscriptionDeleted {
            subscription_id: self.id,
            subscription_label: self.label(),
            topic_name: self.topic_name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// How the audit trail names this subscription: its consumer group, or
    /// else the topic it consumes. The name is copied into each event, so
    /// the entry stays readable after the subscription is gone.
    fn label(&self) -> EventLabel {
        let name = self
            .consumer_group
            .value()
            .map_or_else(|| self.topic_name.as_str(), ConsumerGroup::as_str);
        EventLabel::of(name)
    }

    fn move_to(
        &mut self,
        to: SubscriptionStatus,
        control: &MessagingControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Manage)?;
        self.status = self.status.try_transition(to)?;
        self.updated_at = crate::shared::clock::now();
        Ok(())
    }
}

/// The service a new subscription is for, and who makes it.
#[derive(Debug)]
pub enum Subscriber<'a, T: TenantScope> {
    /// A service that signed in, subscribing itself with what its roles
    /// give it.
    Itself(&'a ConsumerAuthority),
    /// A person subscribing a service of the tenant.
    Enrolled {
        /// The person, with what they hold.
        by: &'a MessagingControl<'a>,
        /// The service they subscribe, as it is stored now.
        consumer: &'a Consumer<T>,
    },
}

impl<T: TenantScope> Subscriber<'_, T> {
    /// The service subscribed and its clearance, once whoever makes the
    /// subscription may.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person, or the service's
    ///   roles, do not give the right to create in messaging.
    /// - [`DomainError::Forbidden`] when a person subscribes a disabled
    ///   service.
    fn ensure_may_subscribe(self) -> Result<(ConsumerId, DataClassLevel), DomainError> {
        match self {
            Self::Itself(authority) => {
                MessagingCreator::Consumer(authority).ensure_may_create()?;
                Ok((*authority.id(), authority.clearance()))
            }
            Self::Enrolled { by, consumer } => {
                MessagingCreator::Person(by).ensure_may_create()?;
                if !consumer.is_active() {
                    return Err(DomainError::forbidden(message!(
                        "messaging-a-disabled-service-is-subscribed-to",
                        "a disabled service is subscribed to nothing"
                    )));
                }
                Ok((*consumer.id(), consumer.clearance()))
            }
        }
    }
}

/// Refuses a new subscription to an archived topic, or to one classed above
/// what the subscriber is cleared for.
fn ensure_subscribable<T: TenantScope>(
    topic: &Topic<T>,
    clearance: DataClassLevel,
) -> Result<(), DomainError> {
    if !topic.accepts_subscriptions() {
        return Err(DomainError::invalid_transition(message!(
            "messaging-an-archived-topic-takes-no-new",
            "an archived topic takes no new subscriptions"
        )));
    }
    if topic.data_class() > clearance {
        return Err(DomainError::forbidden(message!(
            "messaging-the-topic-carries-data-the-subscriber",
            "the topic carries data the subscriber is not cleared for"
        )));
    }
    Ok(())
}

impl<T: TenantScope> Raises for Subscription<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for Subscription<T> {
    type Id = MessageSubscriptionId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

text_value! {
    /// A consumer group: the services in one group share the messages of a
    /// subscription between them.
    pub struct ConsumerGroup;
}

impl TextValue for ConsumerGroup {
    const FIELD: &'static str = "consumer_group";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=128,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE
                | Charset::DOT,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{ConsumersAction, SystemPermission};
    use crate::domains::consumers::fixtures::{billing_sync, sam_holding, service_cleared};
    use crate::domains::messaging::delivery::{MessageFate, PushEndpoint};
    use crate::domains::messaging::fixtures::{
        creating_service, holding, messaging_admin, messaging_viewer, publishing_service,
    };
    use crate::domains::messaging::topic::{CreateTopicParams, RetentionPolicy};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{Lifetime, PublicHttpsUrl};

    const CREATE: SystemPermission = SystemPermission::Messaging(MessagingAction::Create);

    fn topic(name: &str, data_class: DataClassLevel) -> Topic<ResolvedTenant> {
        let params = CreateTopicParams {
            name: label("Events"),
            topic_name: TopicName::new(name).unwrap(),
            description: None,
            schema: Setting::Unset,
            retention: RetentionPolicy::Unlimited,
            data_class,
        };
        Topic::create(params, MessagingCreator::Consumer(&creating_service())).unwrap()
    }

    fn push_params() -> CreateSubscriptionParams {
        CreateSubscriptionParams {
            id: MessageSubscriptionId::new(),
            consumer_group: Setting::Set(ConsumerGroup::new("payment-workers").unwrap()),
            delivery: SubscriptionDelivery::Push(PushEndpoint::new(
                PublicHttpsUrl::new("https://payments.acme.com/push").unwrap(),
                SealedSecret::new("v1.c2VjcmV0").unwrap(),
            )),
            ack_policy: AckPolicy::standard(),
            filter: Setting::Unset,
        }
    }

    /// A pull subscription with the given group and filter.
    fn pull_params(
        consumer_group: Setting<ConsumerGroup>,
        filter: Setting<MessageFilter>,
    ) -> CreateSubscriptionParams {
        CreateSubscriptionParams {
            id: MessageSubscriptionId::new(),
            consumer_group,
            delivery: SubscriptionDelivery::Pull,
            ack_policy: AckPolicy::standard(),
            filter,
        }
    }

    /// `params` on `topic`, asked for by a service that may subscribe and
    /// is cleared for `clearance`.
    fn subscribe(
        topic: &Topic<ResolvedTenant>,
        params: CreateSubscriptionParams,
        clearance: DataClassLevel,
    ) -> Result<Subscription<ResolvedTenant>, DomainError> {
        let service = service_cleared(&[CREATE], clearance);
        Subscription::create(topic, params, Subscriber::Itself(&service))
    }

    fn test_sub() -> Subscription<ResolvedTenant> {
        let orders = topic("orders.created", DataClassLevel::Internal);
        subscribe(&orders, push_params(), DataClassLevel::Internal).unwrap()
    }

    /// A service with publishing permission alone cannot create a subscription.
    #[test]
    fn a_service_without_the_create_right_does_not_subscribe() {
        let orders = topic("orders.created", DataClassLevel::Internal);

        let result = Subscription::create(
            &orders,
            push_params(),
            Subscriber::Itself(&publishing_service()),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A service cleared for internal data cannot subscribe to a restricted
    /// topic.
    #[test]
    fn a_service_cannot_subscribe_to_a_topic_above_its_clearance() {
        let salaries = topic("salaries.paid", DataClassLevel::Restricted);

        let result = subscribe(&salaries, push_params(), DataClassLevel::Internal);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An archived topic refuses a new subscription from an otherwise
    /// authorized service.
    #[test]
    fn a_service_cannot_subscribe_to_an_archived_topic() {
        let mut orders = topic("orders.created", DataClassLevel::Internal);
        orders.archive(&messaging_admin()).unwrap();

        let result = subscribe(&orders, push_params(), DataClassLevel::Internal);

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// `orders.created` is paused. A service cleared for confidential data
    /// subscribes to it. It is accepted, and messages wait until the topic
    /// resumes.
    #[test]
    fn a_service_may_subscribe_to_a_paused_topic_below_its_clearance() {
        let mut orders = topic("orders.created", DataClassLevel::Internal);
        orders.pause(&messaging_admin()).unwrap();

        let result = subscribe(&orders, push_params(), DataClassLevel::Confidential);

        assert!(result.is_ok());
    }

    /// A service subscribes to `orders.created` in the group
    /// `payment-workers` by push. The new subscription is active and keeps
    /// what it was given.
    #[test]
    fn create_produces_active_subscription() {
        let sub = test_sub();
        assert!(sub.is_active());
        assert_eq!(sub.topic_name().as_str(), "orders.created");
        assert_eq!(
            sub.consumer_group().map(ConsumerGroup::as_str),
            Some("payment-workers")
        );
        assert_eq!(sub.delivery_mode(), DeliveryMode::Push);
    }

    /// An active subscription is paused and then resumed. It is inactive in
    /// between and active again after.
    #[test]
    fn pause_and_resume() {
        let mut sub = test_sub();
        sub.pause(&messaging_admin()).unwrap();
        assert!(!sub.is_active());
        sub.resume(&messaging_admin()).unwrap();
        assert!(sub.is_active());
    }

    /// A viewer cannot pause a subscription, which remains active.
    #[test]
    fn a_viewer_cannot_pause_a_subscription() {
        let mut sub = test_sub();

        let result = sub.pause(&messaging_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(sub.is_active());
    }

    /// A viewer cannot resume a subscription paused by an administrator.
    /// It remains inactive after the refusal.
    #[test]
    fn a_viewer_cannot_resume_a_subscription() {
        let mut sub = test_sub();
        sub.pause(&messaging_admin()).unwrap();

        let result = sub.resume(&messaging_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(!sub.is_active());
    }

    /// A subscription is paused five minutes after it was created. Its last
    /// change time moves to the pause and its creation time stays, so a
    /// cache sees that it changed.
    #[test]
    fn pausing_moves_the_timestamp_readers_watch() {
        let mut sub = test_sub();
        let later = sub.created_at + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        sub.pause(&messaging_admin()).unwrap();

        assert_eq!(Aggregate::updated_at(&sub), later);
        assert_eq!(
            Aggregate::created_at(&sub),
            later - time::Duration::minutes(5)
        );
    }

    /// A stored row says the subscription changed one second before it was
    /// created. It is refused as corrupt.
    #[test]
    fn a_stored_subscription_changed_before_it_was_created_is_refused() {
        let sub = test_sub();
        let row = SubscriptionRow {
            id: sub.id,
            topic_name: sub.topic_name.clone(),
            consumer_id: sub.consumer_id,
            consumer_group: sub.consumer_group.clone(),
            delivery: sub.delivery.clone(),
            ack_policy: sub.ack_policy,
            filter: sub.filter.clone(),
            status: sub.status,
            created_at: sub.created_at,
            updated_at: sub.created_at - time::Duration::SECOND,
        };

        assert!(crate::shared::model::row_check::refused_as_corrupt(
            &Subscription::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Resuming an active subscription is refused, and so is pausing one
    /// that is already paused.
    #[test]
    fn pausing_or_resuming_twice_is_refused() {
        let mut sub = test_sub();
        let admin = messaging_admin();

        assert!(sub.resume(&admin).is_err());
        sub.pause(&admin).unwrap();
        assert!(sub.pause(&admin).is_err());
    }

    /// A pull subscription to `events.all` has no group and the filter
    /// `orders`. It reports no group, so it gets every message, and keeps
    /// its filter.
    #[test]
    fn no_consumer_group_is_fanout() {
        let sub = subscribe(
            &topic("events.all", DataClassLevel::Internal),
            pull_params(
                Setting::Unset,
                Setting::Set(MessageFilter::new("orders").unwrap()),
            ),
            DataClassLevel::Internal,
        )
        .unwrap();
        assert!(sub.consumer_group().is_none());
        assert_eq!(sub.filter().map(MessageFilter::as_str), Some("orders"));
    }

    fn grouped(filter: Setting<MessageFilter>) -> Subscription<ResolvedTenant> {
        let group = Setting::Set(ConsumerGroup::new("payment-workers").unwrap());
        subscribe(
            &topic("orders.created", DataClassLevel::Internal),
            pull_params(group, filter),
            DataClassLevel::Internal,
        )
        .unwrap()
    }

    /// A second payment worker joins the group with the same filter and
    /// acknowledgement policy as the first. It may.
    #[test]
    fn a_subscription_reading_alike_joins_its_group() {
        let first = grouped(Setting::Unset);

        let joined = grouped(Setting::Unset).ensure_reads_like(&first);

        assert!(joined.is_ok());
    }

    /// Joining a group with a refund filter conflicts when its existing
    /// member has no filter.
    #[test]
    fn a_subscription_filtering_otherwise_does_not_join_its_group() {
        let first = grouped(Setting::Unset);
        let refunds = Setting::Set(MessageFilter::new("order.refund").unwrap());

        let joined = grouped(refunds).ensure_reads_like(&first);

        assert!(matches!(joined, Err(DomainError::Conflict(_))));
    }

    /// A service subscribes to `orders.created`. The subscription names
    /// that service and has a fresh id of its own, so deliveries reach the
    /// right service.
    #[test]
    fn a_subscription_names_its_consumer_and_carries_its_own_id() {
        let consumer = creating_service();
        let orders = topic("orders.created", DataClassLevel::Internal);

        let sub =
            Subscription::create(&orders, push_params(), Subscriber::Itself(&consumer)).unwrap();

        assert_eq!(sub.consumer_id(), consumer.id());
        assert!(!sub.id().as_uuid().is_nil());
        assert_eq!(Aggregate::id(&sub), sub.id());
    }

    /// Ann may create in messaging and subscribes "billing-sync" to
    /// `orders.created`. The subscription is the service's. Sam, who may
    /// only view messaging, subscribes it to nothing.
    #[test]
    fn a_person_with_the_create_right_subscribes_a_service() {
        let orders = topic("orders.created", DataClassLevel::Internal);
        let service = billing_sync();
        let (ann, sam) = (holding(&[CREATE]), messaging_viewer());
        let enrolled = |by| Subscriber::Enrolled {
            by,
            consumer: &service,
        };

        let sub = Subscription::create(&orders, push_params(), enrolled(&ann)).unwrap();
        let by_viewer = Subscription::create(&orders, push_params(), enrolled(&sam));

        assert_eq!(sub.consumer_id(), service.id());
        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
    }

    /// An administrator cannot subscribe a service above its clearance.
    /// After the service is disabled, subscribing it to an internal topic
    /// is also forbidden.
    #[test]
    fn a_person_subscribes_a_service_only_within_its_clearance_while_active() {
        let (salaries, orders) = (
            topic("salaries.paid", DataClassLevel::Restricted),
            topic("orders.created", DataClassLevel::Internal),
        );
        let mut service = billing_sync();
        let admin = messaging_admin();
        let updater = sam_holding(&[SystemPermission::Consumers(ConsumersAction::Update)]);

        let above = Subscription::create(
            &salaries,
            push_params(),
            Subscriber::Enrolled {
                by: &admin,
                consumer: &service,
            },
        );
        service.disable(&updater).unwrap();
        let disabled = Subscription::create(
            &orders,
            push_params(),
            Subscriber::Enrolled {
                by: &admin,
                consumer: &service,
            },
        );

        assert!(matches!(above, Err(DomainError::Forbidden(_))));
        assert!(matches!(disabled, Err(DomainError::Forbidden(_))));
    }

    /// A publisher cannot delete a subscription, while a messaging
    /// administrator can.
    #[test]
    fn deleting_a_subscription_needs_the_delete_right() {
        let mut sub = test_sub();
        let publisher = holding(&[SystemPermission::Messaging(MessagingAction::Publish)]);

        assert!(matches!(
            sub.delete(&publisher),
            Err(DomainError::Forbidden(_))
        ));
        assert!(sub.delete(&messaging_admin()).is_ok());
    }

    /// The label a subscription event links the subscription under.
    fn label_of(event: &DomainEvent) -> String {
        match event.payload().value("subscription") {
            Some(FieldValue::Reference(reference)) => reference.label().to_owned(),
            other => panic!("subscription is not a reference: {other:?}"),
        }
    }

    /// A service subscribes to `orders.created` in the group
    /// `payment-workers`. The subscription is raised, named by its group.
    #[test]
    fn subscribing_raises_messaging_subscription_created_named_by_group() {
        let mut sub = test_sub();

        let events = raised(&mut sub);

        assert_eq!(
            events[0].event_type().to_string(),
            "messaging.subscription_created"
        );
        assert_eq!(label_of(&events[0]), "payment-workers");
    }

    /// A service subscribes to `events.all` with no group. The record names
    /// the subscription by the topic it consumes.
    #[test]
    fn a_subscription_without_a_group_is_named_by_its_topic() {
        let mut sub = subscribe(
            &topic("events.all", DataClassLevel::Internal),
            pull_params(Setting::Unset, Setting::Unset),
            DataClassLevel::Internal,
        )
        .unwrap();

        assert_eq!(label_of(&raised(&mut sub)[0]), "events.all");
    }

    /// Ann pauses the payment workers' subscription and resumes it, then
    /// deletes it. Each step is raised, in order.
    #[test]
    fn pausing_resuming_and_deleting_are_raised_in_order() {
        let mut sub = test_sub();
        raised_names(&mut sub);
        let admin = messaging_admin();

        sub.pause(&admin).unwrap();
        sub.resume(&admin).unwrap();
        sub.delete(&admin).unwrap();

        assert_eq!(
            raised_names(&mut sub),
            [
                "messaging.subscription_paused",
                "messaging.subscription_resumed",
                "messaging.subscription_deleted",
            ]
        );
    }

    /// A viewer's pause and delete attempts fail without raising events.
    #[test]
    fn a_refused_subscription_change_raises_nothing() {
        let mut sub = test_sub();
        raised_names(&mut sub);

        let paused = sub.pause(&messaging_viewer());
        let deleted = sub.delete(&messaging_viewer());

        assert!(paused.is_err());
        assert!(deleted.is_err());
        assert!(raised_names(&mut sub).is_empty());
    }

    /// The group name `billing-workers` is allowed.
    #[test]
    fn a_well_formed_consumer_group_is_accepted() {
        assert!(ConsumerGroup::new("billing-workers").is_ok());
    }

    /// An empty group name, one with a space and one with a slash are all
    /// refused.
    #[test]
    fn a_malformed_consumer_group_is_refused() {
        for value in ["", "a b", "a/b"] {
            assert!(ConsumerGroup::new(value).is_err(), "{value:?} was accepted");
        }
    }

    /// The payment workers subscribe by push. The subscription keeps where
    /// it pushes, the sealed secret it signs with and its acknowledgement
    /// policy, and reads back from storage with them.
    #[test]
    fn a_push_subscription_keeps_its_endpoint_secret_and_ack_policy() {
        let sub = test_sub();

        let SubscriptionDelivery::Push(endpoint) = sub.delivery() else {
            panic!("the payment workers subscribed by push");
        };

        assert_eq!(endpoint.url().as_str(), "https://payments.acme.com/push");
        assert_eq!(endpoint.signing_secret().as_str(), "v1.c2VjcmV0");
        assert_eq!(sub.ack_policy().fate_after(5), MessageFate::DeadLetter);
        assert!(!format!("{sub:?}").contains("c2VjcmV0"));
    }

    /// Ann manages messaging and replaces the payment workers' push secret
    /// after it leaked. Pushes are signed with the new one and the
    /// rotation is raised.
    #[test]
    fn rotating_a_push_secret_replaces_it() {
        let mut sub = test_sub();
        raised_names(&mut sub);

        sub.rotate_push_secret(
            SealedSecret::new("v1.bmV3").unwrap(),
            RotationOverlap::Immediate,
            &messaging_admin(),
        )
        .unwrap();

        let SubscriptionDelivery::Push(endpoint) = sub.delivery() else {
            panic!("the payment workers subscribed by push");
        };
        assert_eq!(endpoint.signing_secret().as_str(), "v1.bmV3");
        assert_eq!(
            endpoint.signing_secrets(crate::shared::clock::now()).len(),
            1
        );
        assert_eq!(endpoint.url().as_str(), "https://payments.acme.com/push");
        assert_eq!(
            raised_names(&mut sub),
            ["messaging.subscription_secret_rotated"]
        );
    }

    /// Ann rotates the payment workers' push secret with a day's overlap,
    /// so they can move over without refusing a push. The old secret keeps
    /// signing beside the new one, and the record says when it stops.
    #[test]
    fn rotating_with_an_overlap_keeps_the_old_push_secret_signing() {
        let mut sub = test_sub();
        raised_names(&mut sub);
        let day = RotationOverlap::For(Lifetime::seconds(86_400).unwrap());

        sub.rotate_push_secret(
            SealedSecret::new("v1.bmV3").unwrap(),
            day,
            &messaging_admin(),
        )
        .unwrap();

        let SubscriptionDelivery::Push(endpoint) = sub.delivery() else {
            panic!("the payment workers subscribed by push");
        };
        let signing: Vec<&str> = endpoint
            .signing_secrets(crate::shared::clock::now())
            .into_iter()
            .map(SealedSecret::as_str)
            .collect();
        assert_eq!(signing, ["v1.bmV3", "v1.c2VjcmV0"]);
        let events = raised(&mut sub);
        assert!(events[0].payload().value("expires_at").is_some());
    }

    /// A month-long push secret overlap is invalid. Refusing the rotation
    /// preserves the current signing secret.
    #[test]
    fn a_push_secret_overlap_over_seven_days_is_refused() {
        let mut sub = test_sub();
        let month = RotationOverlap::For(Lifetime::seconds(2_592_000).unwrap());
        let new = SealedSecret::new("v1.bmV3").unwrap();

        let result = sub.rotate_push_secret(new, month, &messaging_admin());

        assert!(matches!(result, Err(DomainError::Validation(_))));
        let SubscriptionDelivery::Push(endpoint) = sub.delivery() else {
            panic!("the payment workers subscribed by push");
        };
        assert_eq!(endpoint.signing_secret().as_str(), "v1.c2VjcmV0");
    }

    /// "billing-sync"'s push subscription to `orders.created`, made by Ann,
    /// beside the service as it is stored.
    fn pushed_to_billing_sync() -> (Subscription<ResolvedTenant>, Consumer<ResolvedTenant>) {
        let service = billing_sync();
        let admin = messaging_admin();
        let sub = Subscription::create(
            &topic("orders.created", DataClassLevel::Internal),
            push_params(),
            Subscriber::Enrolled {
                by: &admin,
                consumer: &service,
            },
        )
        .unwrap();
        (sub, service)
    }

    /// "billing-sync" is still enabled and cleared for `orders.created`.
    /// Its messages are pushed.
    #[test]
    fn an_enabled_service_cleared_for_the_topic_is_pushed_to() {
        let (sub, service) = pushed_to_billing_sync();
        let orders = topic("orders.created", DataClassLevel::Internal);

        assert!(sub.ensure_pushable(&orders, &service).is_ok());
    }

    /// Push authorization fails when the topic is now restricted but its
    /// subscriber is cleared only for internal data.
    #[test]
    fn a_topic_raised_above_the_services_clearance_is_not_pushed() {
        let (sub, service) = pushed_to_billing_sync();
        let raised_topic = topic("orders.created", DataClassLevel::Restricted);

        let result = sub.ensure_pushable(&raised_topic, &service);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Disabling the subscribing service makes its push authorization fail.
    #[test]
    fn a_disabled_service_is_not_pushed() {
        let (sub, mut service) = pushed_to_billing_sync();
        let updater = sam_holding(&[SystemPermission::Consumers(ConsumersAction::Update)]);
        service.disable(&updater).unwrap();
        let orders = topic("orders.created", DataClassLevel::Internal);

        let result = sub.ensure_pushable(&orders, &service);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Push authorization rejects a different service from the one named
    /// by the subscription.
    #[test]
    fn a_push_checked_against_another_service_is_refused() {
        let (sub, _) = pushed_to_billing_sync();
        let other = billing_sync();
        let orders = topic("orders.created", DataClassLevel::Internal);

        let result = sub.ensure_pushable(&orders, &other);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann may consume and replays a dead letter of the payment workers'
    /// subscription. The replay is raised.
    #[test]
    fn replaying_a_dead_letter_is_raised() {
        let mut sub = test_sub();
        raised_names(&mut sub);
        let ann = holding(&[SystemPermission::Messaging(MessagingAction::Consume)]);

        sub.replay_dead_letter(MessagingReader::Person(&ann))
            .unwrap();

        assert_eq!(raised_names(&mut sub), ["messaging.dead_letter_replayed"]);
    }

    /// A viewer cannot replay a dead letter, and the refusal raises no event.
    #[test]
    fn replaying_a_dead_letter_needs_the_consume_right() {
        let mut sub = test_sub();
        raised_names(&mut sub);
        let sam = messaging_viewer();

        let result = sub.replay_dead_letter(MessagingReader::Person(&sam));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(raised_names(&mut sub).is_empty());
    }

    /// A publisher cannot rotate a push signing secret. The existing secret
    /// remains in place.
    #[test]
    fn rotating_a_push_secret_needs_the_full_messaging_right() {
        let mut sub = test_sub();
        let publisher = holding(&[SystemPermission::Messaging(MessagingAction::Publish)]);

        let result = sub.rotate_push_secret(
            SealedSecret::new("v1.c2Ftcw").unwrap(),
            RotationOverlap::Immediate,
            &publisher,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        let SubscriptionDelivery::Push(endpoint) = sub.delivery() else {
            panic!("the payment workers subscribed by push");
        };
        assert_eq!(endpoint.signing_secret().as_str(), "v1.c2VjcmV0");
    }

    /// A pulled subscription is given a push secret. It is refused, since
    /// nothing is pushed or signed.
    #[test]
    fn a_pulled_subscription_has_no_push_secret_to_rotate() {
        let mut sub = subscribe(
            &topic("events.all", DataClassLevel::Internal),
            pull_params(Setting::Unset, Setting::Unset),
            DataClassLevel::Internal,
        )
        .unwrap();

        let result = sub.rotate_push_secret(
            SealedSecret::new("v1.bmV3").unwrap(),
            RotationOverlap::Immediate,
            &messaging_admin(),
        );

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(sub.delivery(), &SubscriptionDelivery::Pull);
        assert_eq!(sub.delivery_mode(), DeliveryMode::Pull);
    }
}
