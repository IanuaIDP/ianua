//! A subscription as its row holds it: read back into the aggregate, and
//! written out from it. A push keeps where it goes and its secrets in the
//! push columns, sealed; a pull leaves them empty.

use ianua_domain::domains::messaging::delivery::{AckPolicy, PushEndpoint, SubscriptionDelivery};
use ianua_domain::domains::messaging::message_type::MessageFilter;
use ianua_domain::domains::messaging::subscription::{
    ConsumerGroup, DeliveryMode, Subscription, SubscriptionRow,
};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{
    ConsumerId, MessageSubscriptionId, PublicHttpsUrl, SealedSecret, Seconds, Setting,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::messaging::signing::{previous_columns, previous_from};

const SUBSCRIPTION: Stored = Stored("message subscription");

/// A subscription as it is read. The store's checked queries fill it.
pub(super) struct SubscriptionRecord {
    pub(super) id: Uuid,
    pub(super) topic_name: String,
    pub(super) consumer_id: Uuid,
    pub(super) consumer_group: Option<String>,
    pub(super) delivery_mode: String,
    pub(super) push_url: Option<String>,
    pub(super) push_secret_sealed: Option<String>,
    pub(super) previous_secret_sealed: Option<String>,
    pub(super) previous_secret_until: Option<OffsetDateTime>,
    pub(super) ack_deadline_seconds: i64,
    pub(super) max_deliveries: i64,
    pub(super) filter: Option<String>,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl SubscriptionRecord {
    /// The subscription the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the push columns do not fit the
    /// delivery mode, or the row breaks a rule the subscription keeps.
    pub(super) fn into_subscription(self) -> Result<Subscription<ResolvedTenant>, DomainError> {
        let delivery = self.delivery()?;
        let ack_policy = ack_policy_from(self.ack_deadline_seconds, self.max_deliveries)?;
        Subscription::reconstitute(SubscriptionRow {
            id: MessageSubscriptionId::from_uuid(self.id),
            topic_name: SUBSCRIPTION.value("topic name", TopicName::new(self.topic_name))?,
            consumer_id: ConsumerId::from_uuid(self.consumer_id),
            consumer_group: Setting::from_stored(
                self.consumer_group
                    .map(|group| SUBSCRIPTION.value("consumer group", ConsumerGroup::new(group)))
                    .transpose()?,
            ),
            delivery,
            ack_policy,
            filter: Setting::from_stored(
                self.filter
                    .map(|filter| SUBSCRIPTION.value("filter", MessageFilter::new(filter)))
                    .transpose()?,
            ),
            status: SUBSCRIPTION.choice(&self.status)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// How messages reach the service, from the mode and the push columns.
    fn delivery(&self) -> Result<SubscriptionDelivery, DomainError> {
        let mode: DeliveryMode = SUBSCRIPTION.choice(&self.delivery_mode)?;
        match (
            mode,
            self.push_url.as_deref(),
            self.push_secret_sealed.as_deref(),
        ) {
            (DeliveryMode::Pull, None, None) => Ok(SubscriptionDelivery::Pull),
            (DeliveryMode::Push, Some(url), Some(secret)) => {
                let endpoint = PushEndpoint::restored(
                    SUBSCRIPTION.value("push address", PublicHttpsUrl::new(url))?,
                    SUBSCRIPTION.value("push secret", SealedSecret::new(secret))?,
                    previous_from(
                        SUBSCRIPTION,
                        self.previous_secret_sealed.clone(),
                        self.previous_secret_until,
                    )?,
                );
                Ok(SubscriptionDelivery::Push(endpoint))
            }
            (DeliveryMode::Pull | DeliveryMode::Push, _, _) => Err(DomainError::corrupt_row(
                SUBSCRIPTION.0,
                "push columns that do not fit the delivery mode",
            )),
        }
    }
}

/// The acknowledgement policy the two policy columns hold.
fn ack_policy_from(deadline: i64, deliveries: i64) -> Result<AckPolicy, DomainError> {
    let out_of_range =
        || DomainError::corrupt_row(SUBSCRIPTION.0, "an acknowledgement policy out of range");
    let deadline = u32::try_from(deadline).map_err(|_| out_of_range())?;
    let deliveries = u32::try_from(deliveries).map_err(|_| out_of_range())?;
    AckPolicy::new(Seconds::new(deadline), deliveries).map_err(|_| out_of_range())
}

/// A subscription's columns, as they are written.
pub(super) struct SubscriptionColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) topic_name: &'a str,
    pub(super) consumer_id: &'a Uuid,
    pub(super) consumer_group: Option<&'a str>,
    pub(super) delivery_mode: &'static str,
    pub(super) push_url: Option<&'a str>,
    pub(super) push_secret_sealed: Option<&'a str>,
    pub(super) previous_secret_sealed: Option<&'a str>,
    pub(super) previous_secret_until: Option<OffsetDateTime>,
    pub(super) ack_deadline_seconds: i64,
    pub(super) max_deliveries: i64,
    pub(super) filter: Option<&'a str>,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> SubscriptionColumns<'a> {
    /// The columns `subscription` is written to.
    pub(super) fn of(subscription: &'a Subscription<ResolvedTenant>) -> Self {
        let push = match subscription.delivery() {
            SubscriptionDelivery::Pull => None,
            SubscriptionDelivery::Push(endpoint) => Some(endpoint),
        };
        let (previous_secret_sealed, previous_secret_until) = push
            .map_or((None, None), |endpoint| {
                previous_columns(endpoint.previous_secret())
            });
        let policy = subscription.ack_policy();
        Self {
            id: subscription.id().as_uuid(),
            topic_name: subscription.topic_name().as_str(),
            consumer_id: subscription.consumer_id().as_uuid(),
            consumer_group: subscription.consumer_group().map(ConsumerGroup::as_str),
            delivery_mode: subscription.delivery_mode().word(),
            push_url: push.map(|endpoint| endpoint.url().as_str()),
            push_secret_sealed: push.map(|endpoint| endpoint.signing_secret().as_str()),
            previous_secret_sealed,
            previous_secret_until,
            ack_deadline_seconds: i64::from(policy.ack_deadline().get()),
            max_deliveries: i64::from(policy.max_deliveries()),
            filter: subscription.filter().map(MessageFilter::as_str),
            status: subscription.status().word(),
            created_at: subscription.created_at(),
            updated_at: subscription.updated_at(),
        }
    }
}
