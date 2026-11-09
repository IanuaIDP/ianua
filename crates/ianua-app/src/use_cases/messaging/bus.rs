//! The bus consumer a subscription reads through, kept in step with the
//! subscription itself, and the subject a topic's messages are shown live
//! on.
//!
//! A subscription with no consumer group reads through a consumer of its
//! own. The subscriptions of one group on one topic read through one
//! consumer together, so each message goes to one of them: the consumer is
//! opened by the first and removed with the last.

use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{Acknowledgement, ConsumerSpec, MessageConsumer, SubscriptionStore};
use crate::tenancy::ScopedTenant;

/// The subject `topic`'s messages are broadcast on as they are published,
/// for the dashboards streaming it.
pub(super) fn live_subject(tenant: &ScopedTenant, topic: &TopicName) -> String {
    format!("ianua.msg.{}.{topic}", tenant.as_uuid().as_simple())
}

/// What parts a group consumer's name, a character neither a topic name nor
/// a group name may hold. Joined with one they may hold, topic `orders`
/// with group `x-billing` and topic `orders-x` with group `billing` would
/// read through one consumer, and each would take the other's messages.
const NAME_SEPARATOR: char = '/';

/// The name of the bus consumer `subscription` reads through: its group's
/// on its topic when it has one, otherwise its own from its id. Either way
/// creating it again changes nothing.
pub(super) fn consumer_name(subscription: &Subscription<ResolvedTenant>) -> String {
    match subscription.consumer_group() {
        Some(group) => format!(
            "group{NAME_SEPARATOR}{}{NAME_SEPARATOR}{group}",
            subscription.topic_name()
        ),
        None => format!("sub-{}", subscription.id().as_uuid().as_simple()),
    }
}

/// Creates, or confirms, the bus consumer `subscription` reads through. It
/// waits for each acknowledgement as long as the subscription's policy says,
/// and hands out only the message types its filter lets through.
///
/// # Errors
///
/// `AppError::Internal` when the bus refuses.
pub(super) async fn open_consumer(
    bus: &dyn MessageConsumer,
    tenant: &ScopedTenant,
    subscription: &Subscription<ResolvedTenant>,
) -> Result<(), AppError> {
    let name = consumer_name(subscription);
    bus.ensure_consumer(
        tenant,
        subscription.topic_name(),
        &ConsumerSpec {
            name: &name,
            filter: subscription.filter(),
            acknowledgement: Acknowledgement::Explicit {
                deadline: subscription.ack_policy().ack_deadline(),
            },
        },
    )
    .await
    .or_internal()
}

/// Removes the bus consumer `subscription` reads through, and the messages
/// waiting in it, unless another subscription of its group still reads
/// through it.
///
/// # Errors
///
/// `AppError::Internal` when the store or the bus refuses.
pub(super) async fn close_consumer(
    bus: &dyn MessageConsumer,
    store: &dyn SubscriptionStore,
    tenant: &ScopedTenant,
    subscription: &Subscription<ResolvedTenant>,
) -> Result<(), AppError> {
    if group_still_reads(store, tenant, subscription).await? {
        return Ok(());
    }
    bus.delete_consumer(
        tenant,
        subscription.topic_name(),
        &consumer_name(subscription),
    )
    .await
    .or_internal()
}

/// Whether another subscription of `subscription`'s group reads through
/// its consumer. Never, for a subscription with no group.
async fn group_still_reads(
    store: &dyn SubscriptionStore,
    tenant: &ScopedTenant,
    subscription: &Subscription<ResolvedTenant>,
) -> Result<bool, AppError> {
    let Some(group) = subscription.consumer_group() else {
        return Ok(false);
    };
    let other = store
        .other_in_group(tenant, subscription.topic_name(), group, subscription.id())
        .await
        .or_internal()?;
    Ok(other.is_some())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::messaging::subscription::ConsumerGroup;

    use super::*;
    use crate::test_support::consumers::billing_sync;
    use crate::test_support::messaging::{grouped_subscription_of, topic_named};

    /// Group `x-billing` on `orders` and group `billing` on `orders-x`
    /// receive distinct consumer names despite their shared name fragments.
    #[test]
    fn groups_whose_names_run_together_read_through_different_consumers() {
        let orders = grouped_subscription_of(&billing_sync(), &topic_named("orders"), "x-billing");
        let orders_x =
            grouped_subscription_of(&billing_sync(), &topic_named("orders-x"), "billing");

        assert_ne!(consumer_name(&orders), consumer_name(&orders_x));
    }

    /// Two subscriptions of one group on one topic read through one
    /// consumer.
    #[test]
    fn one_group_on_one_topic_shares_its_consumer() {
        let topic = topic_named("orders");
        let first = grouped_subscription_of(&billing_sync(), &topic, "billing");
        let second = grouped_subscription_of(&billing_sync(), &topic, "billing");

        assert_eq!(consumer_name(&first), consumer_name(&second));
    }

    /// Topic and group names both reject the separator used to distinguish
    /// their parts in a consumer name.
    #[test]
    fn neither_name_may_hold_the_separator() {
        let joined = format!("a{NAME_SEPARATOR}b");

        assert!(TopicName::new(joined.as_str()).is_err());
        assert!(ConsumerGroup::new(joined.as_str()).is_err());
    }
}
