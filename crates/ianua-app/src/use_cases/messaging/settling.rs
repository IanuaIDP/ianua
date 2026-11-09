//! Settling a message a subscription handed out: delivered again or set
//! aside as a dead letter, as the subscription's acknowledgement policy
//! decides.
//!
//! The bus counts the deliveries; `AckPolicy::fate_after` decides what that
//! count means. The same rule settles a message its service refused, one
//! whose push failed, and one whose deadline passed and that comes round
//! again.

use ianua_domain::domains::messaging::delivery::MessageFate;
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{DeliveryReceipt, MessageConsumer, PendingMessage};
use crate::tenancy::ScopedTenant;
use crate::use_cases::messaging::bus::consumer_name;

/// What becomes of `message` as it comes round: handed out while its earlier
/// deliveries, none acknowledged, leave it some; set aside once they are
/// spent, which is how a message whose deadline kept passing ends.
pub(super) fn fate_on_arrival(
    subscription: &Subscription<ResolvedTenant>,
    message: &PendingMessage,
) -> MessageFate {
    subscription
        .ack_policy()
        .fate_after(message.delivered.saturating_sub(1))
}

/// The delivery `receipt` names on `subscription`'s consumer, refused after
/// `delivered` deliveries: delivered again, or set aside once its
/// deliveries are spent. Returns which.
///
/// # Errors
///
/// `AppError::Internal` when the bus refuses.
pub(super) async fn settle_refused(
    bus: &dyn MessageConsumer,
    tenant: &ScopedTenant,
    subscription: &Subscription<ResolvedTenant>,
    receipt: &DeliveryReceipt,
    delivered: u32,
) -> Result<MessageFate, AppError> {
    let fate = subscription.ack_policy().fate_after(delivered);
    match fate {
        MessageFate::Redeliver => redeliver(bus, tenant, subscription, receipt).await?,
        MessageFate::DeadLetter => set_aside(bus, tenant, subscription, receipt).await?,
    }
    Ok(fate)
}

/// Asks the bus to deliver the message `receipt` names again at once.
///
/// # Errors
///
/// `AppError::Internal` when the bus refuses.
async fn redeliver(
    bus: &dyn MessageConsumer,
    tenant: &ScopedTenant,
    subscription: &Subscription<ResolvedTenant>,
    receipt: &DeliveryReceipt,
) -> Result<(), AppError> {
    bus.redeliver(
        tenant,
        subscription.topic_name(),
        &consumer_name(subscription),
        receipt,
    )
    .await
    .or_internal()
}

/// Sets the message `receipt` names aside as one of `subscription`'s dead
/// letters.
///
/// # Errors
///
/// `AppError::Internal` when the bus refuses.
pub(super) async fn set_aside(
    bus: &dyn MessageConsumer,
    tenant: &ScopedTenant,
    subscription: &Subscription<ResolvedTenant>,
    receipt: &DeliveryReceipt,
) -> Result<(), AppError> {
    bus.dead_letter(
        tenant,
        subscription.topic_name(),
        &consumer_name(subscription),
        receipt,
    )
    .await
    .or_internal()
}
