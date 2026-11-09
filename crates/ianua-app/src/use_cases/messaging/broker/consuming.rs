//! The subscription a caller consumes from, and the delivery they settle:
//! pulling, acknowledging, refusing and replaying all start by loading them
//! this way.

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::MessageSubscriptionId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::messaging::{DeliveryReceipt, MessageConsumer, OpenDelivery, SubscriptionStore};
use crate::tenancy::ScopedTenant;
use crate::use_cases::messaging::bus::consumer_name;
use crate::use_cases::messaging::caller::MessagingActor;
use crate::use_cases::messaging::lookup::existing_subscription;

/// The subscription `id`, once `actor` may consume and, for a consumer,
/// once it is its own.
///
/// # Errors
///
/// - `AppError::Forbidden` when the person, or the consumer's roles, may
///   not consume.
/// - `AppError::NotFound` if the tenant has no such subscription, or it is
///   another service's and a consumer asks.
/// - `AppError::Internal` on storage failure.
pub(super) async fn consumed_subscription(
    store: &dyn SubscriptionStore,
    tenant: &ScopedTenant,
    actor: &MessagingActor,
    id: &MessageSubscriptionId,
) -> Result<Subscription<ResolvedTenant>, AppError> {
    actor.ensure_holds(SystemPermission::Messaging(MessagingAction::Consume))?;
    let subscription = existing_subscription(store, tenant, id).await?;
    ensure_own_subscription(actor, &subscription)?;
    Ok(subscription)
}

/// The delivery `receipt` names, while it still waits for its
/// acknowledgement on `subscription`'s consumer.
///
/// # Errors
///
/// - `AppError::NotFound` when it was settled, its deadline passed, or the
///   receipt was never this subscription's.
/// - `AppError::Internal` when the bus cannot be read.
pub(super) async fn existing_delivery(
    bus: &dyn MessageConsumer,
    tenant: &ScopedTenant,
    subscription: &Subscription<ResolvedTenant>,
    receipt: &DeliveryReceipt,
) -> Result<OpenDelivery, AppError> {
    bus.open_delivery(
        tenant,
        subscription.topic_name(),
        &consumer_name(subscription),
        receipt,
    )
    .await
    .or_internal()?
    .or_not_found(message!(
        "messaging-delivery-not-found",
        "delivery not found"
    ))
}

/// Refuses a consumer reading another service's subscription. It is
/// answered as not found, so a consumer learns nothing of what others read.
///
/// # Errors
///
/// `AppError::NotFound` when a consumer asks for another's subscription.
fn ensure_own_subscription(
    actor: &MessagingActor,
    subscription: &Subscription<ResolvedTenant>,
) -> Result<(), AppError> {
    match actor {
        MessagingActor::Consumer(authority) if authority.id() != subscription.consumer_id() => {
            Err(AppError::NotFound(message!(
                "messaging-subscription-not-found",
                "subscription not found"
            )))
        }
        MessagingActor::Consumer(_) | MessagingActor::Person(_) => Ok(()),
    }
}

/// Refuses handing out a paused subscription's messages.
///
/// # Errors
///
/// `AppError::Forbidden` while the subscription is paused.
pub(super) fn ensure_active(subscription: &Subscription<ResolvedTenant>) -> Result<(), AppError> {
    if !subscription.is_active() {
        return Err(AppError::Forbidden(message!(
            "messaging-a-paused-subscription-hands-out-no",
            "a paused subscription hands out no messages"
        )));
    }
    Ok(())
}
