//! Loading the webhook subscription a caller names, which every use case that
//! reads or changes one starts with.

use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::WebhookSubscriptionId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::webhooks::WebhookStore;
use crate::tenancy::ScopedTenant;

/// The tenant's webhook subscription with `subscription_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such subscription.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_subscription(
    store: &dyn WebhookStore,
    tenant: &ScopedTenant,
    subscription_id: &WebhookSubscriptionId,
) -> Result<WebhookSubscription<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, subscription_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "webhooks-webhook-subscription-not-found",
            "webhook subscription not found"
        ))
}
