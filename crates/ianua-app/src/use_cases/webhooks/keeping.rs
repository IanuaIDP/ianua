//! Storing a subscription after a change.

use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::{AppError, OrInternal};
use crate::ports::webhooks::WebhookStore;
use crate::tenancy::ScopedTenant;

/// Stores `subscription` in `store` as it now stands in `tenant`.
///
/// # Errors
///
/// `AppError::Internal` on storage failure.
pub(in crate::use_cases::webhooks) async fn keep_subscription(
    store: &dyn WebhookStore,
    tenant: &ScopedTenant,
    subscription: &WebhookSubscription<ResolvedTenant>,
) -> Result<(), AppError> {
    store.save(tenant, subscription).await.or_internal()
}
