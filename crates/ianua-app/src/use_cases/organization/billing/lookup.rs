//! Loading the records the billing use cases start from: an organization's
//! subscription and what it uses now.

use ianua_domain::domains::organization::billing::subscription::OrgSubscription;
use ianua_domain::domains::organization::billing::usage::PlanUsage;
use ianua_domain::message;
use ianua_domain::types::OrganizationId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::{OrgSubscriptionStore, PlanUsageCounter};

/// The subscription of `organization_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the organization has no subscription.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_subscription(
    store: &dyn OrgSubscriptionStore,
    organization_id: &OrganizationId,
) -> Result<OrgSubscription, AppError> {
    store
        .find_by_organization(organization_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "messaging-subscription-not-found",
            "subscription not found"
        ))
}

/// What `organization_id` uses now, counted fresh just before a plan is
/// checked against it.
///
/// # Errors
///
/// - `AppError::Internal` when a count cannot be read.
pub(super) async fn current_usage(
    counter: &dyn PlanUsageCounter,
    organization_id: &OrganizationId,
) -> Result<PlanUsage, AppError> {
    counter.usage(organization_id).await.or_internal()
}
