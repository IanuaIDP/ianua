//! Keeping a plan move: the subscription that made it, then the
//! organization it moved, as choosing and arranging a plan both change the
//! two.

use ianua_domain::domains::organization::billing::subscription::OrgSubscription;
use ianua_domain::domains::organization::lifecycle::Organization;

use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSubscriptionStore, OrganizationStore};

/// Where subscriptions and the organizations they belong to are kept.
#[derive(Clone, Copy)]
pub(super) struct PlanRecords<'a> {
    /// Organizations' subscriptions.
    pub(super) subscriptions: &'a dyn OrgSubscriptionStore,
    /// Saves the owning organization after its subscription changes.
    pub(super) organizations: &'a dyn OrganizationStore,
}

impl PlanRecords<'_> {
    /// Saves `subscription`, then `organization`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when either cannot be saved.
    pub(super) async fn save(
        &self,
        subscription: &OrgSubscription,
        organization: &Organization,
    ) -> Result<(), AppError> {
        self.subscriptions.save(subscription).await.or_internal()?;
        self.organizations.save(organization).await.or_internal()
    }
}
