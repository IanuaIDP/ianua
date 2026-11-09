//! Reading the organization's subscription: its plan and cycle, its trial,
//! whether a payment method is on file and whether it is paid up.

use std::sync::Arc;

use ianua_domain::domains::organization::billing::subscription::OrgSubscription;
use ianua_domain::domains::organization::members::permission::{OrgBillingAction, OrgPermission};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::organization::OrgSubscriptionStore;
use crate::use_case::Query;
use crate::use_cases::organization::billing::lookup::existing_subscription;

/// The ports [`GetSubscriptionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetSubscriptionPorts {
    /// Organizations' subscriptions.
    pub subscriptions: Arc<dyn OrgSubscriptionStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Reads the caller's organization's subscription.
pub struct GetSubscriptionUseCase {
    ports: GetSubscriptionPorts,
}

impl GetSubscriptionUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetSubscriptionPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetSubscriptionUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<OrgSubscription, AppError>;

    /// The organization's subscription as it stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not read the bill.
    /// - `AppError::NotFound` when the organization has no subscription.
    /// - `AppError::Internal` on storage failure.
    async fn execute(&self, caller: &OrgCaller, (): ()) -> Result<OrgSubscription, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Billing(OrgBillingAction::View),
            )
            .map_err(AppError::from_domain)?;
        existing_subscription(self.ports.subscriptions.as_ref(), organization.id()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgSubscriptionStore, SubscriptionShape, test_subscription,
    };
    use crate::test_support::{block_on, test_org_caller};

    fn read(actors: FakeOrgActors) -> Result<OrgSubscription, AppError> {
        let acme = test_org_caller().organization_id();
        let uc = GetSubscriptionUseCase::new(GetSubscriptionPorts {
            subscriptions: Arc::new(FakeOrgSubscriptionStore::holding([test_subscription(
                acme,
                SubscriptionShape::free(),
            )])),
            org_actors: Arc::new(actors),
        });
        block_on(uc.execute(&test_org_caller(), ()))
    }

    /// Bob, Acme's billing contact, reads its subscription. Acme is on
    /// Free.
    #[test]
    fn the_billing_contact_reads_the_subscription() {
        let subscription = read(FakeOrgActors::in_role(OrgRole::Billing)).unwrap();

        assert_eq!(subscription.plan(), OrganizationPlan::Free);
    }

    /// Acme has no subscription on record. It is not found.
    #[test]
    fn a_missing_subscription_is_not_found() {
        let uc = GetSubscriptionUseCase::new(GetSubscriptionPorts::fakes());

        let result = block_on(uc.execute(&test_org_caller(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A plain member is refused access to the organization's subscription.
    #[test]
    fn a_plain_member_is_refused() {
        let result = read(FakeOrgActors::in_role(OrgRole::Member));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller must authenticate before reading a subscription.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
