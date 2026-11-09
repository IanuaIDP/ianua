//! Listing the plans on sale, with their prices and the limits each sets,
//! for the pricing page and the plan picker.
//!
//! Public: anyone may read what is for sale, signed in or not.

use ianua_domain::domains::organization::billing::catalog::{PlanTier, plan_catalog};

use crate::use_case::Query;

/// Lists the plan catalog.
#[derive(Debug, Default)]
pub struct ListPlansUseCase;

impl ListPlansUseCase {
    /// A use case reading the catalog the domain holds.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Query for ListPlansUseCase {
    type Caller = ();
    type Input = ();
    type Output = Vec<PlanTier>;

    /// Every plan in the order the pricing page shows them: Free, Starter,
    /// Business, Custom. The limits listed are the limits enforced.
    async fn execute(&self, (): &(), (): ()) -> Vec<PlanTier> {
        plan_catalog()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;

    use super::*;
    use crate::test_support::block_on;

    /// Ann opens the pricing page. She sees the four plans on sale, never
    /// the self-hosted one an installation holds.
    #[test]
    fn the_catalog_lists_the_plans_on_sale() {
        let plans = block_on(ListPlansUseCase::new().execute(&(), ()));

        let listed: Vec<OrganizationPlan> = plans.iter().map(|tier| tier.plan).collect();
        assert_eq!(
            listed,
            [
                OrganizationPlan::Free,
                OrganizationPlan::Starter,
                OrganizationPlan::Business,
                OrganizationPlan::Custom
            ]
        );
    }
}
