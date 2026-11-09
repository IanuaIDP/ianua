//! Reading what the organization uses against what its plan allows, for
//! its billing page.

use std::sync::Arc;

use ianua_domain::domains::organization::billing::plan::{OrganizationPlan, PlanLimits};
use ianua_domain::domains::organization::billing::usage::PlanUsage;
use ianua_domain::domains::organization::members::permission::{OrgBillingAction, OrgPermission};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::organization::PlanUsageCounter;
use crate::use_case::Query;
use crate::use_cases::organization::billing::lookup::current_usage;

/// What the organization uses next to what it may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanUsageReport {
    /// The service tier used to interpret this organization's usage.
    pub plan: OrganizationPlan,
    /// What it may use: its plan's limits, or those negotiated for it.
    pub limits: PlanLimits,
    /// What it uses now.
    pub usage: PlanUsage,
}

/// The ports [`GetPlanUsageUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPlanUsagePorts {
    /// Counts what an organization uses now.
    pub usage: Arc<dyn PlanUsageCounter>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Reads the caller's organization's usage against its limits.
pub struct GetPlanUsageUseCase {
    ports: GetPlanUsagePorts,
}

impl GetPlanUsageUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPlanUsagePorts) -> Self {
        Self { ports }
    }
}

impl Query for GetPlanUsageUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<PlanUsageReport, AppError>;

    /// The organization's plan, the limits it works under and what it uses
    /// now, counted fresh.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not read the bill.
    /// - `AppError::Internal` when a count cannot be read.
    async fn execute(&self, caller: &OrgCaller, (): ()) -> Result<PlanUsageReport, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Billing(OrgBillingAction::View),
            )
            .map_err(AppError::from_domain)?;
        let usage = current_usage(self.ports.usage.as_ref(), organization.id()).await?;
        Ok(PlanUsageReport {
            plan: organization.plan(),
            limits: organization.limits(),
            usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::FakePlanUsageCounter;
    use crate::test_support::{block_on, test_org_caller};

    fn read(actors: FakeOrgActors) -> Result<PlanUsageReport, AppError> {
        let uc = GetPlanUsageUseCase::new(GetPlanUsagePorts {
            usage: Arc::new(FakePlanUsageCounter::counting(PlanUsage {
                users: 42,
                tenants: 1,
                ..PlanUsage::default()
            })),
            org_actors: Arc::new(actors),
        });
        block_on(uc.execute(&test_org_caller(), ()))
    }

    /// Bob, Acme's billing contact, opens the billing page. He sees 42 of
    /// Free's 100 users in use.
    #[test]
    fn the_billing_contact_sees_usage_against_the_limits() {
        let report = read(FakeOrgActors::in_role(OrgRole::Billing)).unwrap();

        assert_eq!(report.plan, OrganizationPlan::Free);
        assert_eq!(report.usage.users, 42);
        assert_eq!(report.limits, PlanLimits::free());
    }

    /// Vera is a viewer, who reads the bill too. She sees the same page.
    #[test]
    fn a_viewer_reads_the_usage() {
        assert!(read(FakeOrgActors::in_role(OrgRole::Viewer)).is_ok());
    }

    /// A plain member is refused access to the organization's usage report.
    #[test]
    fn a_plain_member_is_refused() {
        let result = read(FakeOrgActors::in_role(OrgRole::Member));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives no usage report and must authenticate.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
