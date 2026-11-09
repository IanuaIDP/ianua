//! Arranging a plan: an operator moves an organization to the plan sales
//! agreed, Custom included, with the limits negotiated for it.
//!
//! An arranged plan is invoiced by hand, so no payment method or trial is
//! asked for. What the organization uses must still fit.

use std::sync::Arc;

use ianua_domain::domains::organization::billing::subscription::{Arrangement, OrgSubscription};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::OrganizationId;

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSubscriptionStore, OrganizationStore, PlanUsageCounter};
use crate::use_case::Command;
use crate::use_cases::organization::billing::lookup::{current_usage, existing_subscription};
use crate::use_cases::organization::billing::records::PlanRecords;
use crate::use_cases::organization::lookup::existing_organization;

/// Which organization moves to which arranged plan.
pub struct ArrangePlanRequest {
    /// The organization whose plan changes.
    pub organization_id: OrganizationId,
    /// The plan, its billing cycle and the limits it works under.
    pub arrangement: Arrangement,
}

/// The ports [`ArrangePlanUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ArrangePlanPorts {
    /// Organizations, whose plan follows the subscription.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Loads and saves the organization's negotiated service terms.
    pub subscriptions: Arc<dyn OrgSubscriptionStore>,
    /// Counts what an organization uses now.
    pub usage: Arc<dyn PlanUsageCounter>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Moves an organization to the plan an operator arranges for it.
pub struct ArrangePlanUseCase {
    ports: ArrangePlanPorts,
}

impl ArrangePlanUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ArrangePlanPorts) -> Self {
        Self { ports }
    }
}

impl Command for ArrangePlanUseCase {
    type Caller = OperatorCaller;
    type Input = ArrangePlanRequest;
    type Output = Result<(), AppError>;

    /// Counts what the organization uses, moves its subscription and then
    /// its plan and limits to `request.arrangement`, saves both, and
    /// records `organization.subscription_changed` and
    /// `organization.plan_changed`. Arranging exactly what the organization
    /// already has changes and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for a missing operator/key; `Forbidden` for an operator unable to act.
    /// - `AppError::NotFound` for a missing organization/subscription; `Conflict` for usage above arranged limits.
    /// - `AppError::Domain` for a self-hosted plan, negotiated limits outside Custom, or a closed organization.
    /// - `AppError::Internal` on storage, counting or audit failure.
    async fn execute(
        &self,
        operator: &OperatorCaller,
        auditor: &RequestAuditor,
        request: ArrangePlanRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.operator_authorities.authority(operator).await?;
        let id = request.organization_id;
        let organizations = self.ports.organizations.as_ref();
        let mut organization = existing_organization(organizations, &id).await?;
        let subscriptions = self.ports.subscriptions.as_ref();
        let mut subscription = existing_subscription(subscriptions, &id).await?;
        if is_arranged_already(&organization, &subscription, &request.arrangement) {
            return Ok(());
        }
        let usage = current_usage(self.ports.usage.as_ref(), &id).await?;
        let change = subscription
            .arrange(request.arrangement, &usage, &authority)
            .map_err(AppError::from_domain)?;
        organization
            .change_plan(change)
            .map_err(AppError::from_domain)?;
        let records = PlanRecords {
            subscriptions,
            organizations,
        };
        records.save(&subscription, &organization).await?;
        let mut events = subscription.take_events();
        events.extend(organization.take_events());
        auditor
            .dispatch_by(&authority.actor(), events)
            .await
            .or_internal()
    }
}

/// Whether `organization` already stands on the plan, cycle and terms
/// `arrangement` names.
fn is_arranged_already(
    organization: &Organization,
    subscription: &OrgSubscription,
    arrangement: &Arrangement,
) -> bool {
    organization.plan() == arrangement.plan
        && organization.terms() == &arrangement.terms
        && subscription.cycle() == arrangement.cycle
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::negotiated::{NegotiatedLimits, PlanTerms};
    use ianua_domain::domains::organization::billing::payment::BillingCycle;
    use ianua_domain::domains::organization::billing::plan::{OrganizationPlan, PlanLimits};
    use ianua_domain::domains::organization::billing::usage::PlanUsage;
    use ianua_domain::types::OperatorId;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::notifications::operator_caller;
    use crate::test_support::organization::{
        FakeOrgSubscriptionStore, FakeOrganizationStore, FakePlanUsageCounter, SubscriptionShape,
        org_store_with, test_org, test_subscription,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Setup {
        uc: ArrangePlanUseCase,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
        org_id: OrganizationId,
    }

    fn setup_with(operators: FakeOperatorAuthorities, usage: PlanUsage) -> Setup {
        let org_id = OrganizationId::new();
        let orgs = org_store_with([test_org(org_id, "acme")]);
        let subscriptions = FakeOrgSubscriptionStore::holding([test_subscription(
            org_id,
            SubscriptionShape::free(),
        )]);
        Setup {
            uc: ArrangePlanUseCase::new(ArrangePlanPorts {
                organizations: orgs.clone(),
                subscriptions: Arc::new(subscriptions),
                usage: Arc::new(FakePlanUsageCounter::counting(usage)),
                operator_authorities: Arc::new(operators),
            }),
            orgs,
            audit: Arc::new(FakeEventDispatcher::new()),
            org_id,
        }
    }

    fn setup() -> Setup {
        setup_with(FakeOperatorAuthorities::admitting(), PlanUsage::default())
    }

    fn standard(plan: OrganizationPlan) -> Arrangement {
        Arrangement {
            plan,
            cycle: BillingCycle::Monthly,
            terms: PlanTerms::Standard,
        }
    }

    fn negotiated(plan: OrganizationPlan) -> Arrangement {
        let limits = PlanLimits {
            max_users: 250_000,
            ..PlanLimits::business()
        };
        Arrangement {
            plan,
            cycle: BillingCycle::Annual,
            terms: PlanTerms::Negotiated(NegotiatedLimits::new(limits).unwrap()),
        }
    }

    fn arrange(s: &Setup, arrangement: Arrangement) -> Result<(), AppError> {
        block_on(s.uc.execute(
            &operator_caller(OperatorId::new()),
            &test_auditor(s.audit.clone()),
            ArrangePlanRequest {
                organization_id: s.org_id,
                arrangement,
            },
        ))
    }

    fn stored(s: &Setup) -> Organization {
        s.orgs.stored(&s.org_id).unwrap()
    }

    fn recorded(s: &Setup) -> Vec<String> {
        s.audit.records.lock().unwrap().clone()
    }

    /// Sam, an operator, arranges Custom for Acme with the 250,000 users
    /// sales agreed. Acme is on Custom and its limits are the agreed ones,
    /// and both changes are recorded.
    #[test]
    fn an_arranged_custom_plan_carries_its_negotiated_limits() {
        let s = setup();

        arrange(&s, negotiated(OrganizationPlan::Custom)).unwrap();

        assert_eq!(stored(&s).plan(), OrganizationPlan::Custom);
        assert_eq!(stored(&s).limits().max_users, 250_000);
        assert_eq!(
            recorded(&s),
            [
                "organization.subscription_changed",
                "organization.plan_changed"
            ]
        );
    }

    /// Sam arranges the Free plan Acme already has. Nothing changes and
    /// nothing is recorded.
    #[test]
    fn arranging_what_the_organization_has_changes_nothing() {
        let s = setup();

        arrange(&s, standard(OrganizationPlan::Free)).unwrap();

        assert!(recorded(&s).is_empty());
    }

    /// Negotiated limits on Starter are refused; Acme stays on Free and
    /// neither the subscription nor the plan change is recorded.
    #[test]
    fn negotiated_limits_on_a_sold_plan_are_refused() {
        let s = setup();

        let result = arrange(&s, negotiated(OrganizationPlan::Starter));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(stored(&s).plan(), OrganizationPlan::Free);
        assert!(recorded(&s).is_empty());
    }

    /// An operator cannot arrange the self-hosted plan for Acme, and the
    /// refused arrangement records nothing.
    #[test]
    fn arranging_self_hosted_is_refused() {
        let s = setup();

        let result = arrange(&s, standard(OrganizationPlan::SelfHosted));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(recorded(&s).is_empty());
    }

    /// Acme's 200 users exceed Free's allowance, so arranging that plan
    /// with a different billing cycle is refused without an audit record.
    #[test]
    fn an_arrangement_the_usage_does_not_fit_is_refused() {
        let s = setup_with(
            FakeOperatorAuthorities::admitting(),
            PlanUsage {
                users: 200,
                ..PlanUsage::default()
            },
        );

        let result = arrange(
            &s,
            Arrangement {
                cycle: BillingCycle::Annual,
                ..standard(OrganizationPlan::Free)
            },
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(recorded(&s).is_empty());
    }

    /// Sam names an organization that does not exist. It is not found.
    #[test]
    fn an_unknown_organization_is_not_found() {
        let s = setup();
        let use_case = ArrangePlanUseCase::new(ArrangePlanPorts::fakes());

        let result = block_on(use_case.execute(
            &operator_caller(OperatorId::new()),
            &test_auditor(s.audit.clone()),
            ArrangePlanRequest {
                organization_id: OrganizationId::new(),
                arrangement: standard(OrganizationPlan::Starter),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Refused operator authority prevents an upgrade; Acme stays on Free
    /// and nothing is recorded.
    #[test]
    fn an_operator_turned_away_is_refused() {
        let s = setup_with(
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
            PlanUsage::default(),
        );

        let result = arrange(&s, standard(OrganizationPlan::Business));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stored(&s).plan(), OrganizationPlan::Free);
        assert!(recorded(&s).is_empty());
    }
}
