//! Choosing a sold plan: a member with the billing right moves their
//! organization to Free, Starter or Business, once what it uses fits.
//!
//! A paid plan needs a payment method on file or starts the organization's
//! one trial. Custom is arranged by the platform, never chosen here.

use std::sync::Arc;

use ianua_domain::domains::organization::billing::payment::SubscriptionState;
use ianua_domain::domains::organization::billing::subscription::{
    OrgSubscription, PlanChoice, PlanMove,
};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::permission::{OrgBillingAction, OrgPermission};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, OrganizationId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSubscriptionStore, OrganizationStore, PlanUsageCounter};
use crate::use_case::Command;
use crate::use_cases::organization::billing::lookup::{current_usage, existing_subscription};
use crate::use_cases::organization::billing::records::PlanRecords;

/// The ports [`ChoosePlanUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChoosePlanPorts {
    /// Organizations, whose plan follows the subscription.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Loads and saves the organization's selected service terms.
    pub subscriptions: Arc<dyn OrgSubscriptionStore>,
    /// Counts what an organization uses now.
    pub usage: Arc<dyn PlanUsageCounter>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Moves the caller's organization to the sold plan they choose.
pub struct ChoosePlanUseCase {
    ports: ChoosePlanPorts,
}

impl ChoosePlanUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ChoosePlanPorts) -> Self {
        Self { ports }
    }

    /// The subscription of `organization_id` moved to `choice` by
    /// `control`, with the move the organization's plan follows. `None`
    /// when it is already on that plan and cycle.
    async fn moved(
        &self,
        organization_id: &OrganizationId,
        choice: PlanChoice,
        control: &OrgControl<'_>,
    ) -> Result<(OrgSubscription, Option<PlanMove>), AppError> {
        let store = self.ports.subscriptions.as_ref();
        let mut subscription = existing_subscription(store, organization_id).await?;
        if is_current(&subscription, choice) {
            return Ok((subscription, None));
        }
        let usage = current_usage(self.ports.usage.as_ref(), organization_id).await?;
        let change = subscription
            .choose_plan(choice, &usage, control)
            .map_err(AppError::from_domain)?;
        Ok((subscription, Some(change)))
    }
}

impl Command for ChoosePlanUseCase {
    type Caller = OrgCaller;
    type Input = PlanChoice;
    type Output = Result<SubscriptionState, AppError>;

    /// Counts what the organization uses, moves its subscription and then
    /// its plan to `choice`, saves both, and records
    /// `organization.subscription_changed` and, when the plan itself
    /// changed, `organization.plan_changed`. Returns where the subscription
    /// stands now: trialing when the choice started the trial. Choosing the
    /// plan and cycle it is already on changes and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without billing rights or for Custom/self-hosted plans.
    /// - `AppError::NotFound` for no subscription; `Conflict` for excessive usage, payment owed, or a paid plan without payment method/trial.
    /// - `AppError::Domain` for a closed organization; `Internal` on storage, counting or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        choice: PlanChoice,
    ) -> Result<SubscriptionState, AppError> {
        let (mut organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let organization_id = *organization.id();
        ensure_may_choose(&control, &organization_id)?;
        let (mut subscription, change) = self.moved(&organization_id, choice, &control).await?;
        let Some(change) = change else {
            return Ok(subscription.state());
        };
        follow_move(&mut organization, change)?;
        let records = PlanRecords {
            subscriptions: self.ports.subscriptions.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        };
        records.save(&subscription, &organization).await?;
        let mut events = subscription.take_events();
        events.extend(organization.take_events());
        auditor
            .dispatch_by(&ActorRef::OrgUser(*actor.member().id()), events)
            .await
            .or_internal()?;
        Ok(subscription.state())
    }
}

/// Refuses a member who may not change what the organization pays, before
/// anything is counted.
///
/// # Errors
///
/// - `AppError::Forbidden` when they do not carry the billing update right.
fn ensure_may_choose(
    control: &OrgControl<'_>,
    organization_id: &OrganizationId,
) -> Result<(), AppError> {
    control
        .ensure_may(
            organization_id,
            OrgPermission::Billing(OrgBillingAction::Update),
        )
        .map_err(AppError::from_domain)
}

/// Whether `subscription` is already on the plan and cycle `choice` names.
fn is_current(subscription: &OrgSubscription, choice: PlanChoice) -> bool {
    subscription.plan() == choice.plan && subscription.cycle() == choice.cycle
}

/// Moves `organization` to the plan `change` names, unless it is on it
/// already and only the billing cycle changed.
///
/// # Errors
///
/// - `AppError::Domain` when the organization is closed or holds more
///   tenants than the plan allows.
fn follow_move(organization: &mut Organization, change: PlanMove) -> Result<(), AppError> {
    if change.plan() == organization.plan() {
        return Ok(());
    }
    organization
        .change_plan(change)
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::payment::{
        BillingCycle, PaymentMethod, TrialUse,
    };
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::domains::organization::billing::usage::PlanUsage;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgSubscriptionStore, FakeOrganizationStore, FakePlanUsageCounter, SubscriptionShape,
        test_subscription,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    /// Acme's stores, with the use case acting through them.
    struct Setup {
        uc: ChoosePlanUseCase,
        orgs: Arc<FakeOrganizationStore>,
        subscriptions: Arc<FakeOrgSubscriptionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(actors: FakeOrgActors, shape: SubscriptionShape, usage: PlanUsage) -> Self {
            let id = test_org_caller().organization_id();
            let orgs = Arc::new(FakeOrganizationStore::empty());
            let subscriptions = Arc::new(FakeOrgSubscriptionStore::holding([test_subscription(
                id, shape,
            )]));
            Self {
                uc: ChoosePlanUseCase::new(ChoosePlanPorts {
                    organizations: orgs.clone(),
                    subscriptions: subscriptions.clone(),
                    usage: Arc::new(FakePlanUsageCounter::counting(usage)),
                    org_actors: Arc::new(actors),
                }),
                orgs,
                subscriptions,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn as_role(role: OrgRole) -> Self {
            Self::with(
                FakeOrgActors::in_role(role),
                SubscriptionShape::free(),
                PlanUsage::default(),
            )
        }

        fn choose(&self, plan: OrganizationPlan) -> Result<SubscriptionState, AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                PlanChoice {
                    plan,
                    cycle: BillingCycle::Monthly,
                },
            ))
        }

        fn stored_plan(&self) -> Option<OrganizationPlan> {
            self.orgs
                .stored(&test_org_caller().organization_id())
                .map(|org| org.plan())
        }

        fn subscribed_plan(&self) -> OrganizationPlan {
            self.subscriptions
                .stored(&test_org_caller().organization_id())
                .unwrap()
                .plan()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn nothing_changed(&self) -> bool {
            self.stored_plan().is_none()
                && self.subscribed_plan() == OrganizationPlan::Free
                && self.recorded().is_empty()
        }
    }

    /// Ann, Acme's owner, moves it from Free to Starter without a card. Its
    /// one trial starts, both the subscription and the organization move,
    /// and both changes are recorded.
    #[test]
    fn choosing_a_paid_plan_without_a_card_starts_the_trial() {
        let setup = Setup::as_role(OrgRole::Owner);

        let state = setup.choose(OrganizationPlan::Starter).unwrap();

        assert!(matches!(state, SubscriptionState::Trialing { .. }));
        assert_eq!(setup.stored_plan(), Some(OrganizationPlan::Starter));
        assert_eq!(setup.subscribed_plan(), OrganizationPlan::Starter);
        assert_eq!(
            setup.recorded(),
            [
                "organization.subscription_changed",
                "organization.plan_changed"
            ]
        );
    }

    /// Bob is Acme's billing contact. He runs the subscription, so he may
    /// choose its plan.
    #[test]
    fn the_billing_contact_chooses_the_plan() {
        let setup = Setup::as_role(OrgRole::Billing);

        setup.choose(OrganizationPlan::Business).unwrap();

        assert_eq!(setup.stored_plan(), Some(OrganizationPlan::Business));
    }

    /// Ann picks the plan and cycle Acme is already on. Nothing changes
    /// and nothing is recorded.
    #[test]
    fn choosing_the_current_plan_changes_nothing() {
        let setup = Setup::as_role(OrgRole::Owner);

        let state = setup.choose(OrganizationPlan::Free).unwrap();

        assert_eq!(state, SubscriptionState::Active);
        assert!(setup.nothing_changed());
    }

    /// An admin cannot choose Business; the subscription stays on Free,
    /// with no organization save or audit record.
    #[test]
    fn an_admin_may_not_change_what_the_organization_pays() {
        let setup = Setup::as_role(OrgRole::Admin);

        let result = setup.choose(OrganizationPlan::Business);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.nothing_changed());
    }

    /// Even an owner cannot choose Custom; the subscription stays on Free,
    /// with no organization save or audit record.
    #[test]
    fn custom_is_never_chosen() {
        let setup = Setup::as_role(OrgRole::Owner);

        let result = setup.choose(OrganizationPlan::Custom);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.nothing_changed());
    }

    /// Acme's 20,000 users exceed Starter's allowance, so the move is
    /// refused without changing the subscription, saving or recording.
    #[test]
    fn a_plan_the_usage_does_not_fit_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            SubscriptionShape::free(),
            PlanUsage {
                users: 20_000,
                ..PlanUsage::default()
            },
        );

        let result = setup.choose(OrganizationPlan::Starter);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.nothing_changed());
    }

    /// With its trial used and no payment method, Acme cannot move to
    /// Business; its Free subscription stays and nothing is saved or recorded.
    #[test]
    fn a_used_trial_without_a_card_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            SubscriptionShape {
                trial: TrialUse::Used,
                ..SubscriptionShape::free()
            },
            PlanUsage::default(),
        );

        let result = setup.choose(OrganizationPlan::Business);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.nothing_changed());
    }

    /// An outstanding payment prevents choosing Business, with no
    /// organization save or audit record.
    #[test]
    fn a_paid_plan_is_refused_while_a_payment_is_owed() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            SubscriptionShape {
                state: SubscriptionState::PastDue {
                    since: clock::now(),
                },
                payment: PaymentMethod::Missing,
                ..SubscriptionShape::free()
            },
            PlanUsage::default(),
        );

        let result = setup.choose(OrganizationPlan::Business);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.stored_plan().is_none());
        assert!(setup.recorded().is_empty());
    }

    /// Acme has no subscription on record. It is not found.
    #[test]
    fn an_organization_without_a_subscription_is_not_found() {
        let uc = ChoosePlanUseCase::new(ChoosePlanPorts::fakes());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = block_on(uc.execute(
            &test_org_caller(),
            &test_auditor(audit),
            PlanChoice {
                plan: OrganizationPlan::Starter,
                cycle: BillingCycle::Annual,
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot choose a plan; the subscription stays
    /// on Free and nothing is saved or recorded.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::refusing(Refusal::SignedOut),
            SubscriptionShape::free(),
            PlanUsage::default(),
        );

        let result = setup.choose(OrganizationPlan::Starter);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.nothing_changed());
    }
}
