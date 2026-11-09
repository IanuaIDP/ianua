//! What an organization pays for over time: its plan, its trial, how it
//! pays and whether it is paid up.
//!
//! The organization's plan follows its subscription. Every move of the plan
//! starts here, as a [`PlanMove`] this hands out once it checked the move:
//! a member choosing a sold tier with the billing right, a trial or a
//! payment method behind it, and usage that fits; or an operator arranging
//! a plan, Custom included, with the limits negotiated for it.
//! [`Organization::change_plan`] takes nothing else.
//!
//! [`Organization::change_plan`]: crate::domains::organization::lifecycle::Organization::change_plan

mod trial;

use time::{Duration, OffsetDateTime};

use crate::domains::operator::control::OperatorAuthority;
use crate::domains::organization::billing::negotiated::PlanTerms;
use crate::domains::organization::billing::payment::{
    BillingCycle, PaymentMethod, PaymentReference, SubscriptionState, TrialUse,
};
use crate::domains::organization::billing::plan::{OrganizationPlan, PlanSale};
use crate::domains::organization::billing::subscription::trial::{opening_standing, trial_from};
use crate::domains::organization::billing::usage::PlanUsage;
use crate::domains::organization::events::billing::{
    OrgPaymentFailed, OrgPaymentMethodChanged, OrgPaymentSettled, OrgSubscriptionChanged,
    OrgSubscriptionStarted, OrgTrialEnded,
};
use crate::domains::organization::founding::Founding;
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::permission::{OrgBillingAction, OrgPermission};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{OperatorId, OrgUserId, OrganizationId};

/// The right a member needs to choose the organization's plan.
const CHOOSES_PLAN: OrgPermission = OrgPermission::Billing(OrgBillingAction::Update);

/// Who moved a subscription to another plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubscriptionChanger {
    /// A member of the organization, with the billing right.
    Member(OrgUserId),
    /// A platform operator, arranging it.
    Operator(OperatorId),
}

impl SubscriptionChanger {
    /// Who it was, as a record names the kind.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Member(_) => "member",
            Self::Operator(_) => "operator",
        }
    }
}

/// A sold tier a member chooses, and how often to pay for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanChoice {
    /// The tier: Free, Starter or Business.
    pub plan: OrganizationPlan,
    /// How often it is billed.
    pub cycle: BillingCycle,
}

/// A plan an operator arranges, with the terms sales agreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrangement {
    /// The plan, Custom included.
    pub plan: OrganizationPlan,
    /// How often it is billed.
    pub cycle: BillingCycle,
    /// The limits it works under.
    pub terms: PlanTerms,
}

/// Proof that a subscription checked a move of the organization's plan,
/// for [`Organization::change_plan`] to carry out.
///
/// [`Organization::change_plan`]: crate::domains::organization::lifecycle::Organization::change_plan
#[derive(Debug)]
pub struct PlanMove {
    organization_id: OrganizationId,
    plan: OrganizationPlan,
    terms: PlanTerms,
}

impl PlanMove {
    /// The organization whose plan moves.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The plan it moves to.
    #[must_use]
    pub fn plan(&self) -> OrganizationPlan {
        self.plan
    }

    /// The limits it works under there, handed to the organization.
    pub(crate) fn into_terms(self) -> PlanTerms {
        self.terms
    }

    /// A move of `organization_id` to `plan` under `terms`, as a test
    /// says a subscription checked it.
    #[cfg(test)]
    pub(crate) fn assumed(
        organization_id: OrganizationId,
        plan: OrganizationPlan,
        terms: PlanTerms,
    ) -> Self {
        Self {
            organization_id,
            plan,
            terms,
        }
    }
}

/// An organization's subscription as stored, for rebuilding it with
/// [`OrgSubscription::reconstitute`].
pub struct OrgSubscriptionRow {
    /// The organization subscribed.
    pub organization_id: OrganizationId,
    /// The entitlement selection used with billing state to determine subscription service.
    pub plan: OrganizationPlan,
    /// How often it is billed.
    pub cycle: BillingCycle,
    /// Where it stands.
    pub state: SubscriptionState,
    /// How it pays.
    pub payment: PaymentMethod,
    /// Whether it has had its trial.
    pub trial: TrialUse,
    /// When it started.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// What one organization pays for, and whether it is paid up.
#[derive(Debug)]
pub struct OrgSubscription {
    organization_id: OrganizationId,
    plan: OrganizationPlan,
    cycle: BillingCycle,
    state: SubscriptionState,
    payment: PaymentMethod,
    trial: TrialUse,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl OrgSubscription {
    /// Starts the subscription of `organization`, just founded, on the plan
    /// it was founded on. A plan with a trial starts trialing, and uses the
    /// organization's one trial. Raises `organization.subscription_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `founding` is another organization's.
    pub fn start(
        founding: &Founding,
        organization: &Organization,
        cycle: BillingCycle,
    ) -> Result<Self, DomainError> {
        if founding.organization_id() != organization.id() {
            return Err(DomainError::forbidden(message!(
                "organization-a-founding-starts-the-subscription-of",
                "a founding starts the subscription of its own organization only"
            )));
        }
        let now = crate::shared::clock::now();
        let plan = organization.plan();
        let (state, trial) = opening_standing(plan, now);
        let mut subscription = Self {
            organization_id: *organization.id(),
            plan,
            cycle,
            state,
            payment: PaymentMethod::Missing,
            trial,
            created_at: now,
            updated_at: now,
            raised: RaisedEvents::default(),
        };
        subscription
            .raised
            .raise_organization(OrgSubscriptionStarted {
                organization_id: subscription.organization_id,
                plan,
                state,
                occurred_at: now,
            });
        Ok(subscription)
    }

    /// Rebuilds a subscription from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row trials a plan that has
    ///   no trial, trials without having used the trial, or says it changed
    ///   before it started.
    pub fn reconstitute(row: OrgSubscriptionRow) -> Result<Self, DomainError> {
        let trialing = matches!(row.state, SubscriptionState::Trialing { .. });
        RowCheck::of("organization subscription")
            .holds(
                !trialing || row.plan.trial_days().is_some(),
                "a trial on a plan that has none",
            )
            .holds(
                !trialing || row.trial == TrialUse::Used,
                "a trial running that was never used",
            )
            .in_order(row.created_at, row.updated_at, "changed before it started")
            .finish()?;
        Ok(Self {
            organization_id: row.organization_id,
            plan: row.plan,
            cycle: row.cycle,
            state: row.state,
            payment: row.payment,
            trial: row.trial,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The organization subscribed.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The entitlement selection used with billing state to determine subscription service.
    #[must_use]
    pub fn plan(&self) -> OrganizationPlan {
        self.plan
    }

    /// How often it is billed.
    #[must_use]
    pub fn cycle(&self) -> BillingCycle {
        self.cycle
    }

    /// Where it stands.
    #[must_use]
    pub fn state(&self) -> SubscriptionState {
        self.state
    }

    /// How it pays.
    #[must_use]
    pub fn payment(&self) -> &PaymentMethod {
        &self.payment
    }

    /// Whether it has had its trial.
    #[must_use]
    pub fn trial(&self) -> TrialUse {
        self.trial
    }

    /// When it started.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether a payment has been owed for longer than `grace`, so the
    /// platform suspends the organization until it is paid.
    #[must_use]
    pub fn overdue_beyond(&self, grace: Duration) -> bool {
        let SubscriptionState::PastDue { since } = self.state else {
            return false;
        };
        crate::shared::clock::now() >= since.saturating_add(grace)
    }

    /// Moves to the sold tier `choice` names, as `by` decides, once `usage`
    /// fits it. Raises `organization.subscription_changed`. Returns the
    /// [`PlanMove`] the organization's plan follows.
    ///
    /// A paid tier needs a payment method, or starts the organization's one
    /// trial. While a payment is owed, only Free may be chosen, and what is
    /// owed stays owed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the plan.
    /// - [`DomainError::Forbidden`] when the tier is Custom or self-hosted,
    ///   which only the platform arranges, or the organization is on the
    ///   self-hosted plan, which never moves.
    /// - [`DomainError::Conflict`] when `usage` goes past the tier's limits.
    /// - [`DomainError::Conflict`] when a paid tier has no payment method and
    ///   no trial left, or a payment is owed.
    pub fn choose_plan(
        &mut self,
        choice: PlanChoice,
        usage: &PlanUsage,
        by: &OrgControl<'_>,
    ) -> Result<PlanMove, DomainError> {
        by.ensure_may(&self.organization_id, CHOOSES_PLAN)?;
        if choice.plan.sale() == PlanSale::Arranged || !self.plan.can_change_to(choice.plan) {
            return Err(DomainError::forbidden(message!(
                "organization-this-plan-is-arranged-by-the",
                "this plan is arranged by the platform, not chosen"
            )));
        }
        choice.plan.default_limits().ensure_fits(usage)?;
        let (state, trial) = self.standing_on(choice.plan)?;
        self.trial = trial;
        let changer = SubscriptionChanger::Member(*by.by().id());
        let arrangement = Arrangement {
            plan: choice.plan,
            cycle: choice.cycle,
            terms: PlanTerms::Standard,
        };
        Ok(self.move_to(arrangement, state, changer))
    }

    /// Moves to the plan `arrangement` names, with the terms sales agreed,
    /// as the operator `by` arranges it, once `usage` fits them. Raises
    /// `organization.subscription_changed`. Returns the [`PlanMove`] the
    /// organization's plan follows.
    ///
    /// An arranged plan is invoiced by hand, so no payment method or trial
    /// is asked for. What is owed stays owed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when either side is the
    ///   self-hosted plan.
    /// - [`DomainError::Validation`] when negotiated terms are given for a
    ///   plan other than Custom.
    /// - [`DomainError::Conflict`] when `usage` goes past the limits.
    pub fn arrange(
        &mut self,
        arrangement: Arrangement,
        usage: &PlanUsage,
        by: &OperatorAuthority,
    ) -> Result<PlanMove, DomainError> {
        if !self.plan.can_change_to(arrangement.plan) {
            return Err(DomainError::invalid_transition(message!(
                "organization-the-self-hosted-plan-is-fixed",
                "the self-hosted plan is fixed for as long as the installation exists"
            )));
        }
        if !arrangement.terms.fit(arrangement.plan) {
            return Err(DomainError::invalid(message!(
                "organization-negotiated-limits-belong-to-a-custom",
                "negotiated limits belong to a Custom plan only"
            )));
        }
        arrangement
            .terms
            .limits_on(arrangement.plan)
            .ensure_fits(usage)?;
        let state = self.past_due_or(SubscriptionState::Active);
        let changer = SubscriptionChanger::Operator(*by.operator());
        Ok(self.move_to(arrangement, state, changer))
    }

    /// Ends a trial whose time ran out. With a payment method the
    /// organization starts paying; without one, a payment is owed from the
    /// trial's end. Raises `organization.trial_ended`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when no trial is running, or it has not
    ///   run out yet.
    pub fn end_trial(&mut self) -> Result<(), DomainError> {
        let SubscriptionState::Trialing { ends_at } = self.state else {
            return Err(DomainError::conflict(message!(
                "organization-no-trial-is-running",
                "no trial is running"
            )));
        };
        if crate::shared::clock::now() < ends_at {
            return Err(DomainError::conflict(message!(
                "organization-the-trial-is-still-running",
                "the trial is still running"
            )));
        }
        self.state = match self.payment {
            PaymentMethod::OnFile(_) => SubscriptionState::Active,
            PaymentMethod::Missing => SubscriptionState::PastDue { since: ends_at },
        };
        self.touch();
        self.raised.raise_organization(OrgTrialEnded {
            organization_id: self.organization_id,
            plan: self.plan,
            state: self.state,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Records the payment method the provider reports for this
    /// organization, after a checkout a member finished there. Raises
    /// `organization.payment_method_changed`.
    pub fn record_payment_method(&mut self, reference: PaymentReference) {
        self.payment = PaymentMethod::OnFile(reference);
        self.touch();
        self.raised.raise_organization(OrgPaymentMethodChanged {
            organization_id: self.organization_id,
            occurred_at: self.updated_at,
        });
    }

    /// Records that a charge failed, so a payment is owed from now. A
    /// subscription already past due stays past due from when it fell due,
    /// and raises nothing. Raises `organization.payment_failed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] while a trial runs, when nothing is
    ///   charged.
    pub fn record_payment_failed(&mut self) -> Result<(), DomainError> {
        match self.state {
            SubscriptionState::Trialing { .. } => Err(DomainError::conflict(message!(
                "organization-nothing-is-charged-while-a-trial",
                "nothing is charged while a trial runs"
            ))),
            SubscriptionState::PastDue { .. } => Ok(()),
            SubscriptionState::Active => {
                self.touch();
                self.state = SubscriptionState::PastDue {
                    since: self.updated_at,
                };
                self.raised.raise_organization(OrgPaymentFailed {
                    organization_id: self.organization_id,
                    occurred_at: self.updated_at,
                });
                Ok(())
            }
        }
    }

    /// Records that what was owed is paid. A subscription that owed nothing
    /// is left as it is, and raises nothing. Raises
    /// `organization.payment_settled`.
    pub fn record_payment_settled(&mut self) {
        let SubscriptionState::PastDue { .. } = self.state else {
            return;
        };
        self.state = SubscriptionState::Active;
        self.touch();
        self.raised.raise_organization(OrgPaymentSettled {
            organization_id: self.organization_id,
            occurred_at: self.updated_at,
        });
    }

    /// Where the subscription stands once moved to `plan`, and whether that
    /// used the trial.
    fn standing_on(
        &self,
        plan: OrganizationPlan,
    ) -> Result<(SubscriptionState, TrialUse), DomainError> {
        match (plan.sale(), self.state, &self.payment) {
            (PlanSale::NoCost, _, _) => {
                Ok((self.past_due_or(SubscriptionState::Active), self.trial))
            }
            (_, SubscriptionState::PastDue { .. }, _) => Err(DomainError::conflict(message!(
                "organization-a-payment-is-owed-so-only",
                "a payment is owed, so only Free may be chosen until it is paid"
            ))),
            (_, SubscriptionState::Trialing { ends_at }, PaymentMethod::Missing) => {
                Ok((SubscriptionState::Trialing { ends_at }, TrialUse::Used))
            }
            (_, _, PaymentMethod::OnFile(_)) => Ok((SubscriptionState::Active, self.trial)),
            (_, SubscriptionState::Active, PaymentMethod::Missing) => {
                self.new_trial_on(plan, crate::shared::clock::now())
            }
        }
    }

    /// A trial of `plan` from `now`, when the organization has its trial
    /// left and the plan has one.
    fn new_trial_on(
        &self,
        plan: OrganizationPlan,
        now: OffsetDateTime,
    ) -> Result<(SubscriptionState, TrialUse), DomainError> {
        let trial = (self.trial == TrialUse::Unused)
            .then(|| trial_from(plan, now))
            .flatten();
        let Some(state) = trial else {
            return Err(DomainError::conflict(message!(
                "organization-a-paid-plan-needs-a-payment",
                "a paid plan needs a payment method first"
            )));
        };
        Ok((state, TrialUse::Used))
    }

    /// `otherwise`, unless a payment is owed, which stays owed.
    fn past_due_or(&self, otherwise: SubscriptionState) -> SubscriptionState {
        match self.state {
            SubscriptionState::PastDue { .. } => self.state,
            SubscriptionState::Trialing { .. } | SubscriptionState::Active => otherwise,
        }
    }

    /// Moves to the plan and cycle `arrangement` names, standing at `state`,
    /// as `by` did, and hands back the move for the organization.
    fn move_to(
        &mut self,
        arrangement: Arrangement,
        state: SubscriptionState,
        by: SubscriptionChanger,
    ) -> PlanMove {
        let Arrangement { plan, cycle, terms } = arrangement;
        let from = std::mem::replace(&mut self.plan, plan);
        self.cycle = cycle;
        self.state = state;
        self.touch();
        self.raised.raise_organization(OrgSubscriptionChanged {
            organization_id: self.organization_id,
            from,
            to: plan,
            cycle,
            state,
            by,
            occurred_at: self.updated_at,
        });
        PlanMove {
            organization_id: self.organization_id,
            plan,
            terms,
        }
    }

    /// Bumps the `updated_at` timestamp.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

impl RaisesComplete for OrgSubscription {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::billing::negotiated::NegotiatedLimits;
    use crate::domains::organization::billing::plan::PlanLimits;
    use crate::domains::organization::lifecycle::CreateOrganizationParams;
    use crate::domains::organization::members::control::tests::{acting, joined_as, session_of};
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword, OrgUser,
    };
    use crate::shared::config::{DisplayNameLimits, SlugLimits};
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;
    use crate::types::{DisplayName, Email, Label, TenantSlug};

    /// Acme, founded on `plan`, with its subscription started and Ann, its
    /// owner.
    fn founded(plan: OrganizationPlan) -> (Organization, OrgSubscription, OrgUser) {
        let (organization, founding) = Organization::create(CreateOrganizationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Acme Corp").unwrap(),
            contact_email: Email::new("billing@acme.com").unwrap(),
            display_name: DisplayName::new("Acme", &DisplayNameLimits::default()).unwrap(),
            plan,
        })
        .unwrap();
        let subscription =
            OrgSubscription::start(&founding, &organization, BillingCycle::Monthly).unwrap();
        let ann = OrgUser::create(
            CreateOrgUserParams {
                id: OrgUserId::new(),
                organization_id: *organization.id(),
                email: Email::new("ann@acme.com").unwrap(),
                display_name: DisplayName::new("Ann", &DisplayNameLimits::default()).unwrap(),
                password_hash: OrgPassword::NotSet,
                role: OrgRole::Owner,
            },
            AddedBy::Founding(founding),
        )
        .unwrap();
        (organization, subscription, ann)
    }

    /// What `member` gets back choosing `plan` monthly for `subscription`,
    /// with `usage`.
    fn chosen(
        subscription: &mut OrgSubscription,
        member: &OrgUser,
        plan: OrganizationPlan,
        usage: &PlanUsage,
    ) -> Result<PlanMove, DomainError> {
        let session = session_of(member);
        let choice = PlanChoice {
            plan,
            cycle: BillingCycle::Monthly,
        };
        subscription.choose_plan(choice, usage, &acting(member, &session))
    }

    /// An operator to arrange plans.
    fn operator() -> OperatorAuthority {
        OperatorAuthority::assumed(OperatorId::new())
    }

    /// A card the provider holds for Acme.
    fn card() -> PaymentReference {
        PaymentReference::new("pm_1NvXyz").unwrap()
    }

    /// Acme is founded on Starter. Its subscription starts with the 14-day
    /// trial, and the trial counts as used.
    #[test]
    fn a_plan_with_a_trial_starts_trialing() {
        let now = crate::shared::clock::now();
        let _frozen = crate::shared::clock::freeze(now);

        let (_, mut subscription, _) = founded(OrganizationPlan::Starter);

        assert_eq!(
            subscription.state(),
            SubscriptionState::Trialing {
                ends_at: now.saturating_add(Duration::days(14))
            }
        );
        assert_eq!(subscription.trial(), TrialUse::Used);
        assert_eq!(
            raised_complete_names(&mut subscription),
            vec!["organization.subscription_started".to_owned()]
        );
    }

    /// Acme is founded on Free. It is active, and keeps its trial for later.
    #[test]
    fn a_free_start_keeps_the_trial() {
        let (_, subscription, _) = founded(OrganizationPlan::Free);

        assert_eq!(subscription.state(), SubscriptionState::Active);
        assert_eq!(subscription.trial(), TrialUse::Unused);
    }

    /// Globex's founding cannot start a subscription for Acme, whose
    /// organization ID differs.
    #[test]
    fn a_founding_starts_only_its_own_organization() {
        let (acme, _, _) = founded(OrganizationPlan::Free);
        let (globex, globex_founding) = Organization::create(CreateOrganizationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("globex", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Globex").unwrap(),
            contact_email: Email::new("billing@globex.com").unwrap(),
            display_name: DisplayName::new("Globex", &DisplayNameLimits::default()).unwrap(),
            plan: OrganizationPlan::Free,
        })
        .unwrap();

        let refused = OrgSubscription::start(&globex_founding, &acme, BillingCycle::Monthly);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_ne!(globex.id(), acme.id());
    }

    /// Ann moves free Acme to Business without a card. Its one trial starts,
    /// and the organization's plan follows the move.
    #[test]
    fn upgrading_without_a_card_starts_the_trial() {
        let (mut acme, mut subscription, ann) = founded(OrganizationPlan::Free);

        let change = chosen(
            &mut subscription,
            &ann,
            OrganizationPlan::Business,
            &PlanUsage::default(),
        )
        .unwrap();
        acme.change_plan(change).unwrap();

        assert!(matches!(
            subscription.state(),
            SubscriptionState::Trialing { .. }
        ));
        assert_eq!(acme.plan(), OrganizationPlan::Business);
    }

    /// Members, viewers and admins cannot choose Business for Acme; a
    /// billing member can make that choice.
    #[test]
    fn only_the_billing_right_chooses_the_plan() {
        let (_, mut subscription, ann) = founded(OrganizationPlan::Free);
        let usage = PlanUsage::default();

        for role in [OrgRole::Member, OrgRole::Viewer, OrgRole::Admin] {
            let someone = joined_as(&ann, role);
            let refused = chosen(
                &mut subscription,
                &someone,
                OrganizationPlan::Business,
                &usage,
            );
            assert!(matches!(refused, Err(DomainError::Forbidden(_))), "{role}");
        }
        let bob = joined_as(&ann, OrgRole::Billing);
        assert!(chosen(&mut subscription, &bob, OrganizationPlan::Business, &usage).is_ok());
    }

    /// Even Acme's owner cannot choose Custom through member plan selection.
    #[test]
    fn custom_is_never_chosen() {
        let (_, mut subscription, ann) = founded(OrganizationPlan::Free);

        let refused = chosen(
            &mut subscription,
            &ann,
            OrganizationPlan::Custom,
            &PlanUsage::default(),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// After leaving a Starter trial for Free, Acme cannot start Business
    /// without a card by claiming another trial.
    #[test]
    fn the_trial_is_given_once() {
        let (_, mut subscription, ann) = founded(OrganizationPlan::Starter);
        let usage = PlanUsage::default();
        chosen(&mut subscription, &ann, OrganizationPlan::Free, &usage).unwrap();

        let refused = chosen(&mut subscription, &ann, OrganizationPlan::Business, &usage);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// With a card on file, Ann moves Acme to Business and it is active at
    /// once.
    #[test]
    fn a_card_on_file_makes_a_paid_plan_active() {
        let (_, mut subscription, ann) = founded(OrganizationPlan::Starter);
        let usage = PlanUsage::default();
        chosen(&mut subscription, &ann, OrganizationPlan::Free, &usage).unwrap();
        subscription.record_payment_method(card());

        chosen(&mut subscription, &ann, OrganizationPlan::Business, &usage).unwrap();

        assert_eq!(subscription.state(), SubscriptionState::Active);
    }

    /// Forty routes prevent Acme from moving to Free; the refused change
    /// leaves its subscription on Business.
    #[test]
    fn a_downgrade_past_what_is_in_use_is_refused() {
        let (_, mut subscription, ann) = founded(OrganizationPlan::Business);
        let usage = PlanUsage {
            routes: 40,
            ..PlanUsage::default()
        };

        let refused = chosen(&mut subscription, &ann, OrganizationPlan::Free, &usage);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(subscription.plan(), OrganizationPlan::Business);
    }

    /// Acme's Starter trial runs out without a card. A payment is owed from
    /// the day it ended. Ending it a day early is refused.
    #[test]
    fn a_trial_without_a_card_ends_owing() {
        let start = crate::shared::clock::now();
        let frozen = crate::shared::clock::freeze(start);
        let (_, mut subscription, _) = founded(OrganizationPlan::Starter);
        drop(frozen);
        let end = start.saturating_add(Duration::days(14));

        let early = {
            let _frozen = crate::shared::clock::freeze(end.saturating_sub(Duration::days(1)));
            subscription.end_trial()
        };
        let _frozen = crate::shared::clock::freeze(end);
        subscription.end_trial().unwrap();

        assert!(matches!(early, Err(DomainError::Conflict(_))));
        assert_eq!(
            subscription.state(),
            SubscriptionState::PastDue { since: end }
        );
    }

    /// With a card on file, Acme's expired trial becomes active.
    #[test]
    fn a_trial_with_a_card_ends_active() {
        let start = crate::shared::clock::now();
        let frozen = crate::shared::clock::freeze(start);
        let (_, mut subscription, _) = founded(OrganizationPlan::Business);
        subscription.record_payment_method(card());
        drop(frozen);

        let _frozen = crate::shared::clock::freeze(start.saturating_add(Duration::days(15)));
        subscription.end_trial().unwrap();

        assert_eq!(subscription.state(), SubscriptionState::Active);
    }

    /// An outstanding payment prevents Acme from choosing Business. A move
    /// to Free succeeds while the subscription remains past due.
    #[test]
    fn while_owing_only_free_may_be_chosen() {
        let (_, mut subscription, ann) = founded(OrganizationPlan::Free);
        subscription.record_payment_method(card());
        let usage = PlanUsage::default();
        chosen(&mut subscription, &ann, OrganizationPlan::Starter, &usage).unwrap();
        subscription.record_payment_failed().unwrap();

        let refused = chosen(&mut subscription, &ann, OrganizationPlan::Business, &usage);
        chosen(&mut subscription, &ann, OrganizationPlan::Free, &usage).unwrap();

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert!(matches!(
            subscription.state(),
            SubscriptionState::PastDue { .. }
        ));
    }

    /// A charge fails and the subscription owes; ten days later it is
    /// overdue beyond a week's grace. Once paid, it is active again.
    #[test]
    fn a_failed_charge_owes_until_it_is_settled() {
        let start = crate::shared::clock::now();
        let frozen = crate::shared::clock::freeze(start);
        let (_, mut subscription, _) = founded(OrganizationPlan::Free);
        subscription.record_payment_failed().unwrap();
        drop(frozen);

        let _frozen = crate::shared::clock::freeze(start.saturating_add(Duration::days(10)));
        let overdue = subscription.overdue_beyond(Duration::days(7));
        subscription.record_payment_settled();

        assert!(overdue);
        assert_eq!(subscription.state(), SubscriptionState::Active);
        assert!(!subscription.overdue_beyond(Duration::days(7)));
    }

    /// Nothing is charged during a trial, so a failure reported then is
    /// refused.
    #[test]
    fn a_trial_has_no_failed_charge() {
        let (_, mut subscription, _) = founded(OrganizationPlan::Starter);

        assert!(matches!(
            subscription.record_payment_failed(),
            Err(DomainError::Conflict(_))
        ));
    }

    /// An operator arranges Custom for Acme with forty tenants agreed. The
    /// move carries those limits to the organization.
    #[test]
    fn an_operator_arranges_custom_with_its_own_limits() {
        let (mut acme, mut subscription, _) = founded(OrganizationPlan::Business);
        let terms = PlanTerms::Negotiated(
            NegotiatedLimits::new(PlanLimits {
                max_tenants_per_org: 40,
                ..PlanLimits::business()
            })
            .unwrap(),
        );
        let arrangement = Arrangement {
            plan: OrganizationPlan::Custom,
            cycle: BillingCycle::Annual,
            terms,
        };

        let change = subscription
            .arrange(arrangement, &PlanUsage::default(), &operator())
            .unwrap();
        acme.change_plan(change).unwrap();

        assert_eq!(acme.plan(), OrganizationPlan::Custom);
        assert_eq!(acme.limits().max_tenants_per_org, 40);
    }

    /// An operator cannot arrange Starter with negotiated limits; the
    /// arrangement fails validation.
    #[test]
    fn negotiated_limits_are_arranged_on_custom_only() {
        let (_, mut subscription, _) = founded(OrganizationPlan::Free);
        let arrangement = Arrangement {
            plan: OrganizationPlan::Starter,
            cycle: BillingCycle::Monthly,
            terms: PlanTerms::Negotiated(NegotiatedLimits::new(PlanLimits::business()).unwrap()),
        };

        let refused = subscription.arrange(arrangement, &PlanUsage::default(), &operator());

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// A stored subscription trials the Free plan, which has no trial. It is
    /// refused as corrupt.
    #[test]
    fn a_stored_trial_on_a_plan_without_one_is_refused() {
        let now = crate::shared::clock::now();
        let row = OrgSubscriptionRow {
            organization_id: OrganizationId::new(),
            plan: OrganizationPlan::Free,
            cycle: BillingCycle::Monthly,
            state: SubscriptionState::Trialing { ends_at: now },
            payment: PaymentMethod::Missing,
            trial: TrialUse::Used,
            created_at: now,
            updated_at: now,
        };

        assert!(refused_as_corrupt(&OrgSubscription::reconstitute(row)));
    }

    /// Each billing cycle is stored by its name and read back the same.
    #[test]
    fn a_cycle_reads_back_as_stored() {
        for cycle in [BillingCycle::Monthly, BillingCycle::Annual] {
            assert_eq!(BillingCycle::parse(cycle.as_str()), Some(cycle));
        }
        assert_eq!(BillingCycle::parse("weekly"), None);
    }
}
