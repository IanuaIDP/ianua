//! Task templates: a person-approved limit on what one kind of task may do.
//!
//! ianua cannot check why an agent does something, only what it does. An
//! agent that lies about its purpose still gets everything its delegation
//! allows. So the defence is to keep the delegation small. A task template
//! names, for one kind of task, the capabilities, action classes, paths, most
//! sensitive data, budget and lifetime it needs. One person proposes it and a
//! different person, holding what it grants, approves it. A delegation
//! granted under it is the overlap of the template and the delegator's own
//! authority. It never reaches past either.

mod proposal;
mod recorded;
mod row;

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::{
    ActionApproval, AgentBudget, CapabilitySet, DelegationConstraints, ResourceScope,
};
use crate::domains::agents::authority::delegation::attenuate_constraints;
use crate::domains::agents::authority::intent::{
    DriftPolicy, DriftThreshold, IntentBinding, IntentDigest, IntentEnvelope, IntentStatement,
};
use crate::domains::agents::authority::task_template::proposal::ensure_proposable;
use crate::domains::agents::authority::task_template::row::{
    approved_by_another, decided_in_order,
};
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::Raised;
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::restriction::Restriction;
use crate::shared::model::row_check::RowCheck;
use crate::types::{Human, Label, Seconds, TaskTemplateId};

/// Where a template stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateStatus {
    /// Waiting for a second person to approve it. Nothing may be granted
    /// under it yet.
    Proposed,
    /// Approved. Delegations may be granted under it.
    Approved,
    /// Withdrawn. No new delegation may be granted under it.
    Retired,
}

impl TemplateStatus {
    /// The wire and display form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Retired => "retired",
        }
    }
}

/// A second person's approval of a template.
///
/// It keeps the person behind the approving account, not only the account.
/// So a stored approval can still be checked against the proposer through
/// any of their accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateApproval {
    by: Human,
    at: OffsetDateTime,
}

impl TemplateApproval {
    /// Who approved it, with the account they acted through.
    #[must_use]
    pub fn by(&self) -> &Human {
        &self.by
    }

    /// When it was approved.
    #[must_use]
    pub fn at(&self) -> OffsetDateTime {
        self.at
    }
}

/// Whether a retired template had been approved before it was withdrawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorApproval {
    /// Withdrawn while still a proposal.
    NotApproved,
    /// Withdrawn after this approval.
    Approved(TemplateApproval),
}

/// Where a template stands, with who approved it and when it was withdrawn.
///
/// The approver, approval time and retirement time live in one value. So a
/// template can never read as approved by nobody, or approved at a time
/// with no approver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateState {
    /// Waiting for a second person.
    Proposed,
    /// Approved. Delegations may be granted under it.
    Approved(TemplateApproval),
    /// Withdrawn.
    Retired {
        /// Whether it had been approved first.
        before: PriorApproval,
        /// When it was withdrawn.
        at: OffsetDateTime,
    },
}

impl TemplateState {
    /// The status label this state carries.
    #[must_use]
    pub fn status(&self) -> TemplateStatus {
        match self {
            Self::Proposed => TemplateStatus::Proposed,
            Self::Approved(_) => TemplateStatus::Approved,
            Self::Retired { .. } => TemplateStatus::Retired,
        }
    }

    /// Reads a state back from its stored approver, approval time and
    /// retirement time.
    ///
    /// A stored retirement time makes it retired, whether or not it was
    /// approved first.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when an approver is stored without
    ///   an approval time, or the other way round.
    pub fn from_stored(
        approved_by: Option<Human>,
        approved_at: Option<OffsetDateTime>,
        retired_at: Option<OffsetDateTime>,
    ) -> Result<Self, DomainError> {
        let approval = match (approved_by, approved_at) {
            (None, None) => PriorApproval::NotApproved,
            (Some(by), Some(at)) => PriorApproval::Approved(TemplateApproval { by, at }),
            (Some(_), None) | (None, Some(_)) => {
                return Err(DomainError::infra_msg(
                    "stored task template has an approver and an approval time that disagree",
                ));
            }
        };
        Ok(match (approval, retired_at) {
            (before, Some(at)) => Self::Retired { before, at },
            (PriorApproval::Approved(approval), None) => Self::Approved(approval),
            (PriorApproval::NotApproved, None) => Self::Proposed,
        })
    }

    /// The approval, if it was ever approved.
    #[must_use]
    pub fn approval(&self) -> Option<&TemplateApproval> {
        match self {
            Self::Approved(approval)
            | Self::Retired {
                before: PriorApproval::Approved(approval),
                ..
            } => Some(approval),
            Self::Proposed
            | Self::Retired {
                before: PriorApproval::NotApproved,
                ..
            } => None,
        }
    }

    /// When it was withdrawn, if it was. Storage keeps the state in this
    /// form.
    #[must_use]
    pub fn retired_at(&self) -> Option<OffsetDateTime> {
        match self {
            Self::Retired { at, .. } => Some(*at),
            Self::Proposed | Self::Approved(_) => None,
        }
    }

    fn last_changed(&self) -> Option<OffsetDateTime> {
        self.retired_at()
            .or_else(|| self.approval().map(TemplateApproval::at))
    }
}

/// The bounds a template puts on every delegation granted under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateLimits {
    /// The longest lifetime a delegation may have, in seconds.
    pub max_ttl_seconds: Seconds,
    /// The deepest sub-delegation chain allowed.
    pub max_depth: u8,
    /// The most sensitive data the agent may reach.
    pub max_data_class: DataClassLevel,
    /// The paths the agent is confined to.
    pub resource_scope: Restriction<ResourceScope>,
    /// The most the agent may spend.
    pub budget: Restriction<AgentBudget>,
    /// Whether every action waits for a person's approval.
    pub approval: ActionApproval,
}

/// What a person fills in to propose a template.
pub struct ProposeTaskTemplateParams {
    /// A short name people recognise the task by.
    pub name: Label,
    /// What the task is for, in words.
    pub purpose: IntentStatement,
    /// The fingerprint of the purpose.
    pub digest: IntentDigest,
    /// The most a delegation under the template may grant.
    pub ceiling: CapabilitySet,
    /// The kinds of action the task may take.
    pub classes: IntentEnvelope,
    /// The bounds on every delegation.
    pub limits: TemplateLimits,
}

/// A task template as storage keeps it, read back through
/// [`TaskTemplate::reconstitute`].
#[derive(Debug, Clone)]
pub struct TaskTemplateRow {
    /// Unique identifier.
    pub id: TaskTemplateId,
    /// The short name people know the task by.
    pub name: Label,
    /// What the task is for.
    pub purpose: IntentStatement,
    /// The fingerprint of the purpose.
    pub digest: IntentDigest,
    /// The most a delegation under the template may grant.
    pub ceiling: CapabilitySet,
    /// The kinds of action the task may take.
    pub classes: IntentEnvelope,
    /// The bounds on every delegation.
    pub limits: TemplateLimits,
    /// Who proposed it.
    pub proposed_by: Human,
    /// When it was proposed.
    pub proposed_at: OffsetDateTime,
    /// Where it stands; see [`TemplateState::from_stored`].
    pub state: TemplateState,
}

/// A delegation shaped by a template: what it grants and under which
/// constraints.
#[derive(Debug)]
pub struct TemplatedGrant {
    /// The requested capabilities that the template's `ceiling` also allows.
    pub granted: CapabilitySet,
    /// The constraints, never looser than the template's.
    pub constraints: DelegationConstraints,
}

/// A limit on what one kind of task may do, approved by a second person.
#[derive(Debug)]
pub struct TaskTemplate<T: TenantScope> {
    id: TaskTemplateId,
    name: Label,
    purpose: IntentStatement,
    digest: IntentDigest,
    ceiling: CapabilitySet,
    classes: IntentEnvelope,
    limits: TemplateLimits,
    proposed_by: Human,
    proposed_at: OffsetDateTime,
    state: TemplateState,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> TaskTemplate<T> {
    /// The person `proposer` names proposes a template. It grants nothing
    /// until a second person approves.
    ///
    /// The proposer is always the person acting, so an agent never proposes
    /// one. Nor can a caller name Bob as the proposer of Ann's template, and
    /// so let Ann approve it herself.
    ///
    /// Raises `agents.task_template_proposed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the `ceiling` allows no capability.
    /// - [`DomainError::Validation`] when no action class is allowed.
    /// - [`DomainError::Validation`] when the lifetime is zero.
    pub fn propose(
        proposer: &AgentControl<'_>,
        params: ProposeTaskTemplateParams,
    ) -> Result<Self, DomainError> {
        ensure_proposable(&params)?;
        Ok(recorded::proposed(Self {
            id: TaskTemplateId::new(),
            name: params.name,
            purpose: params.purpose,
            digest: params.digest,
            ceiling: params.ceiling,
            classes: params.classes,
            limits: params.limits,
            proposed_by: proposer.by().clone(),
            proposed_at: crate::shared::clock::now(),
            state: TemplateState::Proposed,
            raised: Raised::default(),
            _scope: PhantomData,
        }))
    }

    /// Rebuilds a task template from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row allows no capability.
    /// - [`DomainError::Infrastructure`] when the row allows no kind of
    ///   action.
    /// - [`DomainError::Infrastructure`] when the row sets limits no
    ///   delegation could keep.
    /// - [`DomainError::Infrastructure`] when the row records an approval by
    ///   the person who proposed it, through any of their accounts.
    /// - [`DomainError::Infrastructure`] when the row records an approval
    ///   before the proposal, or a retirement before the approval.
    pub fn reconstitute(row: TaskTemplateRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            purpose: row.purpose,
            digest: row.digest,
            ceiling: row.ceiling,
            classes: row.classes,
            limits: row.limits,
            proposed_by: row.proposed_by,
            proposed_at: row.proposed_at,
            state: row.state,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks one of the template's rules.
    fn ensure_consistent(row: &TaskTemplateRow) -> Result<(), DomainError> {
        RowCheck::of("task template")
            .holds(!row.ceiling.is_empty(), "allows no capability")
            .holds(!row.classes.is_empty(), "allows no kind of action")
            .holds(
                DelegationConstraints::new(row.limits.max_ttl_seconds, row.limits.max_depth)
                    .is_ok(),
                "limits no delegation could keep",
            )
            .holds(approved_by_another(row), "approved by its proposer")
            .holds(decided_in_order(row), "decided before it was proposed")
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &TaskTemplateId {
        &self.id
    }

    /// The short name people know the task by.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// What the task is for.
    #[must_use]
    pub fn purpose(&self) -> &IntentStatement {
        &self.purpose
    }

    /// The fingerprint of the purpose.
    #[must_use]
    pub fn digest(&self) -> &IntentDigest {
        &self.digest
    }

    /// The most a delegation under the template may grant.
    #[must_use]
    pub fn ceiling(&self) -> &CapabilitySet {
        &self.ceiling
    }

    /// The kinds of action the task may take.
    #[must_use]
    pub fn classes(&self) -> &IntentEnvelope {
        &self.classes
    }

    /// The bounds on every delegation.
    #[must_use]
    pub fn limits(&self) -> &TemplateLimits {
        &self.limits
    }

    /// Who proposed it.
    #[must_use]
    pub fn proposed_by(&self) -> &Human {
        &self.proposed_by
    }

    /// When it was proposed.
    #[must_use]
    pub fn proposed_at(&self) -> OffsetDateTime {
        self.proposed_at
    }

    /// Who approved it, if anyone has.
    #[must_use]
    pub fn approved_by(&self) -> Option<&Human> {
        self.state.approval().map(TemplateApproval::by)
    }

    /// When it was approved, if it has been.
    #[must_use]
    pub fn approved_at(&self) -> Option<OffsetDateTime> {
        self.state.approval().map(TemplateApproval::at)
    }

    /// When it was retired, if it has been.
    #[must_use]
    pub fn retired_at(&self) -> Option<OffsetDateTime> {
        self.state.retired_at()
    }

    /// Where it stands, with its approval and withdrawal.
    #[must_use]
    pub fn state(&self) -> &TemplateState {
        &self.state
    }

    /// Where it stands.
    #[must_use]
    pub fn status(&self) -> TemplateStatus {
        self.state.status()
    }

    /// A second person approves the template.
    ///
    /// Only a [`Human`] can approve, so an agent never can. Ann proposes a
    /// template. She cannot approve it, not even through her organization
    /// account.
    ///
    /// The approver must hold every built-in permission the template's
    /// `ceiling` grants. Approving lets delegations hand those out. Sam may
    /// only view routes. Without this check, Sam approves Ann's template
    /// granting "manage routes" and agents start getting it.
    ///
    /// Raises `agents.task_template_approved`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not awaiting approval.
    /// - [`DomainError::Validation`] when the person who proposed it
    ///   approves, through any of their accounts.
    /// - [`DomainError::Forbidden`] when the approver lacks a built-in
    ///   permission the `ceiling` grants.
    pub fn approve(&mut self, approver: &AgentControl<'_>) -> Result<(), DomainError> {
        if self.status() != TemplateStatus::Proposed {
            return Err(DomainError::invalid_transition(message!(
                "agents-only-a-proposed-task-template-can",
                "only a proposed task template can be approved"
            )));
        }
        if self.proposed_by.is_same_person_as(approver.by()) {
            return Err(DomainError::invalid(message!(
                "agents-a-different-person-must-approve-the",
                "a different person must approve the task template than proposed it"
            )));
        }
        approver
            .holds()
            .ensure_may_hand_out(self.ceiling.http(), &[])?;
        self.state = TemplateState::Approved(TemplateApproval {
            by: approver.by().clone(),
            at: crate::shared::clock::now(),
        });
        recorded::raise_approval(self);
        Ok(())
    }

    /// Withdraws the template. No new delegation can be granted under it.
    /// Delegations already granted under it keep their own expiry.
    ///
    /// Its proposer may withdraw it, and so may someone allowed to delegate
    /// to agents, as they may take a delegation back. Sam may only view
    /// agents. Without this check, he retires the template Ann's team
    /// delegates under and their agents get no new work.
    ///
    /// Raises `agents.task_template_retired`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person neither proposed it nor
    ///   may delegate to agents.
    /// - [`DomainError::InvalidTransition`] when it is already retired.
    pub fn retire(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(&self.proposed_by, AgentAction::Delegate)?;
        let before = match &self.state {
            TemplateState::Proposed => PriorApproval::NotApproved,
            TemplateState::Approved(approval) => PriorApproval::Approved(approval.clone()),
            TemplateState::Retired { .. } => {
                return Err(DomainError::invalid_transition(message!(
                    "agents-the-task-template-is-already-retired",
                    "the task template is already retired"
                )));
            }
        };
        self.state = TemplateState::Retired {
            before,
            at: crate::shared::clock::now(),
        };
        recorded::raise_retirement(self);
        Ok(())
    }

    /// Shapes a delegation under this template.
    ///
    /// It grants the requested capabilities that the `ceiling` also allows.
    /// Its constraints keep every bound the template sets. A request naming
    /// no intent takes the template's purpose and classes, enforced in the
    /// request path. A request naming an intent must enforce it and stay
    /// within the template's classes.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the template is not approved.
    /// - [`DomainError::Forbidden`] when the delegation would live longer
    ///   than the template allows.
    /// - [`DomainError::Forbidden`] when the request asks for a deeper
    ///   chain, wider paths, more spend, more sensitive data, an intent that
    ///   only warns, or classes past the template's.
    pub fn apply(
        &self,
        requested: &CapabilitySet,
        constraints: DelegationConstraints,
    ) -> Result<TemplatedGrant, DomainError> {
        if self.status() != TemplateStatus::Approved {
            return Err(DomainError::forbidden(message!(
                "agents-the-task-template-is-not-approved",
                "the task template is not approved"
            )));
        }
        if constraints.ttl_seconds() > self.limits.max_ttl_seconds {
            return Err(DomainError::forbidden(message!(
                "agents-the-delegation-outlives-its-task-template",
                "the delegation outlives its task template"
            )));
        }
        let constraints = attenuate_constraints(&self.bounds()?, constraints)?;
        Ok(TemplatedGrant {
            granted: requested.intersect(&self.ceiling),
            constraints: constraints.under_template(self.id),
        })
    }

    /// The template written as a parent delegation's constraints. The rule
    /// that keeps a sub-delegation inside its parent then keeps a delegation
    /// inside its template.
    fn bounds(&self) -> Result<DelegationConstraints, DomainError> {
        let intent = IntentBinding::new(
            self.purpose.clone(),
            self.digest,
            DriftPolicy::Enforce(DriftThreshold::DEFAULT),
            self.classes.clone(),
        );
        let bounds =
            DelegationConstraints::new(self.limits.max_ttl_seconds, self.limits.max_depth)?
                .with_intent(intent)
                .with_max_data_class(self.limits.max_data_class);
        let bounds = match &self.limits.resource_scope {
            Restriction::To(scope) => bounds.with_resource_scope(scope.clone()),
            Restriction::Unrestricted => bounds,
        };
        let bounds = match &self.limits.budget {
            Restriction::To(budget) => bounds.with_budget(budget.clone()),
            Restriction::Unrestricted => bounds,
        };
        Ok(match self.limits.approval {
            ActionApproval::PerAction => bounds.requiring_approval(),
            ActionApproval::NotRequired => bounds,
        })
    }
}

impl<T: TenantScope> Aggregate for TaskTemplate<T> {
    type Id = TaskTemplateId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.proposed_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.state.last_changed().unwrap_or(self.proposed_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::{PubSub, TopicCapability, TopicPattern};
    use crate::domains::authorization::permission::{RoutingAction, SystemPermission};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{
        ActionClass, HumanAccount, OrgUserId, PersonKey, PrincipalRef, Seconds, TenantId, UserId,
    };

    /// The human acting through tenant account `id`, as a person of their own.
    fn as_approver(id: UserId) -> Human {
        Human::new(
            HumanAccount::User(id),
            PersonKey::new(format!("{id}@corp.test")).unwrap(),
        )
    }

    fn someone() -> Human {
        as_approver(UserId::new())
    }

    const VIEWS_ROUTES: &[SystemPermission] = &[SystemPermission::Routing(RoutingAction::View)];

    /// `by`, holding what the test template grants.
    fn approving(by: &Human) -> AgentControl<'_> {
        AgentControl::new(assumed_authority(by, TenantId::new(), VIEWS_ROUTES, &[]))
    }

    /// `by`, holding nothing.
    fn acting(by: &Human) -> AgentControl<'_> {
        AgentControl::new(assumed_authority(by, TenantId::new(), &[], &[]))
    }

    /// `by`, allowed to delegate to agents.
    fn delegating(by: &Human) -> AgentControl<'_> {
        AgentControl::new(assumed_authority(
            by,
            TenantId::new(),
            &[SystemPermission::Agents(AgentAction::Delegate)],
            &[],
        ))
    }

    fn view() -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![])
    }

    fn limits() -> TemplateLimits {
        TemplateLimits {
            max_ttl_seconds: Seconds::new(3600),
            max_depth: 1,
            max_data_class: DataClassLevel::Internal,
            resource_scope: Restriction::To(ResourceScope::new(["/reports".to_owned()]).unwrap()),
            budget: Restriction::Unrestricted,
            approval: ActionApproval::NotRequired,
        }
    }

    fn params() -> ProposeTaskTemplateParams {
        ProposeTaskTemplateParams {
            name: Label::new("name", "monthly reports").unwrap(),
            purpose: IntentStatement::new("read the monthly reports").unwrap(),
            digest: IntentDigest::new([7; 32]),
            ceiling: view(),
            classes: IntentEnvelope::new([ActionClass::Read]),
            limits: limits(),
        }
    }

    /// Proposes the standard report template under this person's authority.
    fn proposed(by: &Human) -> TaskTemplate<ResolvedTenant> {
        TaskTemplate::propose(&acting(by), params()).unwrap()
    }

    fn approved() -> TaskTemplate<ResolvedTenant> {
        let mut template = proposed(&someone());
        template.approve(&approving(&someone())).unwrap();
        template
    }

    fn ten_minutes() -> DelegationConstraints {
        DelegationConstraints::new(Seconds::new(600), 0).unwrap()
    }

    /// Ann proposes a template and nobody has approved it yet. It stays
    /// proposed, and a delegation under it is refused as forbidden.
    #[test]
    fn a_proposal_waits_for_a_second_person() {
        let template = proposed(&someone());

        assert_eq!(template.status(), TemplateStatus::Proposed);
        assert!(matches!(
            template.apply(&view(), ten_minutes()),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A proposer cannot approve their own template through the same
    /// account. The refusal leaves the template proposed.
    #[test]
    fn the_proposer_cannot_approve_their_own_template() {
        let author = UserId::new();
        let mut template = proposed(&as_approver(author));

        let result = template.approve(&approving(&as_approver(author)));

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert_eq!(template.status(), TemplateStatus::Proposed);
    }

    /// A person without route-viewing rights cannot approve a template
    /// granting them. The refusal leaves the template proposed.
    #[test]
    fn the_approver_must_hold_what_the_template_grants() {
        let mut template = proposed(&someone());
        let sam = someone();
        let empty_handed = AgentControl::new(assumed_authority(&sam, TenantId::new(), &[], &[]));

        let result = template.approve(&empty_handed);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(template.status(), TemplateStatus::Proposed);
    }

    /// Sam approves a template through his tenant account. The template
    /// names that account as its approver.
    #[test]
    fn an_approval_records_the_account_it_came_through() {
        let approver = UserId::new();
        let mut template = proposed(&someone());

        template
            .approve(&approving(&as_approver(approver)))
            .unwrap();

        assert_eq!(
            template.approved_by().map(Human::principal),
            Some(PrincipalRef::User(approver))
        );
    }

    /// A person proposes a template with an empty set of action classes. It
    /// is refused with a validation error, since such a task could do nothing.
    #[test]
    fn a_template_allowing_no_action_is_refused() {
        let result = TaskTemplate::<ResolvedTenant>::propose(
            &acting(&someone()),
            ProposeTaskTemplateParams {
                name: Label::new("name", "nothing").unwrap(),
                purpose: IntentStatement::new("nothing").unwrap(),
                digest: IntentDigest::new([0; 32]),
                ceiling: view(),
                classes: IntentEnvelope::new([]),
                limits: limits(),
            },
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An approved template is retired. A new delegation under it is refused,
    /// and retiring it a second time fails.
    #[test]
    fn a_retired_template_grants_nothing_new() {
        let mut template = approved();
        let bob = someone();

        template.retire(&delegating(&bob)).unwrap();

        assert_eq!(template.status(), TemplateStatus::Retired);
        assert!(template.apply(&view(), ten_minutes()).is_err());
        assert!(template.retire(&delegating(&bob)).is_err());
    }

    /// Someone without delegation rights who did not propose a template
    /// cannot retire it; it stays approved. The proposer can then retire it.
    #[test]
    fn only_the_proposer_or_a_delegator_retires_a_template() {
        let ann = someone();
        let mut template = proposed(&ann);
        template.approve(&approving(&someone())).unwrap();
        let sam = someone();

        let by_sam = template.retire(&acting(&sam));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(template.status(), TemplateStatus::Approved);
        template.retire(&acting(&ann)).unwrap();
        assert_eq!(template.status(), TemplateStatus::Retired);
    }

    /// A ten-minute delegation that names no intent is shaped by the
    /// template. It takes the template's classes with drift enforced, its
    /// data class, its paths and a link back to the template.
    #[test]
    fn a_delegation_under_a_template_carries_every_bound() {
        let template = approved();

        let shaped = template.apply(&view(), ten_minutes()).unwrap();

        let c = &shaped.constraints;
        let intent = c.intent().limit().unwrap();
        assert_eq!(intent.envelope(), template.classes());
        assert!(matches!(intent.drift_policy(), DriftPolicy::Enforce(_)));
        assert_eq!(
            c.max_data_class(),
            crate::shared::model::restriction::Restriction::To(DataClassLevel::Internal)
        );
        assert_eq!(
            c.resource_scope().limit(),
            template.limits().resource_scope.limit()
        );
        assert_eq!(c.template().limit(), Some(template.id()));
    }

    /// Applying a route-viewing template to wider route and messaging
    /// capabilities produces a grant within its ceiling and no messaging rights.
    #[test]
    fn capabilities_beyond_the_ceiling_are_not_granted() {
        let template = approved();
        let wider = CapabilitySet::new(
            vec![
                SystemPermission::Routing(RoutingAction::View),
                SystemPermission::Routing(RoutingAction::Manage),
            ],
            vec![TopicCapability::new(
                TopicPattern::new("orders").unwrap(),
                PubSub::Publish,
            )],
        );

        let shaped = template.apply(&wider, ten_minutes()).unwrap();

        assert!(shaped.granted.subset_of(template.ceiling()));
        assert!(shaped.granted.messaging().is_empty());
    }

    /// A template limited to one hour refuses a delegation requesting a
    /// two-hour lifetime.
    #[test]
    fn a_delegation_outliving_its_template_is_refused() {
        let template = approved();
        let long = DelegationConstraints::new(Seconds::new(7200), 0).unwrap();

        assert!(matches!(
            template.apply(&view(), long),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A template capped at internal data refuses a delegation requesting
    /// access to restricted data.
    #[test]
    fn a_delegation_reaching_more_sensitive_data_is_refused() {
        let template = approved();
        let wider = ten_minutes().with_max_data_class(DataClassLevel::Restricted);

        assert!(template.apply(&view(), wider).is_err());
    }

    /// A template confined to reports refuses a delegation requesting
    /// access to the root path.
    #[test]
    fn a_delegation_widening_the_paths_is_refused() {
        let template = approved();
        let wider =
            ten_minutes().with_resource_scope(ResourceScope::new(["/".to_owned()]).unwrap());

        assert!(template.apply(&view(), wider).is_err());
    }

    /// A template requiring enforced intent refuses a delegation whose
    /// matching read purpose only warns on drift.
    #[test]
    fn an_intent_that_only_warns_is_refused() {
        let template = approved();
        let warned = ten_minutes().with_intent(IntentBinding::new(
            IntentStatement::new("read reports").unwrap(),
            IntentDigest::new([1; 32]),
            DriftPolicy::Warn(DriftThreshold::DEFAULT),
            IntentEnvelope::new([ActionClass::Read]),
        ));

        assert!(template.apply(&view(), warned).is_err());
    }

    /// A read-only template refuses a delegation whose enforced intent
    /// also permits deletion.
    #[test]
    fn an_intent_reaching_past_the_templates_classes_is_refused() {
        let template = approved();
        let wider = ten_minutes().with_intent(IntentBinding::new(
            IntentStatement::new("tidy reports").unwrap(),
            IntentDigest::new([1; 32]),
            DriftPolicy::Enforce(DriftThreshold::DEFAULT),
            IntentEnvelope::new([ActionClass::Read, ActionClass::Delete]),
        ));

        assert!(template.apply(&view(), wider).is_err());
    }

    /// A proposer cannot approve through an organization account with the
    /// same person identity. The refusal leaves the template proposed.
    #[test]
    fn the_proposer_cannot_approve_through_another_account() {
        let mut template = proposed(&Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("carol@corp.test").unwrap(),
        ));
        let carol_through_org = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            PersonKey::new("carol@corp.test").unwrap(),
        );

        assert!(template.approve(&approving(&carol_through_org)).is_err());
        assert_eq!(template.status(), TemplateStatus::Proposed);
    }

    fn stored(template: &TaskTemplate<ResolvedTenant>) -> TaskTemplateRow {
        TaskTemplateRow {
            id: template.id,
            name: template.name.clone(),
            purpose: template.purpose.clone(),
            digest: template.digest,
            ceiling: template.ceiling.clone(),
            classes: template.classes.clone(),
            limits: template.limits.clone(),
            proposed_by: template.proposed_by.clone(),
            proposed_at: template.proposed_at,
            state: template.state.clone(),
        }
    }

    /// An approved template is written to a row and read back. The row
    /// passes every check.
    #[test]
    fn a_stored_template_reads_back() {
        assert!(TaskTemplate::<ResolvedTenant>::reconstitute(stored(&approved())).is_ok());
    }

    /// A stored template approved by its own proposer is refused as corrupt
    /// during reconstitution.
    #[test]
    fn a_stored_template_approved_by_its_proposer_is_refused() {
        let mut row = stored(&proposed(&someone()));
        row.state = TemplateState::Approved(TemplateApproval {
            by: row.proposed_by.clone(),
            at: row.proposed_at,
        });

        assert!(refused_as_corrupt(
            &TaskTemplate::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored template approved by its proposer through an organization
    /// account with the same person identity is refused as corrupt.
    #[test]
    fn a_stored_template_approved_by_its_proposer_through_another_account_is_refused() {
        let mut row = stored(&proposed(&Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("carol@corp.test").unwrap(),
        )));
        row.state = TemplateState::Approved(TemplateApproval {
            by: Human::new(
                HumanAccount::OrgUser(OrgUserId::new()),
                PersonKey::new("carol@corp.test").unwrap(),
            ),
            at: row.proposed_at,
        });

        assert!(refused_as_corrupt(
            &TaskTemplate::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A row records the approval one second before the proposal. It is
    /// refused as corrupt, since nobody can approve what was not yet proposed.
    #[test]
    fn a_stored_template_approved_before_it_was_proposed_is_refused() {
        let mut row = stored(&approved());
        let Some(approval) = row.state.approval().cloned() else {
            panic!("an approved template carries its approval");
        };
        row.state = TemplateState::Approved(TemplateApproval {
            by: approval.by,
            at: row.proposed_at - time::Duration::SECOND,
        });

        assert!(refused_as_corrupt(
            &TaskTemplate::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored row has an empty capability set. It is refused as corrupt,
    /// since a template must allow some capability.
    #[test]
    fn a_stored_template_that_allows_nothing_is_refused() {
        let mut row = stored(&approved());
        row.ceiling = CapabilitySet::default();

        assert!(refused_as_corrupt(
            &TaskTemplate::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Ann proposes a template, Bob approves it and Ann retires it. Each
    /// step is raised, in order.
    #[test]
    fn proposing_approving_and_retiring_raise_each_step() {
        let ann = someone();
        let mut template = proposed(&ann);

        template.approve(&approving(&someone())).unwrap();
        template.retire(&acting(&ann)).unwrap();

        assert_eq!(
            raised_names(&mut template),
            [
                "agents.task_template_proposed",
                "agents.task_template_approved",
                "agents.task_template_retired"
            ]
        );
    }

    /// A template is proposed. The record names it by its name.
    #[test]
    fn the_proposal_names_the_template() {
        let mut template = proposed(&someone());

        let events = raised(&mut template);

        assert_eq!(
            events[0].payload().value("template"),
            Some(&FieldValue::Text("monthly reports".to_owned()))
        );
    }

    /// A proposer's self-approval fails without raising any template events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let author = UserId::new();
        let mut template = proposed(&as_approver(author));
        raised_names(&mut template);

        let result = template.approve(&approving(&as_approver(author)));

        assert!(result.is_err());
        assert!(raised_names(&mut template).is_empty());
    }

    /// A template is read back from storage. It has raised nothing.
    #[test]
    fn read_back_from_storage_has_raised_nothing() {
        let mut template =
            TaskTemplate::<ResolvedTenant>::reconstitute(stored(&approved())).unwrap();

        assert!(raised_names(&mut template).is_empty());
    }
}
