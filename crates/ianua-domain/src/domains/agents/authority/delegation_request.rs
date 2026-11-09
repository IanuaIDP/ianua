//! A delegation an agent asks a person for.
//!
//! An agent working for Ann finds it needs more than it holds. It asks her,
//! naming what it needs and why. Ann sees the request and grants it, or
//! refuses it. Granting makes an ordinary delegation from her, checked
//! against what she holds at that moment, like any she grants herself. The
//! agent's word is never authority: a request grants nothing until the
//! person asked approves it, and lapses unanswered after
//! `REQUEST_WINDOW`.

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
use crate::domains::agents::authority::delegation::{
    Delegate, Delegation, GrantDelegationParams, HeldBy,
};
use crate::domains::agents::events::authority::{AgentDelegationAsked, DelegationAsk};
use crate::domains::agents::identity::acting::ActingAgent;
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{AgentId, DelegationId, DelegationRequestId, EventLabel, Human};

/// How long a request waits for an answer before it lapses: one day.
pub(crate) const REQUEST_WINDOW: Duration = Duration::days(1);

text_value! {
    /// Why the agent asks, in its own words, shown to the person asked.
    pub struct DelegationReason;
}

impl TextValue for DelegationReason {
    const FIELD: &'static str = "reason";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(500)
    }
}

/// What an agent asks a person for.
pub struct AskDelegationParams {
    /// The person asked, who would be the delegation's delegator.
    pub asked_of: Human,
    /// The capabilities it asks for.
    pub granted: CapabilitySet,
    /// The limits it asks for, such as the lifetime and depth.
    pub constraints: DelegationConstraints,
    /// Why it asks.
    pub reason: DelegationReason,
}

/// Where a request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    /// Waiting for the person asked.
    Pending,
    /// The person granted it as this delegation.
    Approved {
        /// The delegation it became.
        delegation_id: DelegationId,
        /// When it was granted.
        at: OffsetDateTime,
    },
    /// The person refused it.
    Denied {
        /// When it was refused.
        at: OffsetDateTime,
    },
}

impl RequestState {
    /// When it was answered, once it was.
    #[must_use]
    pub fn decided_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Pending => None,
            Self::Approved { at, .. } | Self::Denied { at } => Some(at),
        }
    }
}

/// Persisted state for reconstitution.
pub struct DelegationRequestRow {
    /// Unique identifier.
    pub id: DelegationRequestId,
    /// The agent asking.
    pub agent_id: AgentId,
    /// The person asked.
    pub asked_of: Human,
    /// The capabilities asked for.
    pub granted: CapabilitySet,
    /// The limits asked for.
    pub constraints: DelegationConstraints,
    /// Why the agent asks.
    pub reason: DelegationReason,
    /// Where it stands.
    pub state: RequestState,
    /// When the agent asked.
    pub created_at: OffsetDateTime,
    /// When it lapses unanswered.
    pub expires_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A delegation an agent asked a person for.
#[derive(Debug, Clone)]
pub struct DelegationRequest<T: TenantScope> {
    id: DelegationRequestId,
    agent_id: AgentId,
    asked_of: Human,
    granted: CapabilitySet,
    constraints: DelegationConstraints,
    reason: DelegationReason,
    state: RequestState,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> DelegationRequest<T> {
    /// `agent`, signed in as itself, asks the person `params` names for a
    /// delegation. `identity` is that agent as the tenant keeps it.
    ///
    /// Only the agent itself asks, and only while it may act. Agent B
    /// learns agent A's id from a log. Without the sign-in proof, B asks
    /// Ann for authority in A's name.
    ///
    /// Raises `agents.delegation_requested`, so the person asked hears of
    /// it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `identity` is not the agent that
    ///   signed in, or may not act now.
    pub fn ask(
        agent: &ActingAgent,
        identity: &AgentIdentity<T>,
        params: AskDelegationParams,
    ) -> Result<Self, DomainError> {
        let now = clock::now();
        if identity.id() != agent.agent() || !identity.may_act_at(now) {
            return Err(DomainError::forbidden(message!(
                "agents-only-an-agent-free-to-act",
                "only an agent free to act asks for a delegation, in its own name"
            )));
        }
        let mut request = Self {
            id: DelegationRequestId::new(),
            agent_id: *agent.agent(),
            asked_of: params.asked_of,
            granted: params.granted,
            constraints: params.constraints,
            reason: params.reason,
            state: RequestState::Pending,
            created_at: now,
            expires_at: now.saturating_add(REQUEST_WINDOW),
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        request.raise(identity, DelegationAsk::Asked);
        Ok(request)
    }

    /// Rebuilds a request from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it lapses before it was made,
    ///   or waits longer than `REQUEST_WINDOW`.
    /// - [`DomainError::Infrastructure`] when it changed, or was answered,
    ///   before it was made.
    pub fn reconstitute(row: DelegationRequestRow) -> Result<Self, DomainError> {
        RowCheck::of("delegation request")
            .holds(row.created_at < row.expires_at, "lapses before it was made")
            .holds(
                row.expires_at <= row.created_at.saturating_add(REQUEST_WINDOW),
                "waits longer than a request may",
            )
            .in_order(row.created_at, row.updated_at, "changed before it was made")
            .in_order_if(
                row.created_at,
                row.state.decided_at(),
                "answered before it was made",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            agent_id: row.agent_id,
            asked_of: row.asked_of,
            granted: row.granted,
            constraints: row.constraints,
            reason: row.reason,
            state: row.state,
            created_at: row.created_at,
            expires_at: row.expires_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &DelegationRequestId {
        &self.id
    }

    /// The agent asking.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// The person asked.
    #[must_use]
    pub fn asked_of(&self) -> &Human {
        &self.asked_of
    }

    /// The capabilities asked for.
    #[must_use]
    pub fn granted(&self) -> &CapabilitySet {
        &self.granted
    }

    /// The limits asked for.
    #[must_use]
    pub fn constraints(&self) -> &DelegationConstraints {
        &self.constraints
    }

    /// Why the agent asks, in its own words.
    #[must_use]
    pub fn reason(&self) -> &DelegationReason {
        &self.reason
    }

    /// Where it stands.
    #[must_use]
    pub fn state(&self) -> RequestState {
        self.state
    }

    /// When it lapses unanswered.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether it still waits for an answer at `now`.
    #[must_use]
    pub fn is_open_at(&self, now: OffsetDateTime) -> bool {
        self.state == RequestState::Pending && now < self.expires_at
    }

    /// The person asked grants the request, as `held` says what they hold
    /// now, to `delegate`, the agent that asked. It gives back the new
    /// delegation, made as any they grant themselves.
    ///
    /// Only the person asked grants it. Without that check, Sam, who was
    /// not asked, approves Ann's request and her name goes on authority she
    /// never gave. The grant is checked against what Ann holds when she
    /// answers, never against what the agent asked for.
    ///
    /// Raises `agents.delegation_request_approved`, and the new
    /// delegation raises its own grant.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it was answered, or lapsed.
    /// - [`DomainError::Forbidden`] when `held` is not the person asked's.
    /// - [`DomainError::Forbidden`] when `delegate` is not the agent that
    ///   asked, or may not receive authority now.
    /// - [`DomainError::Forbidden`] when it asks for anything the person
    ///   does not hold.
    pub fn approve(
        &mut self,
        held: &HeldBy,
        delegate: &Delegate<'_, T>,
    ) -> Result<Delegation<T>, DomainError> {
        let now = clock::now();
        self.ensure_open(now)?;
        if held.holder() != self.asked_of.principal() {
            return Err(DomainError::forbidden(message!(
                "agents-only-the-person-asked-grants-the",
                "only the person asked grants the delegation"
            )));
        }
        if delegate.id() != self.agent_id {
            return Err(DomainError::forbidden(message!(
                "agents-the-delegation-goes-to-the-agent",
                "the delegation goes to the agent that asked"
            )));
        }
        let agent = delegate.agent;
        let delegation = Delegation::grant(
            GrantDelegationParams {
                granted: self.granted.clone(),
                constraints: self.constraints.clone(),
                name: None,
            },
            held,
            delegate,
        )?;
        let approved = RequestState::Approved {
            delegation_id: *delegation.id(),
            at: now,
        };
        self.answer(approved, DelegationAsk::Approved, agent);
        Ok(delegation)
    }

    /// The person asked, or someone allowed to manage agents, refuses the
    /// request of `agent`.
    ///
    /// Raises `agents.delegation_request_denied`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` is neither the person
    ///   asked nor allowed to manage agents.
    /// - [`DomainError::Forbidden`] when `agent` is not the agent that
    ///   asked.
    /// - [`DomainError::InvalidTransition`] when it was answered, or lapsed.
    pub fn deny(
        &mut self,
        control: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
    ) -> Result<(), DomainError> {
        let asked = control.by().is_same_account_as(&self.asked_of);
        if !asked && !control.holds_agent(AgentAction::Manage) {
            return Err(DomainError::forbidden(message!(
                "agents-only-the-person-asked-or-someone",
                "only the person asked, or someone allowed to manage agents, refuses it"
            )));
        }
        if agent.id() != &self.agent_id {
            return Err(DomainError::forbidden(message!(
                "agents-the-agent-is-not-the-one",
                "the agent is not the one that asked"
            )));
        }
        let now = clock::now();
        self.ensure_open(now)?;
        self.answer(
            RequestState::Denied { at: now },
            DelegationAsk::Denied,
            agent,
        );
        Ok(())
    }

    /// Refuses an answer to a request already answered, or lapsed at `now`.
    fn ensure_open(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.is_open_at(now) {
            return Ok(());
        }
        Err(DomainError::invalid_transition(message!(
            "agents-the-request-was-answered-already-or",
            "the request was answered already, or lapsed"
        )))
    }

    /// Records `state` as the answer, and raises it as `step`.
    fn answer(&mut self, state: RequestState, step: DelegationAsk, agent: &AgentIdentity<T>) {
        self.updated_at = state.decided_at().unwrap_or_else(clock::now);
        self.state = state;
        self.raise(agent, step);
    }

    /// Raises `step` of this request, naming `agent` as the tenant knows it.
    fn raise(&mut self, agent: &AgentIdentity<T>, step: DelegationAsk) {
        self.raised.raise(AgentDelegationAsked {
            request_id: self.id,
            agent_id: self.agent_id,
            agent_label: EventLabel::of(agent.name().as_str()),
            asked_of: self.asked_of.principal(),
            step,
            occurred_at: self.updated_at,
        });
    }
}

impl<T: TenantScope> Raises for DelegationRequest<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for DelegationRequest<T> {
    type Id = DelegationRequestId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::delegation::{HeldResources, ReviewDuty};
    use crate::domains::agents::execution::run::tests::fixtures::{agent, ann};
    use crate::domains::agents::execution::tool::tests::fixtures::{MANAGE, holding, person};
    use crate::domains::agents::identity::agent::SuspendedBy;
    use crate::domains::authorization::permission::{RoutingAction, SystemPermission};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_names;
    use crate::types::Seconds;

    /// Viewing routes, what the agent asks for.
    const VIEW_ROUTES: [SystemPermission; 1] = [SystemPermission::Routing(RoutingAction::View)];

    fn view_routes() -> CapabilitySet {
        CapabilitySet::new(VIEW_ROUTES.to_vec(), Vec::new())
    }

    /// The agent asking Ann for view routes for an hour.
    fn asking_ann() -> AskDelegationParams {
        AskDelegationParams {
            asked_of: ann(),
            granted: view_routes(),
            constraints: DelegationConstraints::new(Seconds::new(3600), 1).unwrap(),
            reason: DelegationReason::new("I need the route list for the audit").unwrap(),
        }
    }

    /// What `by`, holding `system`, may grant from, for this request.
    fn held_by(by: &Human, system: &[SystemPermission]) -> HeldBy {
        HeldBy::worked_out::<ResolvedTenant>(
            &holding(by, system),
            &view_routes(),
            &HeldResources::answered(by.principal(), Vec::new()),
            &[],
        )
        .unwrap()
    }

    fn to(agent: &AgentIdentity<ResolvedTenant>) -> Delegate<'_, ResolvedTenant> {
        Delegate {
            agent,
            duty: ReviewDuty::NotReviewing,
        }
    }

    /// `agent`'s request to Ann, as it asked it.
    fn asked_by(agent: &AgentIdentity<ResolvedTenant>) -> DelegationRequest<ResolvedTenant> {
        DelegationRequest::ask(&ActingAgent::assumed(*agent.id()), agent, asking_ann()).unwrap()
    }

    /// The agent asks Ann for view routes. The request waits for her, and
    /// its asking is raised.
    #[test]
    fn an_agent_asks_a_person_for_a_delegation() {
        let agent = agent();

        let mut request = asked_by(&agent);

        assert!(request.is_open_at(clock::now()));
        assert_eq!(raised_names(&mut request), ["agents.delegation_requested"]);
    }

    /// A signed-in agent cannot request a delegation using another
    /// agent's identity; the mismatch is forbidden.
    #[test]
    fn an_agent_asks_only_in_its_own_name() {
        let (a, b) = (agent(), agent());

        let asked = DelegationRequest::ask(&ActingAgent::assumed(*b.id()), &a, asking_ann());

        assert!(matches!(asked, Err(DomainError::Forbidden(_))));
    }

    /// An agent suspended by a monitor cannot open a delegation request,
    /// even when its sign-in proof names the correct agent.
    #[test]
    fn an_agent_that_may_not_act_asks_for_nothing() {
        let mut agent = agent();
        agent.suspend(SuspendedBy::Monitor).unwrap();

        let asked =
            DelegationRequest::ask(&ActingAgent::assumed(*agent.id()), &agent, asking_ann());

        assert!(matches!(asked, Err(DomainError::Forbidden(_))));
    }

    /// Ann grants the request. A delegation from her to the agent is made,
    /// and the request names it.
    #[test]
    fn the_person_asked_grants_it_as_a_delegation_from_her() {
        let agent = agent();
        let mut request = asked_by(&agent);
        raised_names(&mut request);

        let delegation = request
            .approve(&held_by(&ann(), &VIEW_ROUTES), &to(&agent))
            .unwrap();

        assert_eq!(delegation.delegator(), &ann().principal());
        assert!(matches!(
            request.state(),
            RequestState::Approved { delegation_id, .. } if delegation_id == *delegation.id()
        ));
        assert_eq!(
            raised_names(&mut request),
            ["agents.delegation_request_approved"]
        );
    }

    /// Someone other than the person asked cannot approve a delegation
    /// request, even with the requested rights. The request remains open.
    #[test]
    fn only_the_person_asked_grants_it() {
        let agent = agent();
        let mut request = asked_by(&agent);

        let result = request.approve(
            &held_by(&person("sam@corp.test"), &VIEW_ROUTES),
            &to(&agent),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(request.is_open_at(clock::now()));
    }

    /// Approving a request for route viewing is forbidden when the person
    /// asked does not currently hold that permission.
    #[test]
    fn a_grant_is_checked_against_what_the_person_holds_now() {
        let agent = agent();
        let mut request = asked_by(&agent);

        let result = request.approve(&held_by(&ann(), &[]), &to(&agent));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Approval cannot direct a requested delegation to a different agent
    /// from the one that asked for it.
    #[test]
    fn the_delegation_goes_to_the_agent_that_asked() {
        let (asker, other) = (agent(), agent());
        let mut request = asked_by(&asker);

        let result = request.approve(&held_by(&ann(), &VIEW_ROUTES), &to(&other));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann refuses the request. It is denied, and a later approval is
    /// refused.
    #[test]
    fn the_person_asked_refuses_it() {
        let agent = agent();
        let mut request = asked_by(&agent);

        request.deny(&holding(&ann(), &[]), &agent).unwrap();
        let later = request.approve(&held_by(&ann(), &VIEW_ROUTES), &to(&agent));

        assert!(matches!(request.state(), RequestState::Denied { .. }));
        assert!(matches!(later, Err(DomainError::InvalidTransition(_))));
    }

    /// A person who was not asked and lacks management rights cannot deny
    /// a delegation request. A manager can deny the same request.
    #[test]
    fn only_the_person_asked_or_a_manager_refuses_it() {
        let agent = agent();
        let mut request = asked_by(&agent);

        let by_sam = request.deny(&holding(&person("sam@corp.test"), &[]), &agent);
        let by_bob = request.deny(&holding(&person("bob@corp.test"), &MANAGE), &agent);

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_bob.is_ok());
    }

    /// A request nobody answered in a day lapses. Granting it then is
    /// refused.
    #[test]
    fn an_unanswered_request_lapses_after_a_day() {
        let agent = agent();
        let mut request = asked_by(&agent);
        let later = clock::freeze(request.expires_at());

        let result = request.approve(&held_by(&ann(), &VIEW_ROUTES), &to(&agent));

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        drop(later);
    }

    /// A stored request that waits a week, longer than any request may, is
    /// refused as corrupt.
    #[test]
    fn a_stored_request_waiting_too_long_is_refused() {
        let agent = agent();
        let request = asked_by(&agent);
        let row = DelegationRequestRow {
            id: request.id,
            agent_id: request.agent_id,
            asked_of: request.asked_of.clone(),
            granted: request.granted.clone(),
            constraints: request.constraints.clone(),
            reason: request.reason.clone(),
            state: request.state,
            created_at: request.created_at,
            expires_at: request.created_at + Duration::weeks(1),
            updated_at: request.updated_at,
        };

        assert!(refused_as_corrupt(
            &DelegationRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
