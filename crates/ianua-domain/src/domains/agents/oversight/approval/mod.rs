//! A request for a person to approve one action an agent wants to take.
//!
//! When a delegation's constraints set [`requires_approval`], the agent's
//! action pauses. An [`ApprovalRequest`] is recorded instead of running it.
//! A person may [`approve`](ApprovalRequest::approve) or
//! [`deny`](ApprovalRequest::deny) it within a set time. After that the
//! request [`expire`](ApprovalRequest::expire)s. A person who stops the run
//! that raised it [`withdraw`](ApprovalRequest::withdraw)s it, and one who
//! changes the call it is about [`supersede`](ApprovalRequest::supersede)s
//! it.
//!
//! Only an [`Approver`] holding the permission to approve agent actions, and
//! cleared for what the request shows, decides it. Whoever put the action
//! there, the agent's owner and the people behind its delegation never do.
//!
//! The action runs only on an `Approved` request whose time has not run out,
//! while the delegation it uses is still live. Pending, denied and expired
//! requests allow nothing.
//!
//! [`requires_approval`]: crate::domains::agents::authority::capability::DelegationConstraints::requires_approval

mod announce;
mod authority;
mod origin;
mod parties;
mod row;
mod state;

use std::marker::PhantomData;

pub use authority::*;
pub use origin::*;
pub use parties::*;
pub use row::{ApprovalRequestRow, RequestApprovalParams};
pub use state::*;
use time::{Duration, OffsetDateTime};

use crate::domains::agents::authority::delegation::{ActingUnder, Delegation};
use crate::domains::agents::execution::run::{
    DeniedCall, PendingCallRef, ReleasedCall, RevisedCall, RunCancelled,
};
use crate::domains::agents::oversight::approval::row::{
    ensure_consistent, ensure_fits_run, ensure_parties_fit,
};
use crate::domains::agents::oversight::approval_status::ApprovalStatus;
use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::Raised;
use crate::shared::model::aggregate::Aggregate;
use crate::shared::validation::numeric::validate_range;
use crate::types::{
    AgentId, AgentRunId, ApprovalId, DeclaredAction, EventLabel, Human, PrincipalRef,
};

/// A paused agent action waiting for a person to decide.
#[derive(Debug, Clone)]
pub struct ApprovalRequest<T: TenantScope> {
    id: ApprovalId,
    agent_id: AgentId,
    delegation_id: ActingUnder,
    origin: ApprovalOrigin,
    parties: ActionParties,
    action_class: DeclaredAction,
    action: ApprovalAction,
    state: ApprovalState,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// The longest a request may wait for a decision: 7 days. A call nobody
/// decided on in a week is asked for again.
pub const MAX_APPROVAL_SECONDS: u32 = 7 * 24 * 3600;

impl<T: TenantScope> ApprovalRequest<T> {
    /// Opens a pending approval request.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `ttl_seconds` is zero or longer
    ///   than [`MAX_APPROVAL_SECONDS`].
    /// - [`DomainError::Validation`] when the request names another agent
    ///   than the run it comes from.
    /// - [`DomainError::Validation`] when the request names another class
    ///   than the call the run paused on.
    /// - [`DomainError::Validation`] when the parties name no delegator for
    ///   an action using a delegation, or any for one using none.
    pub fn request(params: RequestApprovalParams) -> Result<Self, DomainError> {
        validate_range(
            "ttl_seconds",
            params.ttl_seconds.get(),
            1..=MAX_APPROVAL_SECONDS,
        )?;
        if let ApprovalOrigin::Run(run) = &params.origin {
            ensure_fits_run(run, &params)?;
        }
        ensure_parties_fit(&params)?;
        let now = crate::shared::clock::now();
        let expires_at = now.saturating_add(Duration::seconds(i64::from(params.ttl_seconds.get())));
        Ok(Self {
            id: ApprovalId::new(),
            agent_id: params.agent_id,
            delegation_id: params.delegation_id,
            origin: params.origin,
            parties: params.parties,
            action_class: params.action_class,
            action: params.action,
            state: ApprovalState::Pending(FirstOfTwo::NotGiven),
            created_at: now,
            expires_at,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Rebuilds an approval request from storage.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] for a run/agent mismatch, expiry or
    /// changes before raising, unordered approvals, or missing or repeated approvers.
    /// The requester, run starter, owner and delegators cannot approve; stored
    /// delegators must match the delegation. Withdrawal requires a run, and a run's
    /// request requires a class.
    pub fn reconstitute(row: ApprovalRequestRow) -> Result<Self, DomainError> {
        ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            agent_id: row.agent_id,
            delegation_id: row.delegation_id,
            origin: ApprovalOrigin::from_stored(row.origin, row.action_class)?,
            parties: row.parties,
            action_class: row.action_class,
            action: row.action,
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
    pub fn id(&self) -> &ApprovalId {
        &self.id
    }

    /// The agent whose action is paused.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// The delegation whose authority the action uses. A run calling its
    /// tools directly uses none.
    #[must_use]
    pub fn delegation_id(&self) -> &ActingUnder {
        &self.delegation_id
    }

    /// The run that paused, if a run raised this request. A request opened by
    /// hand has none.
    #[must_use]
    pub fn run_id(&self) -> Option<&AgentRunId> {
        self.run().map(RunOrigin::run_id)
    }

    fn run(&self) -> Option<&RunOrigin> {
        let ApprovalOrigin::Run(run) = &self.origin else {
            return None;
        };
        Some(run)
    }

    /// The class of the action waiting for approval, if known.
    #[must_use]
    pub fn action_class(&self) -> DeclaredAction {
        self.action_class
    }

    /// The exact call the run is holding, if a run raised this request.
    ///
    /// A decision carries this back to the run. So it applies to the call the
    /// approver saw, not to whatever the run holds by then.
    #[must_use]
    pub fn pending_call(&self) -> Option<&PendingCallRef> {
        self.run().map(RunOrigin::pending_call)
    }

    /// A summary of the paused action.
    #[must_use]
    pub fn action(&self) -> &ApprovalAction {
        &self.action
    }

    /// Current status. A request still waiting when its time to decide ran
    /// out reads as [`Expired`](ApprovalStatus::Expired), whether or not
    /// the expiry was saved yet.
    ///
    /// No sweep moves a lapsed request on. Without this, Olga's request
    /// that ran out last week would still sit in Bob's inbox as pending.
    #[must_use]
    pub fn status(&self) -> ApprovalStatus {
        if self.has_lapsed(crate::shared::clock::now()) {
            return ApprovalStatus::Expired;
        }
        self.state.status()
    }

    /// Whether the request was still waiting when its time to decide ran
    /// out, at `now`.
    fn has_lapsed(&self, now: OffsetDateTime) -> bool {
        self.state.status().is_pending() && now >= self.expires_at
    }

    /// Where it stands, with its approvals and decision.
    #[must_use]
    pub fn state(&self) -> &ApprovalState {
        &self.state
    }

    /// The account or machine that decided, if a decision was made.
    #[must_use]
    pub fn decided_by(&self) -> Option<PrincipalRef> {
        self.state.decision().map(|decision| decision.by())
    }

    /// When that decision was made.
    ///
    /// Only a real decision sets it, together with
    /// [`decided_by`](Self::decided_by). A request that expired undecided
    /// reports `None`. [`expires_at`](Self::expires_at) dates it instead.
    #[must_use]
    pub fn decided_at(&self) -> Option<OffsetDateTime> {
        self.state.decision().map(|decision| decision.at())
    }

    /// When the time to decide runs out.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether this request still waits for a decision.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status().is_pending()
    }

    /// Whether the paused action may run at `now` on `authority`: approved,
    /// before [`expires_at`](Self::expires_at), and backed by the live
    /// delegation the request names. Every other state allows nothing.
    #[must_use]
    pub fn grants_action_at(
        &self,
        now: OffsetDateTime,
        authority: &ActionAuthority<'_, T>,
    ) -> bool {
        self.status().is_approved()
            && now < self.expires_at
            && authority.backs(&self.delegation_id, now)
    }

    /// Where this request came from.
    #[must_use]
    pub fn origin(&self) -> &ApprovalOrigin {
        &self.origin
    }

    /// The agent's owner and the people behind the delegation the action
    /// uses.
    #[must_use]
    pub fn parties(&self) -> &ActionParties {
        &self.parties
    }

    /// The most sensitive data an approver reads in this request. See
    /// [`ApprovalOrigin::exposure`].
    #[must_use]
    pub fn exposure(&self) -> DataClassLevel {
        self.origin.exposure()
    }

    /// Whether `reader` is cleared for the data this request shows.
    ///
    /// Sam may see internal data only. A request raised by a run that read
    /// payroll shows confidential figures, so it stays out of his inbox and
    /// his reach, though he may view the agent.
    #[must_use]
    pub fn readable_by(&self, reader: &TenantAuthority) -> bool {
        reader.data_clearance() >= self.exposure()
    }

    /// Raises `agents.approval_requested` for notification to eligible decision makers,
    /// naming the action and its delegation.
    ///
    /// # Errors
    /// [`DomainError::Validation`] if `delegation` differs from the request's delegation.
    /// [`DomainError::InvalidTransition`] unless the request still awaits a decision.
    pub fn announce_request(&mut self, delegation: &Delegation<T>) -> Result<(), DomainError> {
        announce::raise_request(self, delegation)
    }

    /// Announces how the request was decided, its agent named `agent` as
    /// the audit trail knows it.
    ///
    /// Raises `agents.approval_granted` once approved and
    /// `agents.approval_signed` on the first of two approvals, each with how
    /// long the request waited, `agents.approval_denied` once refused, and
    /// `agents.approval_withdrawn` once its run was stopped. A request still
    /// waiting for its first approval, expired or spent announces nothing.
    pub fn announce_decision(&mut self, agent: EventLabel) {
        announce::decision(self, agent);
    }

    /// How many different people must approve before the action may run.
    ///
    /// It is two for a high-risk class, and two when the class is unknown. A
    /// request that cannot say what it is for counts as the riskiest kind.
    #[must_use]
    pub fn approvers_needed(&self) -> u8 {
        if self.is_high_risk() {
            return 2;
        }
        1
    }

    /// Whether each approver must prove they are present with a fresh second
    /// factor. It follows the same rule as two approvers: high-risk or
    /// unknown.
    #[must_use]
    pub fn needs_presence(&self) -> bool {
        self.is_high_risk()
    }

    fn is_high_risk(&self) -> bool {
        self.action_class.may_be_high_risk()
    }

    /// The first of two approvals, if one has been given.
    #[must_use]
    pub fn first_approval(&self) -> Option<&Approval> {
        self.state.first().approval()
    }

    /// The approval that granted the action, with the person who gave it,
    /// once it is granted.
    #[must_use]
    pub fn granting_approval(&self) -> Option<&Approval> {
        self.state.approval()
    }

    /// How long the request waited for its decision, when it has one.
    #[must_use]
    pub fn time_to_decide(&self) -> Option<Duration> {
        self.decided_at()
            .map(|at| crate::shared::clock::between(self.created_at, at))
    }

    /// Approves the paused action.
    ///
    /// Whoever put the action there cannot approve it, through any account.
    /// That is the person who opened the request, or who started the run.
    /// Nor can the agent's owner, or a person behind the delegation it uses.
    /// An approval exists so someone else looks at what the agent will do.
    ///
    /// The approver must hold the permission to approve agent actions, and
    /// be cleared for the data the request shows. A tenant user with no
    /// rights approves nothing.
    ///
    /// A high-risk action needs two approvals from different people. The
    /// first is recorded and the action keeps waiting. The second grants it.
    ///
    /// The time limit is checked here, against the clock. No background job
    /// moves a lapsed request to [`Expired`](ApprovalStatus::Expired).
    /// Without this check, a request with fifteen minutes to decide could be
    /// approved weeks later. Past the limit, this call expires the request,
    /// so it can be saved as expired.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] for the requester, owner, delegator or first
    /// approver; missing approval rights or clearance; or missing presence for high risk.
    /// Returns [`DomainError::InvalidTransition`] after expiry or unless pending.
    pub fn approve(&mut self, approver: &Approver<'_>) -> Result<ApprovalStep, DomainError> {
        self.ensure_not_answerable(approver.by())?;
        approver.ensure_entitled(self.exposure())?;
        self.ensure_present(approver)?;
        let now = crate::shared::clock::now();
        self.ensure_open(now)?;
        self.ensure_not_first_approver(approver.by())?;
        let first = self.state.first().clone();
        let approval = Approval {
            by: approver.by().clone(),
            at: now,
        };
        if self.approvers_needed() == 2 && first == FirstOfTwo::NotGiven {
            self.state = ApprovalState::Pending(FirstOfTwo::Given(approval));
            self.updated_at = now;
            return Ok(ApprovalStep::AwaitingSecond);
        }
        self.move_to(ApprovalState::Approved { approval, first })?;
        Ok(ApprovalStep::Granted)
    }

    /// Refuses an approver of a high-risk action who did not prove they are
    /// present just now.
    fn ensure_present(&self, approver: &Approver<'_>) -> Result<(), DomainError> {
        if self.needs_presence() && approver.presence() != Presence::Proven {
            return Err(DomainError::forbidden(message!(
                "agents-a-high-risk-action-needs-an",
                "a high-risk action needs an approver who proved they are present just now"
            )));
        }
        Ok(())
    }

    /// Refuses a request that no longer waits for a decision at `now`. One
    /// whose time to decide ran out is expired by the attempt.
    fn ensure_open(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.has_lapsed(now) {
            self.expire()?;
            return Err(DomainError::invalid_transition(message!(
                "agents-the-approval-decision-window-has-closed",
                "the approval decision window has closed"
            )));
        }
        if !self.state.status().is_pending() {
            return Err(DomainError::invalid_transition(message!(
                "agents-the-approval-is-no-longer-pending",
                "the approval is no longer pending"
            )));
        }
        Ok(())
    }

    /// Refuses whoever put the action there, the agent's owner and the
    /// people behind the delegation it uses, through any of their accounts.
    fn ensure_not_answerable(&self, by: &Human) -> Result<(), DomainError> {
        if self.origin.is_requester(by) || self.parties.include(by) {
            return Err(DomainError::forbidden(message!(
                "agents-an-approval-cannot-be-granted-by",
                "an approval cannot be granted by its requester, the agent's owner or a delegator"
            )));
        }
        Ok(())
    }

    /// Refuses whoever gave the first of two approvals. That covers the same
    /// account, and the same person through any account.
    fn ensure_not_first_approver(&self, by: &Human) -> Result<(), DomainError> {
        let gave_the_first = self
            .first_approval()
            .is_some_and(|first| first.by.is_same_person_as(by));
        if gave_the_first {
            return Err(DomainError::forbidden(message!(
                "agents-the-second-approval-must-come-from",
                "the second approval must come from a different person"
            )));
        }
        Ok(())
    }

    /// Denies the paused action and returns proof for its run to drop the held call.
    /// Requires approval rights and sufficient clearance. A late decision expires the
    /// request instead of recording a denial; see [`expire`](Self::expire).
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without approval rights or sufficient clearance.
    /// [`DomainError::InvalidTransition`] if the decision window ended or it is not pending.
    pub fn deny(&mut self, by: &Approver<'_>) -> Result<Option<DeniedCall>, DomainError> {
        by.ensure_entitled(self.exposure())?;
        self.ensure_open(crate::shared::clock::now())?;
        let decision = Decision::now(by.by().clone());
        let first = self.state.first().clone();
        self.move_to(ApprovalState::Denied { decision, first })?;
        Ok(self
            .run()
            .map(|run| DeniedCall::new(*run.run_id(), run.pending_call().clone())))
    }

    /// Uses up an approval on the one action it allowed, on `authority`, the
    /// delegation the action uses as it stands now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] unless the request is approved,
    ///   its time has not run out, and `authority` is the live delegation it
    ///   names. A pending, denied, expired or used approval lets nothing
    ///   through. Nor does one whose delegation is revoked or expired.
    pub fn consume(&mut self, authority: &ActionAuthority<'_, T>) -> Result<(), DomainError> {
        if !self.grants_action_at(crate::shared::clock::now(), authority) {
            return Err(DomainError::invalid_transition(message!(
                "agents-only-an-approved-unexpired-approval-on",
                "only an approved, unexpired approval on a live delegation can be spent"
            )));
        }
        let ApprovalState::Approved { approval, first } = self.state.clone() else {
            return Err(DomainError::invalid_transition(message!(
                "agents-only-an-approved-approval-can-be",
                "only an approved approval can be spent"
            )));
        };
        self.move_to(ApprovalState::Consumed { approval, first })
    }

    /// Uses up the approval on the call its run holds. Gives back the proof
    /// the run resumes on.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] unless the request is approved,
    ///   its time has not run out, and `authority` backs it. See
    ///   [`consume`](Self::consume).
    /// - [`DomainError::Validation`] when the request was opened by hand, not
    ///   raised by a run.
    pub fn release(
        &mut self,
        authority: &ActionAuthority<'_, T>,
    ) -> Result<ReleasedCall, DomainError> {
        let Some(run) = self.run() else {
            return Err(DomainError::invalid(message!(
                "agents-only-a-request-raised-by-a-2",
                "only a request raised by a run releases a run's call"
            )));
        };
        let released = ReleasedCall::new(*run.run_id(), run.pending_call().clone());
        self.consume(authority)?;
        Ok(released)
    }

    /// Expires the request when nobody decided in time. A request whose
    /// time ran out but whose expiry was not saved yet may still be expired.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the request is not pending.
    pub fn expire(&mut self) -> Result<(), DomainError> {
        let first = self.state.first().clone();
        self.move_to(ApprovalState::Expired(first))
    }

    /// Takes the request back because the run that raised it was stopped.
    /// It is recorded as withdrawn by the person who stopped the run, not
    /// as denied or expired, since nobody decided it.
    ///
    /// Ann stops her agent's run while it waits on a payment. Without this,
    /// Bob approves the payment later, for a run that will never make it,
    /// and the inbox shows a decision nobody needed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the request was opened by hand,
    ///   not raised by a run.
    /// - [`DomainError::Forbidden`] when `cancelled` is another run's.
    /// - [`DomainError::InvalidTransition`] when the request is not pending,
    ///   or its time to decide has run out.
    pub fn withdraw(&mut self, cancelled: &RunCancelled) -> Result<(), DomainError> {
        let Some(run) = self.run() else {
            return Err(DomainError::invalid(message!(
                "agents-only-a-request-raised-by-a-3",
                "only a request raised by a run is withdrawn when the run stops"
            )));
        };
        if run.run_id() != cancelled.run_id() {
            return Err(DomainError::forbidden(message!(
                "agents-the-cancellation-is-of-another-run",
                "the cancellation is of another run"
            )));
        }
        self.ensure_open(crate::shared::clock::now())?;
        let decision = Decision::now(cancelled.by().clone());
        let first = self.state.first().clone();
        self.move_to(ApprovalState::Withdrawn { decision, first })
    }

    /// Takes the request back because a person changed the call it is
    /// about, as `revised` proves. A new request is opened for the changed
    /// call, so nobody approves the old one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the request was opened by hand,
    ///   not raised by a run.
    /// - [`DomainError::Forbidden`] when `revised` is another run's.
    /// - [`DomainError::Conflict`] when `revised` changed another call than
    ///   the one this request is about.
    /// - [`DomainError::InvalidTransition`] when the request is not pending,
    ///   or its time to decide has run out.
    pub fn supersede(&mut self, revised: &RevisedCall) -> Result<(), DomainError> {
        let Some(run) = self.run() else {
            return Err(DomainError::invalid(message!(
                "agents-only-a-request-raised-by-a",
                "only a request raised by a run is about a call a person can change"
            )));
        };
        if run.run_id() != revised.run_id() {
            return Err(DomainError::forbidden(message!(
                "agents-the-change-is-to-another-run",
                "the change is to another run's call"
            )));
        }
        if run.pending_call() != revised.previous() {
            return Err(DomainError::conflict(message!(
                "agents-the-change-is-to-another-call",
                "the change is to another call than this request's"
            )));
        }
        self.ensure_open(crate::shared::clock::now())?;
        let decision = Decision::now(revised.by().clone());
        let first = self.state.first().clone();
        self.move_to(ApprovalState::Withdrawn { decision, first })
    }

    fn move_to(&mut self, to: ApprovalState) -> Result<(), DomainError> {
        self.state
            .status()
            .try_transition(to.status())
            .map_err(|e| {
                DomainError::invalid_transition(message!(
                    "agents-cannot-transition-approval-from-to",
                    format!("cannot transition approval from {:?} to {:?}", e.from, e.to)
                ))
            })?;
        self.updated_at = to
            .decision()
            .map_or_else(crate::shared::clock::now, |decision| decision.at());
        self.state = to;
        Ok(())
    }
}

impl<T: TenantScope> Aggregate for ApprovalRequest<T> {
    type Id = ApprovalId;

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
    use crate::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
    use crate::domains::agents::authority::delegation::{
        Delegate, Delegation, GrantDelegationParams, HeldBy, HeldResources, ReviewDuty,
    };
    use crate::domains::agents::authority::intent::IntentEnvelope;
    use crate::domains::agents::execution::run::{
        AgentRun, ResolvedCall, RunGoal, RunStarter, StartRunParams, ToolCall,
    };
    use crate::domains::agents::execution::tool::tests::fixtures::registered;
    use crate::domains::agents::execution::tool::{PathValue, PathValues, ToolMethod, ToolName};
    use crate::domains::agents::identity::acting::ActingAgent;
    use crate::domains::agents::identity::agent::{AgentIdentity, CreateAgentParams};
    use crate::domains::agents::identity::control::AgentControl;
    use crate::domains::authorization::permission::{
        AgentAction, DataAccessAction, SystemPermission,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::chain::EventOrigin;
    use crate::shared::events::event::DomainEvent;
    use crate::shared::model::restriction::Restriction;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{
        ActionClass, DelegationId, EventLabel, HumanAccount, Initiator, Label, ModelProviderId,
        OrgUserId, PersonKey, Seconds, TenantId, UserId,
    };

    /// What the action of a request that uses no delegation runs on.
    const NONE: ActionAuthority<'static, ResolvedTenant> = ActionAuthority::NoDelegation;

    /// What someone allowed to approve agent actions holds.
    const APPROVES: &[SystemPermission] = &[SystemPermission::Agents(AgentAction::Approve)];

    /// What someone allowed to create agents holds.
    const CREATES: &[SystemPermission] = &[SystemPermission::Agents(AgentAction::Create)];

    /// `by`, allowed to approve agent actions and cleared for every class.
    fn cleared(by: &Human) -> Approver<'_> {
        cleared_for(by, DataClassLevel::Restricted)
    }

    /// A financial action refuses an otherwise entitled approver who has
    /// not proved their presence.
    #[test]
    fn a_high_risk_approval_needs_proof_of_presence() {
        let mut request = of_class(
            UserId::new(),
            DeclaredAction::Declared(ActionClass::Financial),
        );
        let bob = approver_for(UserId::new());
        let absent = Approver::assumed(
            AgentControl::new(assumed_authority(&bob, TenantId::new(), APPROVES, &[])),
            DataClassLevel::Restricted,
            Presence::NotProven,
        );

        let result = request.approve(&absent);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// `by`, allowed to approve agent actions and cleared for `clearance`.
    fn cleared_for(by: &Human, clearance: DataClassLevel) -> Approver<'_> {
        Approver::assumed(
            AgentControl::new(assumed_authority(by, TenantId::new(), APPROVES, &[])),
            clearance,
            Presence::Proven,
        )
    }

    /// The human acting through tenant account `id`, as a person of their own.
    fn approver_for(id: UserId) -> Human {
        Human::new(
            HumanAccount::User(id),
            PersonKey::new(format!("{id}@corp.test")).unwrap(),
        )
    }

    fn person(address: &str) -> PersonKey {
        PersonKey::new(address).unwrap()
    }

    fn human(address: &str) -> Human {
        Human::new(HumanAccount::User(UserId::new()), person(address))
    }

    /// Owen owns the agent, and the action uses no delegation.
    fn parties() -> ActionParties {
        ActionParties::from_stored(human("owen@corp.test"), Vec::new())
    }

    /// The delegation a run of `agent` started by `starter` acts under, with
    /// the starter it names. A person delegates to the agent. An agent
    /// starter is the agent spending its own token.
    fn delegated_by(
        starter: Initiator,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> (Delegation<ResolvedTenant>, Initiator) {
        let constraints = DelegationConstraints::new(Seconds::new(3600), 1).unwrap();
        let Initiator::Human(person) = &starter else {
            let owned = Delegation::grant_owned(*agent.id(), CapabilitySet::default(), constraints);
            return (owned, Initiator::Agent(*agent.id()));
        };
        let nothing = CapabilitySet::default();
        let control = AgentControl::new(assumed_authority(person, TenantId::new(), &[], &[]));
        let granted = Delegation::grant(
            GrantDelegationParams {
                granted: CapabilitySet::default(),
                constraints,
                name: None,
            },
            &HeldBy::worked_out::<ResolvedTenant>(
                &control,
                &nothing,
                &HeldResources::answered(person.principal(), Vec::new()),
                &[],
            )
            .unwrap(),
            &Delegate {
                agent,
                duty: ReviewDuty::NotReviewing,
            },
        )
        .unwrap();
        (granted, starter)
    }

    /// A run started by `starter`, paused on `delete_order({"id":1})`.
    fn paused_run(starter: Initiator) -> AgentRun<ResolvedTenant> {
        paused_run_from(starter, EventOrigin::Outside)
    }

    fn paused_run_from(starter: Initiator, origin: EventOrigin) -> AgentRun<ResolvedTenant> {
        paused_at(starter, origin, DataClassLevel::Public)
    }

    /// A run of Owen's agent started by `starter` at `exposure`, paused on
    /// `delete_order({"id":1})`.
    fn paused_at(
        starter: Initiator,
        origin: EventOrigin,
        exposure: DataClassLevel,
    ) -> AgentRun<ResolvedTenant> {
        paused_with_agent(starter, origin, exposure).0
    }

    /// A run as `paused_at` makes it, with Owen's agent running it.
    fn paused_with_agent(
        starter: Initiator,
        origin: EventOrigin,
        exposure: DataClassLevel,
    ) -> (AgentRun<ResolvedTenant>, AgentIdentity<ResolvedTenant>) {
        let owen = human("owen@corp.test");
        let agent = tidying_agent(&owen);
        let (delegation, starter) = delegated_by(starter, &agent);
        let signed_in = ActingAgent::assumed(*agent.id());
        let by = match &starter {
            Initiator::Human(person) => {
                RunStarter::person(assumed_authority(person, TenantId::new(), &[], &[]))
            }
            Initiator::Agent(_) | Initiator::Consumer(_) => RunStarter::agent(&signed_in),
        };
        let mut run =
            AgentRun::start(by, tidying_run(origin, exposure), &delegation, &agent).unwrap();
        let tool = registered(
            "delete_order",
            ToolMethod::Delete,
            "/orders/{id}",
            DeclaredAction::Undeclared,
            exposure,
        );
        let values = PathValues::new().with("id", PathValue::new("1").unwrap());
        let call = ToolCall::new("delete_order", "{\"id\":1}").unwrap();
        run.await_approval(ResolvedCall::resolve(call, &tool, &values).unwrap(), &agent)
            .unwrap();
        (run, agent)
    }

    /// Creates the agent whose order deletion will require approval.
    fn tidying_agent(owner: &Human) -> AgentIdentity<ResolvedTenant> {
        AgentIdentity::create(
            &AgentControl::new(assumed_authority(owner, TenantId::new(), CREATES, &[])),
            CreateAgentParams {
                name: Label::new("name", "tidier").unwrap(),
                description: None,
            },
        )
        .unwrap()
    }

    /// Defines a five-step deletion run that pauses before using its only tool.
    fn tidying_run(origin: EventOrigin, exposure: DataClassLevel) -> StartRunParams {
        StartRunParams {
            provider_id: ModelProviderId::new(),
            goal: RunGoal::new("tidy the orders").unwrap(),
            purpose: IntentEnvelope::new([ActionClass::Delete]),
            granted_tools: vec![ToolName::new("delete_order").unwrap()],
            approval_classes: vec![ActionClass::Delete],
            max_steps: 5,
            spend_limit: Restriction::Unrestricted,
            ask_past: Restriction::Unrestricted,
            exposure,
            origin,
        }
    }

    /// Owen orders `run` stopped, and the worker stops it on his order.
    fn stopped_by_owner(
        run: &mut AgentRun<ResolvedTenant>,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> RunCancelled {
        let owen = AgentControl::new(assumed_authority(agent.owner(), TenantId::new(), &[], &[]));
        let order = run.order_cancel(&owen, agent).unwrap();
        run.cancel(&order).unwrap().unwrap()
    }

    /// Owen stops his agent's run while it waits on a delete. Its request is
    /// withdrawn, by Owen, and grants nothing. Nobody approves it afterwards.
    #[test]
    fn stopping_a_run_withdraws_its_pending_request() {
        let (mut run, agent) = paused_with_agent(
            Initiator::Agent(AgentId::new()),
            EventOrigin::Outside,
            DataClassLevel::Public,
        );
        let mut r = raised_by(&run, ActionClass::Delete).unwrap();
        let cancelled = stopped_by_owner(&mut run, &agent);

        r.withdraw(&cancelled).unwrap();

        assert_eq!(r.status(), ApprovalStatus::Withdrawn);
        assert_eq!(r.decided_by(), Some(agent.owner().principal()));
        assert!(!r.grants_action_at(now(), &NONE));
        assert!(matches!(
            r.approve(&cleared(&human("bob@corp.test"))),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// Cancelling one run does not authorize withdrawing another run's
    /// approval request. The refusal leaves that request pending.
    #[test]
    fn a_cancellation_withdraws_only_its_own_runs_request() {
        let (mut stopped, agent) = paused_with_agent(
            Initiator::Agent(AgentId::new()),
            EventOrigin::Outside,
            DataClassLevel::Public,
        );
        let other = paused_run(Initiator::Agent(AgentId::new()));
        let mut r = raised_by(&other, ActionClass::Delete).unwrap();
        let cancelled = stopped_by_owner(&mut stopped, &agent);

        let result = r.withdraw(&cancelled);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(r.is_pending());
    }

    /// A request opened by hand names no run, so no cancellation withdraws
    /// it. It is refused and stays pending.
    #[test]
    fn a_hand_opened_request_is_not_withdrawn_by_a_cancellation() {
        let (mut run, agent) = paused_with_agent(
            Initiator::Agent(AgentId::new()),
            EventOrigin::Outside,
            DataClassLevel::Public,
        );
        let cancelled = stopped_by_owner(&mut run, &agent);
        let mut r = request();

        let result = r.withdraw(&cancelled);

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(r.is_pending());
    }

    /// Bob, who may approve, changes `run`'s held delete to order 2, as
    /// Owen's agent runs it.
    fn revised_by_bob(
        run: &mut AgentRun<ResolvedTenant>,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> RevisedCall {
        let bob = human("bob@corp.test");
        let editor = AgentControl::new(assumed_authority(&bob, TenantId::new(), APPROVES, &[]));
        let tool = registered(
            "delete_order",
            ToolMethod::Delete,
            "/orders/{id}",
            DeclaredAction::Undeclared,
            DataClassLevel::Public,
        );
        let values = PathValues::new().with("id", PathValue::new("1").unwrap());
        let call = ToolCall::new("delete_order", "{\"id\":2}").unwrap();
        run.revise_pending(
            &editor,
            ResolvedCall::resolve(call, &tool, &values).unwrap(),
            agent,
        )
        .unwrap()
    }

    /// Bob changes the call a request is about. The request is withdrawn,
    /// in Bob's name, and nobody approves the old call afterwards.
    #[test]
    fn changing_the_held_call_withdraws_its_request() {
        let (mut run, agent) = paused_with_agent(
            Initiator::Agent(AgentId::new()),
            EventOrigin::Outside,
            DataClassLevel::Public,
        );
        let mut r = raised_by(&run, ActionClass::Delete).unwrap();
        let revised = revised_by_bob(&mut run, &agent);

        r.supersede(&revised).unwrap();

        assert_eq!(r.status(), ApprovalStatus::Withdrawn);
        assert_eq!(r.decided_by(), Some(revised.by().principal()));
    }

    /// Revising one run's call cannot withdraw another run's request,
    /// which remains pending. A request opened by hand also refuses the revision.
    #[test]
    fn a_change_withdraws_only_the_request_about_that_call() {
        let (mut changed, agent) = paused_with_agent(
            Initiator::Agent(AgentId::new()),
            EventOrigin::Outside,
            DataClassLevel::Public,
        );
        let other = paused_run(Initiator::Agent(AgentId::new()));
        let mut theirs = raised_by(&other, ActionClass::Delete).unwrap();
        let mut by_hand = request();
        let revised = revised_by_bob(&mut changed, &agent);

        let on_theirs = theirs.supersede(&revised);
        let on_hand = by_hand.supersede(&revised);

        assert!(matches!(on_theirs, Err(DomainError::Forbidden(_))));
        assert!(matches!(on_hand, Err(DomainError::Validation(_))));
        assert!(theirs.is_pending());
    }

    /// A workflow's run pauses for approval, and a run started by hand does
    /// too. A decision on the first is taken carrying the workflow's chain,
    /// so loop protection still counts when a person decides in between. A
    /// decision on the second comes from outside.
    #[test]
    fn a_request_from_a_workflows_run_marks_its_events_with_the_chain() {
        let chain = EventOrigin::Execution(crate::shared::events::chain::ChainDepth::FIRST);
        let starter = Initiator::Human(approver_for(UserId::new()));
        let mut marked = raised_by(
            &paused_run_from(starter.clone(), chain),
            ActionClass::Delete,
        )
        .unwrap();
        let mut outside = raised_by(&paused_run(starter), ActionClass::Delete).unwrap();
        let bob = human("bob@corp.test");

        for request in [&mut marked, &mut outside] {
            request.deny(&cleared(&bob)).unwrap();
            request.announce_decision(EventLabel::of("tidier"));
        }

        assert_eq!(raised(&mut marked)[0].origin(), chain);
        assert_eq!(raised(&mut outside)[0].origin(), EventOrigin::Outside);
    }

    fn raised_by(
        run: &AgentRun<ResolvedTenant>,
        class: ActionClass,
    ) -> Result<ApprovalRequest<ResolvedTenant>, DomainError> {
        ApprovalRequest::request(RequestApprovalParams {
            agent_id: *run.agent_id(),
            delegation_id: ActingUnder::NoDelegation,
            origin: ApprovalOrigin::Run(RunOrigin::of(run).unwrap()),
            parties: parties(),
            action_class: DeclaredAction::Declared(class),
            action: ApprovalAction::new("delete_order({\"id\":1})").unwrap(),
            ttl_seconds: Seconds::new(900),
        })
    }

    fn requested_by(who: UserId) -> ApprovalRequest<ResolvedTenant> {
        of_class(who, DeclaredAction::Declared(ActionClass::Write))
    }

    fn of_class(who: UserId, action_class: DeclaredAction) -> ApprovalRequest<ResolvedTenant> {
        ApprovalRequest::request(RequestApprovalParams {
            agent_id: AgentId::new(),
            delegation_id: ActingUnder::NoDelegation,
            action_class,
            action: ApprovalAction::new("transfer $5000 to vendor").unwrap(),
            origin: ApprovalOrigin::Opened(Initiator::Human(approver_for(who))),
            parties: parties(),
            ttl_seconds: Seconds::new(900),
        })
        .unwrap()
    }

    fn request() -> ApprovalRequest<ResolvedTenant> {
        requested_by(UserId::new())
    }

    /// A request is opened with zero seconds to decide. It is refused, since
    /// nobody could ever approve it.
    #[test]
    fn request_rejects_zero_window() {
        assert!(
            ApprovalRequest::<ResolvedTenant>::request(RequestApprovalParams {
                agent_id: AgentId::new(),
                delegation_id: ActingUnder::NoDelegation,
                action_class: DeclaredAction::Undeclared,
                action: ApprovalAction::new("x").unwrap(),
                origin: ApprovalOrigin::Opened(Initiator::Human(approver_for(UserId::new()))),
                parties: parties(),
                ttl_seconds: Seconds::new(0),
            })
            .is_err()
        );
    }

    /// A request opened by hand with `ttl_seconds` to decide.
    fn opened_for(ttl_seconds: u32) -> Result<ApprovalRequest<ResolvedTenant>, DomainError> {
        ApprovalRequest::request(RequestApprovalParams {
            agent_id: AgentId::new(),
            delegation_id: ActingUnder::NoDelegation,
            action_class: DeclaredAction::Undeclared,
            action: ApprovalAction::new("x").unwrap(),
            origin: ApprovalOrigin::Opened(Initiator::Human(approver_for(UserId::new()))),
            parties: parties(),
            ttl_seconds: Seconds::new(ttl_seconds),
        })
    }

    /// Decision windows of `u32::MAX` seconds or one second above the limit
    /// are refused. A window exactly at the limit is accepted.
    #[test]
    fn a_window_past_the_ceiling_is_refused() {
        assert!(opened_for(u32::MAX).is_err());
        assert!(opened_for(MAX_APPROVAL_SECONDS + 1).is_err());
        assert!(opened_for(MAX_APPROVAL_SECONDS).is_ok());
    }

    /// A request for an action under Ann's delegation names no one behind
    /// it. It is refused, since nobody could then tell whether Ann approves
    /// her own delegation's action. One naming a delegator for an action
    /// under no delegation is refused too.
    #[test]
    fn the_parties_name_delegators_exactly_when_a_delegation_is_used() {
        let opened = |delegation_id, delegators| {
            ApprovalRequest::<ResolvedTenant>::request(RequestApprovalParams {
                agent_id: AgentId::new(),
                delegation_id,
                action_class: DeclaredAction::Declared(ActionClass::Write),
                action: ApprovalAction::new("rotate the key").unwrap(),
                origin: ApprovalOrigin::Opened(Initiator::Human(human("bob@corp.test"))),
                parties: ActionParties::from_stored(human("owen@corp.test"), delegators),
                ttl_seconds: Seconds::new(900),
            })
        };

        let unnamed = opened(ActingUnder::Delegation(DelegationId::new()), Vec::new());
        let stray = opened(ActingUnder::NoDelegation, vec![human("ann@corp.test")]);

        assert!(matches!(unnamed, Err(DomainError::Validation(_))));
        assert!(matches!(stray, Err(DomainError::Validation(_))));
    }

    /// An approver without approval rights is refused despite sufficient
    /// clearance and presence. The request remains pending.
    #[test]
    fn an_approver_must_hold_the_right_to_approve() {
        let mut r = request();
        let carol = human("carol@corp.test");
        let empty_handed = Approver::assumed(
            AgentControl::new(assumed_authority(&carol, TenantId::new(), &[], &[])),
            DataClassLevel::Restricted,
            Presence::Proven,
        );

        let result = r.approve(&empty_handed);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(r.is_pending());
    }

    /// A request from a run exposed to confidential data is unreadable
    /// without sufficient clearance and readable with confidential clearance.
    #[test]
    fn only_a_reader_cleared_for_what_it_shows_reads_a_request() {
        let run = paused_at(
            Initiator::Agent(AgentId::new()),
            EventOrigin::Outside,
            DataClassLevel::Confidential,
        );
        let r = raised_by(&run, ActionClass::Delete).unwrap();
        let (sam, bob) = (human("sam@corp.test"), human("bob@corp.test"));
        let sam_holds = assumed_authority(&sam, TenantId::new(), &[], &[]);
        let bob_holds = assumed_authority(
            &bob,
            TenantId::new(),
            &[SystemPermission::Data(DataAccessAction::Confidential)],
            &[],
        );

        assert!(!r.readable_by(sam_holds));
        assert!(r.readable_by(bob_holds));
    }

    /// A confidential run's request refuses an approver cleared only for
    /// public data. An approver cleared for confidential data gives its
    /// first approval, leaving the high-risk action waiting for a second.
    #[test]
    fn an_approver_must_be_cleared_for_what_the_run_read() {
        let run = paused_at(
            Initiator::Agent(AgentId::new()),
            EventOrigin::Outside,
            DataClassLevel::Confidential,
        );
        let mut r = raised_by(&run, ActionClass::Delete).unwrap();
        let (sam, bob) = (human("sam@corp.test"), human("bob@corp.test"));

        let by_sam = r.approve(&cleared_for(&sam, DataClassLevel::Public));
        let by_bob = r.approve(&cleared_for(&bob, DataClassLevel::Confidential));

        assert_eq!(r.exposure(), DataClassLevel::Confidential);
        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(by_bob.unwrap(), ApprovalStep::AwaitingSecond);
    }

    /// An agent's owner cannot approve its paused delete through an
    /// organization account. The refusal records no first approval.
    #[test]
    fn the_agents_owner_cannot_approve_its_action() {
        let run = paused_run(Initiator::Agent(AgentId::new()));
        let mut r = raised_by(&run, ActionClass::Delete).unwrap();
        let owen_through_org = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            person("owen@corp.test"),
        );

        let result = r.approve(&cleared(&owen_through_org));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(r.first_approval().is_none());
    }

    /// A person behind an action's delegation cannot approve the agent's
    /// request to perform that action.
    #[test]
    fn the_person_behind_the_delegation_cannot_approve_its_action() {
        let ann = human("ann@corp.test");
        let mut r = ApprovalRequest::<ResolvedTenant>::request(RequestApprovalParams {
            agent_id: AgentId::new(),
            delegation_id: ActingUnder::Delegation(DelegationId::new()),
            action_class: DeclaredAction::Declared(ActionClass::Write),
            action: ApprovalAction::new("rotate the signing key").unwrap(),
            origin: ApprovalOrigin::Opened(Initiator::Agent(AgentId::new())),
            parties: ActionParties::from_stored(human("owen@corp.test"), vec![ann.clone()]),
            ttl_seconds: Seconds::new(900),
        })
        .unwrap();

        assert!(matches!(
            r.approve(&cleared(&ann)),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// An approved request grants an action only with its live delegation.
    /// Revoking that delegation removes the grant and prevents consuming the approval.
    #[test]
    fn an_approval_dies_with_the_delegation_it_uses() {
        let agent = AgentId::new();
        let mut delegation: Delegation<ResolvedTenant> = Delegation::grant_owned(
            agent,
            CapabilitySet::default(),
            DelegationConstraints::new(Seconds::new(600), 0).unwrap(),
        );
        let mut r = approved_invoice(&delegation);
        let live = ActionAuthority::Delegation {
            delegation: &delegation,
            above: &[],
        };
        assert!(r.grants_action_at(now(), &live));
        assert!(!r.grants_action_at(now(), &NONE), "it names a delegation");

        delegation
            .revoke(crate::domains::agents::authority::delegation::Revoker::Platform)
            .unwrap();
        let revoked = ActionAuthority::Delegation {
            delegation: &delegation,
            above: &[],
        };

        assert!(!r.grants_action_at(now(), &revoked));
        assert!(matches!(
            r.consume(&revoked),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// Has Bob approve the invoice request under the supplied agent delegation.
    fn approved_invoice(
        delegation: &Delegation<ResolvedTenant>,
    ) -> ApprovalRequest<ResolvedTenant> {
        let agent = *delegation.delegate();
        let mut request = ApprovalRequest::request(RequestApprovalParams {
            agent_id: agent,
            delegation_id: ActingUnder::Delegation(*delegation.id()),
            action_class: DeclaredAction::Declared(ActionClass::Write),
            action: ApprovalAction::new("pay invoice 7").unwrap(),
            origin: ApprovalOrigin::Opened(Initiator::Agent(agent)),
            parties: ActionParties::from_stored(
                human("owen@corp.test"),
                vec![human("ann@corp.test")],
            ),
            ttl_seconds: Seconds::new(900),
        })
        .unwrap();
        request.approve(&cleared(&human("bob@corp.test"))).unwrap();
        request
    }

    /// A paused `DELETE` on `/repos/1?force=true` is summed up as the method
    /// and the full target, query included. The approver sees `force=true`.
    #[test]
    fn the_action_of_a_call_is_its_method_and_target() {
        let action =
            ApprovalAction::for_call(crate::types::HttpMethod::Delete, "/repos/1?force=true")
                .unwrap();

        assert_eq!(action.as_str(), "DELETE /repos/1?force=true");
    }

    /// A call's target is free text such as "transfer $5000" instead of a
    /// path. No summary is made from it, so an approver never reads a
    /// made-up description as the call.
    #[test]
    fn a_call_whose_target_is_not_a_path_has_no_action() {
        assert!(
            ApprovalAction::for_call(crate::types::HttpMethod::Post, "transfer $5000").is_err()
        );
    }

    /// A request has just been opened and nobody has decided. The paused
    /// action may not run yet.
    #[test]
    fn pending_request_grants_nothing() {
        let r = request();
        assert!(r.is_pending());
        assert!(!r.grants_action_at(crate::shared::clock::now(), &NONE));
    }

    /// Someone other than the requester approves a low-risk request. The
    /// action may run, and the request names that person as the decider.
    #[test]
    fn approved_request_grants_action_and_records_approver() {
        let mut r = request();
        let approver = UserId::new();
        r.approve(&cleared(&approver_for(approver))).unwrap();
        assert!(r.grants_action_at(crate::shared::clock::now(), &NONE));
        assert_eq!(r.decided_by(), Some(PrincipalRef::User(approver)));
    }

    /// Approving a request one second after its window closes is refused.
    /// The request expires, grants no action and records no decider.
    #[test]
    fn a_lapsed_request_cannot_be_approved() {
        let mut r = request();
        let after_the_window = r.expires_at() + Duration::seconds(1);
        let _late = crate::shared::clock::freeze(after_the_window);

        let result = r.approve(&cleared(&approver_for(UserId::new())));

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert_eq!(r.status(), ApprovalStatus::Expired);
        assert!(!r.grants_action_at(after_the_window, &NONE));
        assert!(r.decided_by().is_none());
    }

    /// Olga's request ran out a second ago and nothing saved its expiry. It
    /// reads as expired, not pending, so it leaves Bob's inbox.
    #[test]
    fn a_lapsed_request_reads_as_expired() {
        let r = request();
        let _late = crate::shared::clock::freeze(r.expires_at() + Duration::seconds(1));

        assert_eq!(r.status(), ApprovalStatus::Expired);
        assert!(!r.is_pending());
    }

    /// Denying a request one second after its window closes is refused.
    /// Its stored state becomes expired without recording a decider.
    #[test]
    fn a_lapsed_request_cannot_be_denied() {
        let mut r = request();
        let _late = crate::shared::clock::freeze(r.expires_at() + Duration::seconds(1));

        let result = r.deny(&cleared(&approver_for(UserId::new())));

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert_eq!(r.state().status(), ApprovalStatus::Expired);
        assert!(r.decided_by().is_none());
    }

    /// A requester cannot approve their own request. The refusal leaves
    /// it pending without a decider.
    #[test]
    fn the_requester_cannot_approve_their_own_request() {
        let requester = UserId::new();
        let mut r = requested_by(requester);

        let result = r.approve(&cleared(&approver_for(requester)));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(r.is_pending());
        assert!(r.decided_by().is_none());
    }

    /// Ann opens a request and then changes her mind. She may deny her own
    /// request, because a denial only ever lets less through.
    #[test]
    fn the_requester_may_still_withdraw_their_request() {
        let requester = UserId::new();
        let mut r = requested_by(requester);

        r.deny(&cleared_for(
            &approver_for(requester),
            DataClassLevel::Restricted,
        ))
        .unwrap();

        assert!(!r.grants_action_at(crate::shared::clock::now(), &NONE));
    }

    /// Consuming an approved request spends its grant. It then grants
    /// nothing and refuses a second consumption.
    #[test]
    fn an_approval_lets_one_action_through_and_then_nothing() {
        let mut r = request();
        r.approve(&cleared(&approver_for(UserId::new()))).unwrap();

        r.consume(&NONE).unwrap();

        assert_eq!(r.status(), ApprovalStatus::Consumed);
        assert!(
            !r.grants_action_at(now(), &NONE),
            "a spent approval grants nothing"
        );
        assert!(matches!(
            r.consume(&NONE),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// An agent tries to use a request nobody has decided yet. It is refused,
    /// and the request stays pending for a person to decide.
    #[test]
    fn a_pending_approval_cannot_be_spent() {
        let mut r = request();

        assert!(matches!(
            r.consume(&NONE),
            Err(DomainError::InvalidTransition(_))
        ));
        assert!(r.is_pending());
    }

    /// A request is approved, but the agent tries to use it at the moment its
    /// time runs out. The use is refused and the approval stays unspent.
    #[test]
    fn an_approval_past_its_window_cannot_be_spent() {
        let mut r = request();
        r.approve(&cleared(&approver_for(UserId::new()))).unwrap();
        let _at_the_end = crate::shared::clock::freeze(r.expires_at());

        assert!(r.consume(&NONE).is_err());
        assert_eq!(r.status(), ApprovalStatus::Approved);
    }

    /// An approved request reaches its expiry time. From that instant on it
    /// lets the action through no more.
    #[test]
    fn approval_does_not_survive_its_window() {
        let mut r = request();
        r.approve(&cleared(&approver_for(UserId::new()))).unwrap();
        assert!(!r.grants_action_at(r.expires_at(), &NONE));
    }

    /// A person denies a request. The paused action may not run.
    #[test]
    fn denied_request_grants_nothing() {
        let mut r = request();
        r.deny(&cleared_for(
            &approver_for(UserId::new()),
            DataClassLevel::Restricted,
        ))
        .unwrap();
        assert!(!r.grants_action_at(crate::shared::clock::now(), &NONE));
    }

    /// Ann approves a request. A later denial or expiry is refused, so her
    /// decision stands as recorded.
    #[test]
    fn decisions_are_final() {
        let mut r = request();
        r.approve(&cleared(&approver_for(UserId::new()))).unwrap();
        assert!(matches!(
            r.deny(&cleared_for(
                &approver_for(UserId::new()),
                DataClassLevel::Restricted
            )),
            Err(DomainError::InvalidTransition(_))
        ));
        assert!(matches!(r.expire(), Err(DomainError::InvalidTransition(_))));
    }

    /// A run pauses on `delete_order({"id":1})` and raises a request. The
    /// request names the run, the delete class and that exact call, so the
    /// approver sees what they decide and the decision reaches that call.
    #[test]
    fn a_run_raised_request_carries_the_run_the_class_and_the_call() {
        let run = paused_run(Initiator::Human(approver_for(UserId::new())));
        let call = PendingCallRef::of(run.pending().unwrap());
        let request = raised_by(&run, ActionClass::Delete).unwrap();

        assert_eq!(request.run_id(), Some(run.id()));
        assert_eq!(
            request.action_class(),
            DeclaredAction::Declared(ActionClass::Delete)
        );
        assert_eq!(request.pending_call(), Some(&call));
        assert!(
            request.delegation_id() == &ActingUnder::NoDelegation,
            "a run calling tools directly exercises no delegation"
        );
    }

    /// A run's paused call is approved, so the run waits on nobody. No origin
    /// can be taken from it, so nobody opens a second approval for the same
    /// call.
    #[test]
    fn a_run_whose_call_is_approved_raises_no_origin() {
        let mut run = paused_run(Initiator::Agent(AgentId::new()));
        let call = PendingCallRef::of(run.pending().unwrap());

        run.approve_pending(&ReleasedCall::new(*run.id(), call))
            .unwrap();

        assert!(run.pending().is_some());
        assert!(RunOrigin::of(&run).is_none());
    }

    /// Ann opens a request by hand without saying its class, under Bob's
    /// delegation. It names no run and no held call, and it keeps the
    /// delegation it was opened under.
    #[test]
    fn a_hand_opened_request_has_no_run_or_class() {
        let delegation = DelegationId::new();
        let request = ApprovalRequest::<ResolvedTenant>::request(RequestApprovalParams {
            agent_id: AgentId::new(),
            delegation_id: ActingUnder::Delegation(delegation),
            action_class: DeclaredAction::Undeclared,
            action: ApprovalAction::new("transfer $5000 to vendor").unwrap(),
            origin: ApprovalOrigin::Opened(Initiator::Human(human("ann@corp.test"))),
            parties: ActionParties::from_stored(
                human("owen@corp.test"),
                vec![human("bob@corp.test")],
            ),
            ttl_seconds: Seconds::new(900),
        })
        .unwrap();

        assert!(request.run_id().is_none());
        assert!(request.action_class() == DeclaredAction::Undeclared);
        assert!(request.pending_call().is_none());
        assert_eq!(
            request.delegation_id(),
            &ActingUnder::Delegation(delegation)
        );
    }

    /// An agent opens a request by hand. Nobody checked its text, so it
    /// reads as restricted, and only an approver cleared for restricted data
    /// may decide it. A request a person opened reads as public.
    #[test]
    fn a_request_an_agent_wrote_counts_as_restricted() {
        let by_agent = ApprovalRequest::<ResolvedTenant>::request(RequestApprovalParams {
            agent_id: AgentId::new(),
            delegation_id: ActingUnder::NoDelegation,
            action_class: DeclaredAction::Declared(ActionClass::Write),
            action: ApprovalAction::new("rotate the signing key").unwrap(),
            origin: ApprovalOrigin::Opened(Initiator::Agent(AgentId::new())),
            parties: parties(),
            ttl_seconds: Seconds::new(900),
        })
        .unwrap();

        assert_eq!(by_agent.exposure(), DataClassLevel::Restricted);
        assert_eq!(request().exposure(), DataClassLevel::Public);
    }

    /// A request waits for a decision. It reports neither a decider nor a
    /// decision time, so nobody reads it as decided.
    #[test]
    fn a_pending_request_has_no_decision_recorded() {
        let r = request();
        assert!(r.decided_by().is_none());
        assert!(r.decided_at().is_none());
    }

    /// One request is approved and another denied. Each records its decision
    /// time, and that time matches its last change.
    #[test]
    fn approving_and_denying_both_date_the_decision() {
        let mut approved = request();
        approved
            .approve(&cleared(&approver_for(UserId::new())))
            .unwrap();
        assert_eq!(approved.decided_at(), Some(approved.updated_at()));

        let mut denied = request();
        denied
            .deny(&cleared_for(
                &approver_for(UserId::new()),
                DataClassLevel::Restricted,
            ))
            .unwrap();
        assert_eq!(denied.decided_at(), Some(denied.updated_at()));
    }

    /// A request expires through a late approval, and another through
    /// `expire`. Neither records a decision time or a decider, because nobody
    /// decided. `expires_at` dates the expiry.
    #[test]
    fn a_lapsed_request_dates_no_decision() {
        let mut r = request();
        let after_the_window = r.expires_at() + Duration::seconds(1);
        let late = crate::shared::clock::freeze(after_the_window);

        let _ = r.approve(&cleared(&approver_for(UserId::new())));
        drop(late);

        assert_eq!(r.status(), ApprovalStatus::Expired);
        assert!(r.decided_at().is_none());
        assert!(r.decided_by().is_none());

        let mut swept = request();
        swept.expire().unwrap();
        assert!(swept.decided_at().is_none());
    }

    /// An empty summary and one of 501 characters are both refused. An
    /// approver always has a short text to read.
    #[test]
    fn action_summary_is_validated() {
        assert!(ApprovalAction::new("").is_err());
        assert!(ApprovalAction::new("a".repeat(501)).is_err());
    }

    /// A summary "transfer $5000 to vendor" reads back unchanged. It is all
    /// an approver sees before deciding.
    #[test]
    fn the_action_summary_reads_back_as_written() {
        let action = ApprovalAction::new("transfer $5000 to vendor").unwrap();

        assert_eq!(action.as_str(), "transfer $5000 to vendor");
    }

    /// A request opened for one agent's payment reports that agent, its own
    /// id and the financial class. A wrong agent here would put the decision
    /// against another agent.
    #[test]
    fn a_request_names_itself_and_the_agent_it_is_about() {
        let agent = AgentId::new();
        let request: ApprovalRequest<ResolvedTenant> =
            ApprovalRequest::request(RequestApprovalParams {
                agent_id: agent,
                delegation_id: ActingUnder::NoDelegation,
                action_class: DeclaredAction::Declared(ActionClass::Financial),
                action: ApprovalAction::new("transfer $5000 to vendor").unwrap(),
                origin: ApprovalOrigin::Opened(Initiator::Human(approver_for(UserId::new()))),
                parties: parties(),
                ttl_seconds: Seconds::new(900),
            })
            .unwrap();

        assert_eq!(request.agent_id(), &agent);
        assert_eq!(Aggregate::id(&request), request.id());
        assert_eq!(
            request.action_class(),
            DeclaredAction::Declared(ActionClass::Financial)
        );
        assert_eq!(
            request.delegation_id(),
            &ActingUnder::NoDelegation,
            "a run calling tools directly exercises no delegation"
        );
    }

    /// Two requests start pending. Once one is approved and the other denied,
    /// neither reports pending, so neither can be decided twice.
    #[test]
    fn only_an_undecided_request_reports_itself_pending() {
        let mut approved = request();
        let mut denied = request();

        assert!(approved.is_pending());
        assert!(denied.is_pending());

        approved
            .approve(&cleared(&approver_for(UserId::new())))
            .unwrap();
        denied
            .deny(&cleared_for(
                &approver_for(UserId::new()),
                DataClassLevel::Restricted,
            ))
            .unwrap();

        assert!(!approved.is_pending());
        assert!(!denied.is_pending());
    }

    fn approver() -> UserId {
        UserId::new()
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// A request for a write needs one person and no fresh second factor. The
    /// first approval grants it.
    #[test]
    fn a_low_risk_action_needs_one_approver_and_no_step_up() {
        let mut request = request();

        assert_eq!(request.approvers_needed(), 1);
        assert!(!request.needs_presence());
        assert_eq!(
            request
                .approve(&cleared(&approver_for(approver())))
                .unwrap(),
            ApprovalStep::Granted
        );
    }

    /// A paused delete cannot be released after one approval. A second
    /// person's approval allows release and acceptance by the run, after
    /// which another release is refused.
    #[test]
    fn a_held_high_risk_call_resumes_only_on_a_granted_approval() {
        let mut run = paused_run(Initiator::Agent(AgentId::new()));
        let mut request = raised_by(&run, ActionClass::Delete).unwrap();

        request
            .approve(&cleared(&approver_for(UserId::new())))
            .unwrap();
        assert!(request.release(&NONE).is_err(), "one approval of two");

        request
            .approve(&cleared(&approver_for(UserId::new())))
            .unwrap();
        let released = request.release(&NONE).unwrap();
        run.approve_pending(&released).unwrap();

        assert!(request.release(&NONE).is_err(), "an approval is spent once");
    }

    /// A delete, payment, configure or admin request needs two people with a
    /// fresh second factor. After Ann approves it still waits. After Bob
    /// approves it is granted, with Bob as the decider.
    #[test]
    fn a_high_risk_action_waits_for_a_second_approver() {
        for class in [
            ActionClass::Delete,
            ActionClass::Financial,
            ActionClass::Configure,
            ActionClass::Admin,
        ] {
            assert_two_approvers(class);
        }
    }

    /// Proves that the first approval waits and the second grants this action class.
    fn assert_two_approvers(class: ActionClass) {
        let mut request = of_class(UserId::new(), DeclaredAction::Declared(class));
        let (first, second) = (approver(), approver());

        assert_eq!(request.approvers_needed(), 2, "{class:?}");
        assert!(request.needs_presence(), "{class:?}");
        assert_eq!(
            request.approve(&cleared(&approver_for(first))).unwrap(),
            ApprovalStep::AwaitingSecond
        );
        assert!(request.is_pending());
        assert!(!request.grants_action_at(now(), &NONE));
        assert_eq!(
            request.first_approval().map(|f| f.by.principal()),
            Some(PrincipalRef::User(first))
        );

        assert_eq!(
            request.approve(&cleared(&approver_for(second))).unwrap(),
            ApprovalStep::Granted
        );
        assert!(request.grants_action_at(now(), &NONE));
        assert_eq!(request.decided_by(), Some(PrincipalRef::User(second)));
        assert_eq!(
            request.granting_approval().map(|g| g.by.principal()),
            Some(PrincipalRef::User(second))
        );
    }

    /// The first approver cannot also give the second approval of a delete;
    /// the repeated approval is forbidden and the request remains pending.
    #[test]
    fn the_same_person_cannot_approve_twice() {
        let mut request = of_class(UserId::new(), DeclaredAction::Declared(ActionClass::Delete));
        let person = approver();
        request.approve(&cleared(&approver_for(person))).unwrap();

        let again = request.approve(&cleared(&approver_for(person)));

        assert!(matches!(again, Err(DomainError::Forbidden(_))));
        assert!(request.is_pending());
    }

    /// A request opened without a class needs two approvers with a fresh
    /// second factor. One that cannot say what it is for gets the strictest
    /// rule.
    #[test]
    fn an_unknown_class_is_treated_as_high_risk() {
        let request = of_class(UserId::new(), DeclaredAction::Undeclared);

        assert_eq!(request.approvers_needed(), 2);
        assert!(request.needs_presence());
    }

    /// Ann gives the first approval of a payment, then Bob denies it. The
    /// request is denied and the payment may not run.
    #[test]
    fn one_denial_stops_a_half_approved_action() {
        let mut request = of_class(
            UserId::new(),
            DeclaredAction::Declared(ActionClass::Financial),
        );
        request
            .approve(&cleared(&approver_for(approver())))
            .unwrap();

        request
            .deny(&cleared_for(
                &approver_for(approver()),
                DataClassLevel::Restricted,
            ))
            .unwrap();

        assert_eq!(request.status(), ApprovalStatus::Denied);
        assert!(!request.grants_action_at(now(), &NONE));
    }

    /// A pending request has no time to decide. Once approved, it reports
    /// how long it waited, and never a negative span.
    #[test]
    fn the_time_to_decide_is_known_once_decided() {
        let mut request = request();
        assert!(request.time_to_decide().is_none());

        request
            .approve(&cleared(&approver_for(approver())))
            .unwrap();

        assert!(request.time_to_decide().is_some_and(|t| !t.is_negative()));
    }

    /// Action summaries containing a right-to-left override or a zero-width
    /// space are refused.
    #[test]
    fn an_action_summary_with_invisible_characters_is_refused() {
        assert!(ApprovalAction::new("read report\u{202E}gnp.exe").is_err());
        assert!(ApprovalAction::new("read\u{200B}report").is_err());
    }

    /// A payment's first approver cannot supply the second approval through
    /// an organization account with the same person identity.
    #[test]
    fn one_person_through_two_accounts_is_not_two_approvers() {
        let mut request = of_class(
            UserId::new(),
            DeclaredAction::Declared(ActionClass::Financial),
        );
        let through_tenant =
            Human::new(HumanAccount::User(UserId::new()), person("alice@corp.test"));
        let through_org = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            person("alice@corp.test"),
        );

        assert_eq!(
            request.approve(&cleared(&through_tenant)).unwrap(),
            ApprovalStep::AwaitingSecond
        );
        assert!(request.approve(&cleared(&through_org)).is_err());
    }

    /// A requester cannot approve through an organization account whose
    /// address uses a plus alias of the requester's address.
    #[test]
    fn the_requester_cannot_approve_through_another_account() {
        let mut request = ApprovalRequest::<ResolvedTenant>::request(RequestApprovalParams {
            agent_id: AgentId::new(),
            delegation_id: ActingUnder::NoDelegation,
            action_class: DeclaredAction::Declared(ActionClass::Write),
            action: ApprovalAction::new("rotate the signing key").unwrap(),
            origin: ApprovalOrigin::Opened(Initiator::Human(Human::new(
                HumanAccount::User(UserId::new()),
                person("bob@corp.test"),
            ))),
            parties: parties(),
            ttl_seconds: Seconds::new(900),
        })
        .unwrap();
        let bob_through_org = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            person("bob+org@corp.test"),
        );

        assert!(request.approve(&cleared(&bob_through_org)).is_err());
    }

    /// An agent opens a request for a write. No person put the action there,
    /// so anyone allowed to approve, other than the agent's owner, may
    /// approve it, and one approval grants it.
    #[test]
    fn a_request_an_agent_opened_may_be_approved_by_another_person() {
        let mut request = ApprovalRequest::<ResolvedTenant>::request(RequestApprovalParams {
            agent_id: AgentId::new(),
            delegation_id: ActingUnder::NoDelegation,
            action_class: DeclaredAction::Declared(ActionClass::Write),
            action: ApprovalAction::new("rotate the signing key").unwrap(),
            origin: ApprovalOrigin::Opened(Initiator::Agent(AgentId::new())),
            parties: parties(),
            ttl_seconds: Seconds::new(900),
        })
        .unwrap();

        assert_eq!(
            request
                .approve(&cleared(&approver_for(UserId::new())))
                .unwrap(),
            ApprovalStep::Granted
        );
    }

    /// The person who started a run cannot approve its paused delete through
    /// another account. The refusal records no first approval.
    #[test]
    fn the_person_a_run_acts_for_gives_neither_approval() {
        let alice = Human::new(HumanAccount::User(UserId::new()), person("alice@corp.test"));
        let alice_through_org = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            person("alice@corp.test"),
        );
        let run = paused_run(Initiator::Human(alice));
        let mut request = raised_by(&run, ActionClass::Delete).unwrap();

        assert!(request.approve(&cleared(&alice_through_org)).is_err());
        assert!(request.first_approval().is_none());
    }

    /// A request for a paused delete cannot declare itself a read. Using
    /// the matching delete class succeeds and requires two approvers.
    #[test]
    fn a_run_raised_request_takes_the_class_of_the_paused_tool() {
        let run = paused_run(Initiator::Agent(AgentId::new()));

        let result = raised_by(&run, ActionClass::Read);

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert_eq!(
            raised_by(&run, ActionClass::Delete)
                .unwrap()
                .approvers_needed(),
            2
        );
    }

    /// A run's request is opened naming a different agent than the run's.
    /// It is refused, so the decision never lands on the wrong agent.
    #[test]
    fn a_run_raised_request_names_the_runs_agent() {
        let run = paused_run(Initiator::Agent(AgentId::new()));

        let result = ApprovalRequest::<ResolvedTenant>::request(RequestApprovalParams {
            agent_id: AgentId::new(),
            delegation_id: ActingUnder::NoDelegation,
            origin: ApprovalOrigin::Run(RunOrigin::of(&run).unwrap()),
            parties: parties(),
            action_class: DeclaredAction::Declared(ActionClass::Delete),
            action: ApprovalAction::new("delete").unwrap(),
            ttl_seconds: Seconds::new(900),
        });

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An account cannot give both approvals of a payment under different
    /// addresses. The second attempt fails and the action remains ungranted.
    #[test]
    fn one_account_cannot_give_both_approvals_under_two_addresses() {
        let mut request = of_class(
            UserId::new(),
            DeclaredAction::Declared(ActionClass::Financial),
        );
        let account = HumanAccount::User(UserId::new());
        let before = Human::new(account, person("old@corp.test"));
        let after = Human::new(account, person("new@corp.test"));

        assert_eq!(
            request.approve(&cleared(&before)).unwrap(),
            ApprovalStep::AwaitingSecond
        );
        assert!(request.approve(&cleared(&after)).is_err());
        assert!(!request.grants_action_at(now(), &NONE));
    }

    /// A stored grant by `human` at `at`.
    fn granted_by(human: &Human, at: OffsetDateTime) -> StoredDecision {
        StoredDecision::Decided {
            by: human.clone(),
            at,
        }
    }

    /// A stored row says approved with no approver, or pending or expired
    /// with a decision. Each is refused as a storage fault. The first would
    /// let through an action nobody approved.
    #[test]
    fn a_stored_status_and_decision_must_agree() {
        let at = crate::shared::clock::now();
        let decided = || granted_by(&approver_for(UserId::new()), at);

        assert!(ApprovalState::from_stored(ApprovalStatus::Approved, None, decided()).is_ok());
        for (status, decision) in [
            (ApprovalStatus::Approved, StoredDecision::Undecided),
            (ApprovalStatus::Denied, StoredDecision::Undecided),
            (ApprovalStatus::Pending, decided()),
            (ApprovalStatus::Expired, decided()),
        ] {
            let read = ApprovalState::from_stored(status, None, decision);
            assert!(
                matches!(read, Err(DomainError::Infrastructure(_))),
                "{status:?}"
            );
        }
    }

    /// Bob, who did not ask, denies Ann's request. It is denied, and the
    /// decision names Bob's account.
    #[test]
    fn a_person_denies_a_request() {
        let bob = UserId::new();
        let mut request = requested_by(UserId::new());

        request
            .deny(&cleared_for(&approver_for(bob), DataClassLevel::Restricted))
            .unwrap();

        assert_eq!(request.status(), ApprovalStatus::Denied);
        assert_eq!(request.decided_by(), Some(PrincipalRef::User(bob)));
    }

    /// Bob denies Ann's request. The denial keeps Bob as a person, with
    /// the account he used, so a stored denial reads back naming him and
    /// not only his account.
    #[test]
    fn a_denial_keeps_the_person_who_made_it() {
        let bob = approver_for(UserId::new());
        let mut request = requested_by(UserId::new());

        request
            .deny(&cleared_for(&bob, DataClassLevel::Restricted))
            .unwrap();

        let decision = request.state().decision().unwrap();
        assert_eq!(decision.decider(), &bob);
    }

    fn stored(request: &ApprovalRequest<ResolvedTenant>, who: UserId) -> ApprovalRequestRow {
        ApprovalRequestRow {
            id: request.id,
            agent_id: request.agent_id,
            delegation_id: request.delegation_id,
            origin: StoredApprovalOrigin::Opened(Initiator::Human(approver_for(who))),
            parties: request.parties.clone(),
            action_class: request.action_class,
            action: request.action.clone(),
            state: request.state.clone(),
            created_at: request.created_at,
            expires_at: request.expires_at,
            updated_at: request.updated_at,
        }
    }

    /// A pending request saved as it was opened is read back without error.
    #[test]
    fn a_stored_request_reads_back() {
        let who = UserId::new();

        assert!(
            ApprovalRequest::<ResolvedTenant>::reconstitute(stored(&requested_by(who), who))
                .is_ok()
        );
    }

    /// A manually opened request stored as withdrawn is refused as corrupt,
    /// because withdrawal requires a request originating from a run.
    #[test]
    fn a_stored_hand_opened_request_marked_withdrawn_is_refused() {
        let who = UserId::new();
        let mut row = stored(&requested_by(who), who);
        row.state = ApprovalState::from_stored(
            ApprovalStatus::Withdrawn,
            None,
            granted_by(&approver_for(approver()), row.created_at),
        )
        .unwrap();

        assert!(refused_as_corrupt(
            &ApprovalRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored grant has its first approval and its decision from the same
    /// account. It is refused as corrupt, since one person approved twice.
    #[test]
    fn a_stored_grant_of_two_approvals_from_one_account_is_refused() {
        let who = UserId::new();
        let mut row = stored(&requested_by(who), who);
        let approver = approver_for(approver());
        row.state = ApprovalState::from_stored(
            ApprovalStatus::Approved,
            Some(Approval {
                by: approver.clone(),
                at: row.created_at,
            }),
            granted_by(&approver, row.created_at),
        )
        .unwrap();

        assert!(refused_as_corrupt(
            &ApprovalRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored delete approval naming the same person through tenant and
    /// organization accounts as its two approvers is refused as corrupt.
    #[test]
    fn a_stored_grant_of_two_approvals_from_one_person_is_refused() {
        let who = UserId::new();
        let request = of_class(who, DeclaredAction::Declared(ActionClass::Delete));
        let mut row = stored(&request, who);
        let through_tenant =
            Human::new(HumanAccount::User(UserId::new()), person("alice@corp.test"));
        let through_org = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            person("alice@corp.test"),
        );
        row.state = ApprovalState::from_stored(
            ApprovalStatus::Approved,
            Some(Approval {
                by: through_tenant,
                at: row.created_at,
            }),
            granted_by(&through_org, row.created_at),
        )
        .unwrap();

        assert!(refused_as_corrupt(
            &ApprovalRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored write request approved by its own requester is refused as
    /// corrupt during reconstitution.
    #[test]
    fn a_stored_grant_by_its_requester_is_refused() {
        let ann = UserId::new();
        let mut row = stored(&requested_by(ann), ann);
        row.state = ApprovalState::from_stored(
            ApprovalStatus::Approved,
            None,
            granted_by(&approver_for(ann), row.created_at),
        )
        .unwrap();

        assert!(refused_as_corrupt(
            &ApprovalRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored run request is refused as corrupt when its first approver
    /// is the run's starter through another account, even with a different
    /// person giving the second approval.
    #[test]
    fn a_stored_first_approval_by_the_runs_starter_is_refused() {
        let alice = Human::new(HumanAccount::User(UserId::new()), person("alice@corp.test"));
        let alice_through_org = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            person("alice@corp.test"),
        );
        let bob = approver_for(UserId::new());
        let run = paused_run(Initiator::Human(alice.clone()));
        let request = raised_by(&run, ActionClass::Delete).unwrap();
        let mut row = stored(&request, UserId::new());
        row.origin = StoredApprovalOrigin::Run(StoredRunOrigin {
            run_id: *run.id(),
            agent_id: *run.agent_id(),
            started_by: Initiator::Human(alice),
            pending_call: request.pending_call().unwrap().clone(),
            exposure: run.exposure(),
            chain: EventOrigin::Outside,
        });
        row.state = ApprovalState::from_stored(
            ApprovalStatus::Approved,
            Some(Approval {
                by: alice_through_org,
                at: row.created_at,
            }),
            granted_by(&bob, row.created_at),
        )
        .unwrap();

        assert!(refused_as_corrupt(
            &ApprovalRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A delete raised by Alice's run, approved first by Carol and then by
    /// Bob, is stored and read back without error.
    #[test]
    fn a_stored_grant_by_two_other_people_reads_back() {
        let alice = Human::new(HumanAccount::User(UserId::new()), person("alice@corp.test"));
        let run = paused_run(Initiator::Human(alice));
        let mut request = raised_by(&run, ActionClass::Delete).unwrap();
        request
            .approve(&cleared(&approver_for(approver())))
            .unwrap();
        request
            .approve(&cleared(&approver_for(approver())))
            .unwrap();
        let mut row = stored(&request, UserId::new());
        row.origin = StoredApprovalOrigin::Run(StoredRunOrigin {
            run_id: *run.id(),
            agent_id: *run.agent_id(),
            started_by: run.started_by().clone(),
            pending_call: request.pending_call().unwrap().clone(),
            exposure: run.exposure(),
            chain: EventOrigin::Outside,
        });

        assert!(ApprovalRequest::<ResolvedTenant>::reconstitute(row).is_ok());
    }

    /// A stored write request approved by the agent's owner is refused as
    /// corrupt during reconstitution.
    #[test]
    fn a_stored_grant_by_the_agents_owner_is_refused() {
        let who = UserId::new();
        let mut row = stored(&requested_by(who), who);
        row.state = ApprovalState::from_stored(
            ApprovalStatus::Approved,
            None,
            granted_by(row.parties.owner(), row.created_at),
        )
        .unwrap();

        assert!(refused_as_corrupt(
            &ApprovalRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored request under a delegation names nobody behind it. Read
    /// back, the delegator could approve their own delegation's action, so
    /// the row is refused as corrupt.
    #[test]
    fn a_stored_request_naming_no_delegator_for_its_delegation_is_refused() {
        let who = UserId::new();
        let mut row = stored(&requested_by(who), who);
        row.delegation_id = ActingUnder::Delegation(DelegationId::new());

        assert!(refused_as_corrupt(
            &ApprovalRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored delete request marked approved with only one approver is
    /// refused as corrupt during reconstitution.
    #[test]
    fn a_stored_high_risk_grant_with_one_approval_is_refused() {
        let who = UserId::new();
        let request = of_class(who, DeclaredAction::Declared(ActionClass::Delete));
        let mut row = stored(&request, who);
        row.state = ApprovalState::from_stored(
            ApprovalStatus::Approved,
            None,
            granted_by(&approver_for(approver()), row.created_at),
        )
        .unwrap();

        assert!(refused_as_corrupt(
            &ApprovalRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored request was denied one second before it was raised. The row
    /// is refused as corrupt.
    #[test]
    fn a_stored_request_decided_before_it_was_raised_is_refused() {
        let who = UserId::new();
        let mut row = stored(&requested_by(who), who);
        row.state = ApprovalState::from_stored(
            ApprovalStatus::Denied,
            None,
            granted_by(&approver_for(approver()), row.created_at - Duration::SECOND),
        )
        .unwrap();

        assert!(refused_as_corrupt(
            &ApprovalRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A request Sam opened by hand for Owen's agent, under the delegation
    /// Ann gave it, with that delegation.
    fn under_delegation() -> (ApprovalRequest<ResolvedTenant>, Delegation<ResolvedTenant>) {
        let ann = human("ann@corp.test");
        let agent = AgentIdentity::create(
            &AgentControl::new(assumed_authority(
                &human("owen@corp.test"),
                TenantId::new(),
                CREATES,
                &[],
            )),
            CreateAgentParams {
                name: Label::new("name", "tidier").unwrap(),
                description: None,
            },
        )
        .unwrap();
        let (delegation, _) = delegated_by(Initiator::Human(ann.clone()), &agent);
        let request = ApprovalRequest::request(RequestApprovalParams {
            agent_id: *agent.id(),
            delegation_id: ActingUnder::Delegation(*delegation.id()),
            origin: ApprovalOrigin::Opened(Initiator::Human(human("sam@corp.test"))),
            parties: ActionParties::from_stored(agent.owner().clone(), vec![ann]),
            action_class: DeclaredAction::Declared(ActionClass::Write),
            action: ApprovalAction::new("transfer $5000 to vendor").unwrap(),
            ttl_seconds: Seconds::new(900),
        })
        .unwrap();
        (request, delegation)
    }

    /// The label of the entity a payload field points at.
    fn label_in(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(crate::shared::events::data::FieldValue::Reference(reference)) => {
                reference.label().to_owned()
            }
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    /// Sam opens a request under a delegation that has no name. Announcing
    /// it raises "approval requested", naming the delegation by its id and
    /// the request by the action it waits on.
    #[test]
    fn announcing_a_request_names_its_delegation_and_its_action() {
        let (mut request, delegation) = under_delegation();

        request.announce_request(&delegation).unwrap();

        let events = raised(&mut request);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.approval_requested"
        );
        assert_eq!(
            label_in(&events[0], "delegation"),
            delegation.id().to_string()
        );
        assert_eq!(label_in(&events[0], "approval"), "transfer $5000 to vendor");
    }

    /// Announcing a request with another delegation is refused without
    /// raising any events.
    #[test]
    fn a_request_announced_under_another_delegation_is_refused() {
        let (mut request, _) = under_delegation();
        let (_, other) = under_delegation();

        let result = request.announce_request(&other);

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(raised(&mut request).is_empty());
    }

    /// Bob approves a write a minute after it was asked for. Announcing the
    /// decision raises "approval granted", with the minute it waited.
    #[test]
    fn announcing_a_grant_raises_approval_granted_with_the_wait() {
        let mut request = request();
        let frozen = crate::shared::clock::freeze(request.created_at + Duration::MINUTE);
        request.approve(&cleared(&human("bob@corp.test"))).unwrap();

        request.announce_decision(EventLabel::of("tidier"));

        let events = raised(&mut request);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.approval_granted"
        );
        assert_eq!(
            events[0].payload().value("seconds_to_decide"),
            Some(&crate::shared::events::data::FieldValue::Text(
                "60".to_owned()
            ))
        );
        drop(frozen);
    }

    /// Bob gives the first of the two approvals a payment needs. Announcing
    /// it raises "approval signed"; the payment still waits for a second
    /// person.
    #[test]
    fn announcing_a_first_of_two_raises_approval_signed() {
        let mut request = of_class(
            UserId::new(),
            DeclaredAction::Declared(ActionClass::Financial),
        );
        request.approve(&cleared(&human("bob@corp.test"))).unwrap();

        request.announce_decision(EventLabel::of("tidier"));

        assert_eq!(raised_names(&mut request), ["agents.approval_signed"]);
    }

    /// Bob refuses a request, and Owen stops the run behind another. Each
    /// announcement records how it was settled: a denial and a withdrawal.
    #[test]
    fn a_refusal_and_a_withdrawal_each_raise_their_own_record() {
        let mut denied = request();
        denied.deny(&cleared(&human("bob@corp.test"))).unwrap();
        let (mut run, agent) = paused_with_agent(
            Initiator::Agent(AgentId::new()),
            EventOrigin::Outside,
            DataClassLevel::Public,
        );
        let mut withdrawn = raised_by(&run, ActionClass::Delete).unwrap();
        withdrawn
            .withdraw(&stopped_by_owner(&mut run, &agent))
            .unwrap();

        denied.announce_decision(EventLabel::of("tidier"));
        withdrawn.announce_decision(EventLabel::of("tidier"));

        assert_eq!(raised_names(&mut denied), ["agents.approval_denied"]);
        assert_eq!(raised_names(&mut withdrawn), ["agents.approval_withdrawn"]);
    }

    /// A requester's self-approval is refused. Announcing the still
    /// undecided request then raises no decision event.
    #[test]
    fn an_undecided_request_announces_no_decision() {
        let who = UserId::new();
        let mut request = requested_by(who);
        let refused = request.approve(&cleared(&approver_for(who)));

        request.announce_decision(EventLabel::of("tidier"));

        assert!(refused.is_err());
        assert!(raised(&mut request).is_empty());
    }

    /// A request whose denial was announced is saved and read back. The copy
    /// read from storage has raised nothing.
    #[test]
    fn a_request_read_back_from_storage_has_raised_nothing() {
        let who = UserId::new();
        let mut request = requested_by(who);
        request.deny(&cleared(&human("bob@corp.test"))).unwrap();
        request.announce_decision(EventLabel::of("tidier"));

        let mut read_back =
            ApprovalRequest::<ResolvedTenant>::reconstitute(stored(&request, who)).unwrap();

        assert!(raised(&mut read_back).is_empty());
    }
}
