//! An agent run: one pass of an agent asking its model for steps until it
//! answers or stops.
//!
//! The run asks a model to work toward a `goal`. The model is not trusted. It
//! may only call tools whose action lies inside the run's declared `purpose`.
//! Each step is recorded as a [`RunStep`] that is never changed. A step is an
//! allowed tool call and its result, a denied one and why, or the final
//! answer. So anyone can later see exactly what a run did.
//!
//! A run starts only for an agent that may act. A run that calls tools does
//! so under a live delegation to that agent, with a purpose inside the
//! delegation's intent, and takes the delegation's approval rule with it. A
//! run under no delegation is given no tool. Its calls stop once its agent
//! may no longer act.
//!
//! A run also carries its exposure: the most sensitive data class it has
//! read. It only rises. A run may call a tool, or ask a model, only if it is
//! cleared for that class. Once a run has read confidential data, no prompt
//! can make it send that data to a public tool or an outside model.
//!
//! A run counts the tokens its model calls use and what they cost. Under a
//! spend limit it stops once it spent the limit. A person may pause a run
//! between its steps and resume it later, and may change or answer the
//! call it holds for approval.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::ActionApproval;
use crate::domains::agents::authority::delegation::{ActingUnder, Delegation};
use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::agents::execution::run::gate::CallGate;
use crate::domains::agents::execution::tool::ToolName;
use crate::domains::agents::execution::usage::{ModelTokens, Spend};
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::events::chain::EventOrigin;
use crate::shared::events::raised::Raised;
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::restriction::Restriction;
use crate::types::{ActionClass, AgentId, AgentRunId, Initiator, ModelProviderId};
mod announce;
mod call;
mod cancel;
mod check;
mod gate;
mod goal;
mod params;
mod pause;
mod spend;
mod start;
mod starter;
mod status;
mod steering;
mod stepping;
mod stored;
mod target;

pub use announce::RunNames;
pub use call::*;
pub use cancel::{CancelOrder, CancelOrderRow, RunCancelled};
pub use check::{CheckTries, CheckVerdict, DueCheck, MAX_CHECK_TRIES, RunCheck};
pub use gate::{Admission, CallRefusal};
pub use goal::*;
pub use params::*;
pub use spend::SpendCheck;
pub use starter::RunStarter;
pub use status::*;
pub use target::ResolvedCall;

/// One run of an agent toward a goal, with every step it took.
#[derive(Debug, Clone)]
pub struct AgentRun<T: TenantScope> {
    id: AgentRunId,
    agent_id: AgentId,
    provider_id: ModelProviderId,
    goal: RunGoal,
    purpose: IntentEnvelope,
    granted_tools: Vec<ToolName>,
    approval_classes: Vec<ActionClass>,
    approval: ActionApproval,
    delegation_id: ActingUnder,
    max_steps: u32,
    spend_limit: Restriction<Spend>,
    spend_check: SpendCheck,
    usage: ModelTokens,
    spent: Spend,
    started_by: Initiator,
    exposure: DataClassLevel,
    origin: EventOrigin,
    steps: Vec<RunStep>,
    state: RunState,
    check: RunCheck,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AgentRun<T> {
    /// `starter` starts `agent` on a run under `delegation`. It is running,
    /// has no steps, and asks the model first.
    ///
    /// The run acts for the agent the delegation was granted to, and records
    /// `starter` as who started it. When the delegation asks for approval on
    /// every action, every call the run makes waits for a person.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] for a delegation to another agent or by
    /// another starter, an expired or revoked delegation, an agent suspended, revoked
    /// or needing re-attestation, or a purpose beyond the delegated intent.
    /// Returns [`DomainError::Validation`] for a zero approval threshold or one
    /// at or above the spend limit.
    pub fn start(
        starter: RunStarter<'_>,
        params: StartRunParams,
        delegation: &Delegation<T>,
        agent: &AgentIdentity<T>,
    ) -> Result<Self, DomainError> {
        let now = clock::now();
        start::ensure_step_limit(params.max_steps)?;
        start::ensure_spend_check_below_limit(&params)?;
        start::ensure_startable(&starter, &params, delegation, agent, now)?;
        let under = Authority {
            delegation: ActingUnder::Delegation(*delegation.id()),
            approval: delegation.constraints().approval(),
            started_by: starter.initiator(),
        };
        Ok(Self::begin(params, agent, under, now))
    }

    /// `starter` starts `agent` on a run that acts under no delegation and
    /// so may call no tool, such as a workflow step that only writes text.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the agent is suspended, revoked or
    ///   must re-attest.
    /// - [`DomainError::Validation`] when `params` gives the run a tool.
    /// - [`DomainError::Validation`] when the amount to ask a person at is
    ///   nothing, or not below the spend limit.
    pub fn start_without_tools(
        starter: RunStarter<'_>,
        params: StartRunParams,
        agent: &AgentIdentity<T>,
    ) -> Result<Self, DomainError> {
        let now = clock::now();
        start::ensure_toolless(&params, agent, now)?;
        let under = Authority {
            delegation: ActingUnder::NoDelegation,
            approval: ActionApproval::NotRequired,
            started_by: starter.initiator(),
        };
        Ok(Self::begin(params, agent, under, now))
    }

    /// A new running run of `agent` at `now`, with no steps.
    fn begin(
        params: StartRunParams,
        agent: &AgentIdentity<T>,
        under: Authority,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            id: AgentRunId::new(),
            agent_id: *agent.id(),
            provider_id: params.provider_id,
            goal: params.goal,
            purpose: params.purpose,
            granted_tools: params.granted_tools,
            approval_classes: params.approval_classes,
            approval: under.approval,
            delegation_id: under.delegation,
            max_steps: params.max_steps,
            spend_limit: params.spend_limit,
            spend_check: SpendCheck::starting_at(params.ask_past),
            usage: ModelTokens::default(),
            spent: Spend::default(),
            started_by: under.started_by,
            exposure: params.exposure,
            origin: params.origin,
            steps: Vec::new(),
            state: RunState::Running(NextCall::Model),
            check: RunCheck::Unchecked,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds a run from storage.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] for steps not numbered from one, excess
    /// tool calls, exposure below a step's reads, or a held call at the wrong next step.
    /// Step times must be ordered within the run's lifetime, as must held-call approval.
    /// A run over budget must end; its approval threshold must be below the cap, and
    /// reaching it must end or owe approval. Changes cannot precede the run's start.
    pub fn reconstitute(row: AgentRunRow) -> Result<Self, DomainError> {
        stored::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            agent_id: row.agent_id,
            provider_id: row.provider_id,
            goal: row.goal,
            purpose: row.purpose,
            granted_tools: row.granted_tools,
            approval_classes: row.approval_classes,
            approval: row.approval,
            delegation_id: row.delegation_id,
            max_steps: row.max_steps,
            spend_limit: row.spend_limit,
            spend_check: row.spend_check,
            usage: row.usage,
            spent: row.spent,
            started_by: row.started_by,
            exposure: row.exposure,
            origin: row.origin,
            steps: row.steps,
            state: row.state,
            check: row.check,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Decides whether the run may call the tool and needs approval first.
    /// Both the tool's class and target path's class must fit the run's purpose.
    ///
    /// # Errors
    /// [`CallRefusal::NoAuthority`] without a delegation; [`CallRefusal::NotGranted`]
    /// for a tool outside its grant; [`CallRefusal::OutsidePurpose`] for either class;
    /// [`CallRefusal::WouldLeak`] if tool clearance is below data the run has read.
    pub fn admit(&self, call: &ResolvedCall<'_, T>) -> Result<Admission, CallRefusal> {
        self.gate().admit(call)
    }

    fn gate(&self) -> CallGate<'_> {
        CallGate {
            delegation: &self.delegation_id,
            granted_tools: &self.granted_tools,
            purpose: &self.purpose,
            exposure: self.exposure,
            approval_classes: &self.approval_classes,
            approval: self.approval,
        }
    }

    /// Whether what the run has read may be sent to a tool or a model
    /// cleared for `clearance`.
    ///
    /// Any call can carry data out. It can do so in its arguments, its path,
    /// or by which tool it picks. So this applies to every call, reads
    /// included.
    #[must_use]
    pub fn may_send_to(&self, clearance: DataClassLevel) -> bool {
        clearance >= self.exposure
    }

    /// The most sensitive data class the run has read. Never falls.
    #[must_use]
    pub fn exposure(&self) -> DataClassLevel {
        self.exposure
    }

    /// Where the run came from: outside any workflow, or a workflow
    /// execution at its depth.
    #[must_use]
    pub fn origin(&self) -> EventOrigin {
        self.origin
    }

    /// Who started the run.
    #[must_use]
    pub fn started_by(&self) -> &Initiator {
        &self.started_by
    }

    /// Whether a tool of `class` needs a person's approval before it runs.
    ///
    /// Every class does under a delegation that asks for approval on every
    /// action. A high-risk class always does, whatever the person starting
    /// the run chose. Any other class does when they listed it.
    #[must_use]
    pub fn requires_approval(&self, class: ActionClass) -> bool {
        self.gate().admission_for(class) == Admission::NeedsApproval
    }

    /// Whether the run was started with the tool `name`. A run started with
    /// no tools may call none.
    #[must_use]
    pub fn grants_tool(&self, name: &ToolName) -> bool {
        self.granted_tools.contains(name)
    }

    /// The approved call the run makes next.
    ///
    /// The run holds it until [`Self::record_allowed`] or
    /// [`Self::record_denied`] records it. So the approval stays with the
    /// call until its step is written.
    #[must_use]
    pub fn approved_call(&self) -> Option<&ToolCall> {
        let RunState::Running(NextCall::Approved(held)) = &self.state else {
            return None;
        };
        Some(held.call())
    }

    /// The tool call the run holds. The run is either paused on it, or it is
    /// approved and waiting to run.
    #[must_use]
    pub fn pending(&self) -> Option<&PendingCall> {
        self.state.pending()
    }

    /// Where the run stands, with the call it holds when it holds one.
    #[must_use]
    pub fn state(&self) -> &RunState {
        &self.state
    }

    /// The action classes the starter listed as needing approval. High-risk
    /// classes need it too, listed or not.
    #[must_use]
    pub fn approval_classes(&self) -> &[ActionClass] {
        &self.approval_classes
    }

    /// Whether every tool call waits for a person, as the delegation asked
    /// when the run started.
    #[must_use]
    pub fn approval(&self) -> ActionApproval {
        self.approval
    }

    /// Whether the run may take another step: it is running and under its
    /// step limit, or holds an answer waiting for its check, which runs
    /// even on the last step.
    #[must_use]
    pub fn can_step(&self) -> bool {
        self.status() == RunStatus::Running
            && (self.steps_taken() < self.max_steps || self.due_check().is_some())
    }

    /// How many steps the run has taken. Any count past `u32::MAX` is
    /// `u32::MAX`.
    fn steps_taken(&self) -> u32 {
        u32::try_from(self.steps.len()).unwrap_or(u32::MAX)
    }

    /// The number the next step takes.
    fn next_step(&self) -> u32 {
        self.steps_taken().saturating_add(1)
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &AgentRunId {
        &self.id
    }

    /// The acting agent.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// The model provider.
    #[must_use]
    pub fn provider_id(&self) -> &ModelProviderId {
        &self.provider_id
    }

    /// The instructions the model follows during this execution.
    #[must_use]
    pub fn goal(&self) -> &RunGoal {
        &self.goal
    }

    /// The action classes the run's tool calls may take.
    #[must_use]
    pub fn purpose(&self) -> &IntentEnvelope {
        &self.purpose
    }

    /// The tools the run was given. Empty means it may call none.
    #[must_use]
    pub fn granted_tools(&self) -> &[ToolName] {
        &self.granted_tools
    }

    /// The delegation the run acts under. Its tool calls go through the
    /// proxy under it. A run under none calls no tool.
    #[must_use]
    pub fn delegation_id(&self) -> &ActingUnder {
        &self.delegation_id
    }

    /// The most steps the run may take.
    #[must_use]
    pub fn max_steps(&self) -> u32 {
        self.max_steps
    }

    /// The recorded steps.
    #[must_use]
    pub fn steps(&self) -> &[RunStep] {
        &self.steps
    }

    /// Where the run stands, without the call it holds.
    #[must_use]
    pub fn status(&self) -> RunStatus {
        self.state.status()
    }

    /// The final answer its last step recorded, once the run completed.
    /// `None` while it runs, or when it ended any other way.
    #[must_use]
    pub fn answer(&self) -> Option<&str> {
        if self.status() != RunStatus::Completed {
            return None;
        }
        match self.steps.last()?.outcome() {
            StepOutcome::Answered(answer) => Some(answer),
            StepOutcome::Allowed(_)
            | StepOutcome::Denied(_)
            | StepOutcome::Replied(_)
            | StepOutcome::CheckFailed(_) => None,
        }
    }

    /// The most the run may spend on its model, or that it has no limit.
    #[must_use]
    pub fn spend_limit(&self) -> Restriction<Spend> {
        self.spend_limit
    }

    /// Where the run waits for a person before spending more.
    #[must_use]
    pub fn spend_check(&self) -> SpendCheck {
        self.spend_check
    }

    /// The tokens its model calls used so far.
    #[must_use]
    pub fn usage(&self) -> ModelTokens {
        self.usage
    }

    /// What its model calls cost so far.
    #[must_use]
    pub fn spent(&self) -> Spend {
        self.spent
    }

    fn touch(&mut self) {
        self.updated_at = clock::now();
    }
}

/// What a run acts under: its delegation, whether that delegation asks for
/// approval on every action, and who started it.
struct Authority {
    delegation: ActingUnder,
    approval: ActionApproval,
    started_by: Initiator,
}

impl<T: TenantScope> Aggregate for AgentRun<T> {
    type Id = AgentRunId;

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
pub(crate) mod tests {
    pub(crate) mod fixtures;

    use self::fixtures::{
        agent, ann, by_ann, call, calling, constraints, delegation, denied, params, released, run,
        started, tool,
    };
    use super::*;
    use crate::domains::agents::execution::tool::PathValues;
    use crate::domains::agents::identity::control::AgentControl;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::assumed_authority;
    use crate::types::TenantId;

    fn owner_of(agent: &AgentIdentity<ResolvedTenant>) -> AgentControl<'_> {
        nobody_special(agent.owner())
    }

    fn nobody_special(by: &crate::types::Human) -> AgentControl<'_> {
        AgentControl::new(assumed_authority(by, TenantId::new(), &[], &[]))
    }

    /// The agent's owner orders `r` stopped, and the order is applied.
    fn cancel_as_owner(
        r: &mut AgentRun<ResolvedTenant>,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> Option<RunCancelled> {
        let order = r.order_cancel(&owner_of(agent), agent).unwrap();
        r.cancel(&order).unwrap()
    }
    use crate::shared::model::row_check::refused_as_corrupt;

    /// A run reads an order, has a delete refused, then answers. It holds
    /// three steps numbered from 1 in that order and is completed.
    #[test]
    fn steps_are_appended_in_order_and_complete_finishes() {
        let (mut r, agent) = run(5);
        r.record_allowed(calling(&tool("get_order"), "{}"), &agent, "{\"id\":1}")
            .unwrap();
        r.record_denied(call("delete_order", "{}"), "outside declared purpose")
            .unwrap();
        r.complete("done").unwrap();

        assert_eq!(r.status(), RunStatus::Completed);
        assert_eq!(r.steps().len(), 3);
        assert_eq!(r.steps()[0].seq(), 1);
        assert_eq!(r.steps()[0].tool(), Some("get_order"));
        assert!(matches!(r.steps()[1].outcome(), StepOutcome::Denied(_)));
        assert!(matches!(r.steps()[2].outcome(), StepOutcome::Answered(_)));
    }

    /// A completed run is asked to record one more tool call. It is refused,
    /// and the run reports it cannot step.
    #[test]
    fn a_finished_run_rejects_further_steps() {
        let (mut r, agent) = run(5);
        r.complete("done").unwrap();
        assert!(
            r.record_allowed(calling(&tool("lookup"), "{}"), &agent, "y")
                .is_err()
        );
        assert!(!r.can_step());
    }

    /// A run allowed one step can step before it and cannot after one call.
    #[test]
    fn can_step_respects_the_cap() {
        let (mut r, agent) = run(1);
        assert!(r.can_step());
        r.record_allowed(calling(&tool("get_order"), "{}"), &agent, "ok")
            .unwrap();
        assert!(!r.can_step(), "one step used of a one-step cap");
    }

    /// A run allowed one step has used it. Another allowed call, a denied
    /// call and a pause for approval are all refused. The run may still
    /// record its final answer.
    #[test]
    fn a_run_at_its_cap_takes_no_further_call() {
        let (mut r, agent) = run(1);
        r.record_allowed(calling(&tool("get_order"), "{}"), &agent, "ok")
            .unwrap();

        assert!(
            r.record_allowed(calling(&tool("get_order"), "{}"), &agent, "ok")
                .is_err()
        );
        assert!(
            r.record_denied(call("delete_order", "{}"), "refused")
                .is_err()
        );
        assert!(
            r.await_approval(calling(&tool("delete_order"), "{}"), &agent)
                .is_err()
        );
        assert!(r.complete("done").is_ok(), "the run may still finish");
    }

    /// A run pauses on `delete_order`. It does not step and has no approved
    /// call. Once approved, it is running again with that exact call next.
    #[test]
    fn await_approval_pauses_and_approval_resumes_the_call() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();

        assert_eq!(r.status(), RunStatus::AwaitingApproval);
        assert!(!r.can_step(), "a paused run does not step");
        assert!(
            !r.status().is_terminal(),
            "awaiting approval is not terminal"
        );
        assert_eq!(r.pending().unwrap().tool(), "delete_order");
        assert!(r.approved_call().is_none(), "not yet approved");

        r.approve_pending(&released(&r, "delete_order", "{\"id\":1}"))
            .unwrap();
        assert_eq!(r.status(), RunStatus::Running);
        assert_eq!(r.approved_call(), Some(&call("delete_order", "{\"id\":1}")));
    }

    /// Approval of a denied read cannot release the delete held afterward;
    /// the run remains awaiting approval with no approved call.
    #[test]
    fn approving_a_call_that_has_since_changed_is_refused() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("read_order"), "{\"id\":1}"), &agent)
            .unwrap();
        let reviewed = PendingCallRef::of(r.pending().unwrap());

        r.deny_pending(&denied(&r, "read_order", "{\"id\":1}"), "not this one")
            .unwrap();
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();

        let result = r.approve_pending(&ReleasedCall::new(*r.id(), reviewed));

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(r.status(), RunStatus::AwaitingApproval);
        assert!(r.approved_call().is_none());
    }

    /// Approval for deleting all orders cannot release a held deletion of
    /// order 1 because the arguments differ.
    #[test]
    fn approving_the_same_tool_with_other_arguments_is_refused() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();

        let result = r.approve_pending(&released(&r, "delete_order", "{\"id\":\"all\"}"));

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// After an approved deletion is recorded, a second pause on the same
    /// call cannot reuse the first pause's approval and stays awaiting review.
    #[test]
    fn a_spare_approval_does_not_release_a_later_pause() {
        let (mut r, agent) = run(5);
        let delete = tool("delete_order");
        r.await_approval(calling(&delete, "{\"id\":1}"), &agent)
            .unwrap();
        let spare = PendingCallRef::of(r.pending().unwrap());
        r.approve_pending(&released(&r, "delete_order", "{\"id\":1}"))
            .unwrap();
        r.record_allowed(calling(&delete, "{\"id\":1}"), &agent, "deleted")
            .unwrap();
        r.await_approval(calling(&delete, "{\"id\":1}"), &agent)
            .unwrap();

        let result = r.approve_pending(&ReleasedCall::new(*r.id(), spare));

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(r.status(), RunStatus::AwaitingApproval);
    }

    /// A lapsed approval cannot record an allowed call or add a step. The
    /// run can still record the denial and release its held approval.
    #[test]
    fn an_approved_call_is_not_made_once_its_approval_lapsed() {
        let (mut r, agent) = run(5);
        let delete = tool("delete_order");
        r.await_approval(calling(&delete, "{\"id\":1}"), &agent)
            .unwrap();
        r.approve_pending(&released(&r, "delete_order", "{\"id\":1}"))
            .unwrap();
        let later = crate::shared::clock::freeze(
            r.updated_at() + APPROVED_CALL_WINDOW + time::Duration::SECOND,
        );

        let result = r.record_allowed(calling(&delete, "{\"id\":1}"), &agent, "deleted");

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(r.steps().is_empty());
        r.record_denied(call("delete_order", "{\"id\":1}"), "approval lapsed")
            .unwrap();
        assert!(r.approved_call().is_none());
        drop(later);
    }

    /// A paused call is approved at a fixed time. The run stamps the
    /// approval with its own clock, not a time the caller hands in.
    #[test]
    fn an_approval_is_stamped_with_the_run_clock() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();
        let at = r.updated_at() + time::Duration::seconds(30);
        let frozen = crate::shared::clock::freeze(at);

        r.approve_pending(&released(&r, "delete_order", "{\"id\":1}"))
            .unwrap();

        assert_eq!(r.pending().unwrap().approved_at(), Some(at));
        drop(frozen);
    }

    /// A completed run is then cancelled, failed and halted. It stays
    /// completed.
    #[test]
    fn a_terminal_run_keeps_how_it_ended() {
        let (mut r, agent) = run(5);
        r.complete("done").unwrap();

        let late = cancel_as_owner(&mut r, &agent);
        r.fail();
        r.halt();

        assert_eq!(
            r.status(),
            RunStatus::Completed,
            "a late cancel must not rewrite a finished run"
        );
        assert!(late.is_none(), "a run that completed was not cancelled");
    }

    /// A person denies a paused `delete_order`. The run is running again,
    /// holds no call, and has one denied step naming `delete_order`.
    #[test]
    fn deny_records_a_refusal_and_resumes() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{}"), &agent)
            .unwrap();
        r.deny_pending(
            &denied(&r, "delete_order", "{}"),
            "a human declined this action",
        )
        .unwrap();

        assert_eq!(r.status(), RunStatus::Running);
        assert!(r.pending().is_none());
        assert_eq!(r.steps().len(), 1);
        assert_eq!(r.steps()[0].tool(), Some("delete_order"));
        assert!(matches!(r.steps()[0].outcome(), StepOutcome::Denied(_)));
    }

    /// An approval naming another run cannot release this run's matching
    /// call; it remains awaiting approval.
    #[test]
    fn a_call_released_for_another_run_is_refused() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{}"), &agent)
            .unwrap();
        let elsewhere = ReleasedCall::new(
            AgentRunId::new(),
            PendingCallRef::new(call("delete_order", "{}"), 1),
        );

        let result = r.approve_pending(&elsewhere);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(r.status(), RunStatus::AwaitingApproval);
    }

    /// A running run that holds no call is approved and then denied. Both are
    /// refused.
    #[test]
    fn approve_and_deny_require_awaiting_approval() {
        let (mut r, _) = run(5);
        assert!(r.approve_pending(&released(&r, "x", "{}")).is_err());
        assert!(r.deny_pending(&denied(&r, "x", "{}"), "x").is_err());
    }

    /// A run started with `Delete` listed for approval needs approval for
    /// deletes but not for reads.
    #[test]
    fn requires_approval_reflects_the_configured_classes() {
        let (r, _) = started(StartRunParams {
            approval_classes: vec![ActionClass::Delete],
            ..params(5)
        });

        assert!(r.requires_approval(ActionClass::Delete));
        assert!(!r.requires_approval(ActionClass::Read));
    }

    /// An empty approval list still requires approval for delete, configure,
    /// financial and admin actions, while ordinary writes need none.
    #[test]
    fn high_risk_classes_always_need_approval() {
        let (r, _) = run(5);

        for class in [
            ActionClass::Delete,
            ActionClass::Configure,
            ActionClass::Financial,
            ActionClass::Admin,
        ] {
            assert!(r.requires_approval(class), "{class:?}");
        }
        assert!(!r.requires_approval(ActionClass::Write));
    }

    /// A run started with an empty tool list asks about `get_order`. It is
    /// not granted, since an empty list means no tools, not every tool.
    #[test]
    fn a_run_naming_no_tools_may_call_none() {
        let (r, _) = started(StartRunParams {
            granted_tools: Vec::new(),
            ..params(5)
        });

        assert!(!r.grants_tool(&ToolName::new("get_order").unwrap()));
        assert_eq!(
            r.admit(&calling(&tool("get_order"), "{}")),
            Err(CallRefusal::NotGranted)
        );
    }

    /// A run reads back the agent, model, goal, purpose, tools, approval
    /// classes, delegation, step limit and starter it was started with. A
    /// wrong value would run the work for somebody else.
    #[test]
    fn a_started_run_reports_back_everything_it_was_started_with() {
        let agent = agent();
        let delegation = delegation(&agent, constraints());
        let start = StartRunParams {
            purpose: IntentEnvelope::new([ActionClass::Read]),
            granted_tools: vec![ToolName::new("get_order").unwrap()],
            approval_classes: vec![ActionClass::Delete],
            max_steps: 7,
            ..params(5)
        };
        let provider = start.provider_id;

        let r = AgentRun::start(by_ann(), start, &delegation, &agent).unwrap();

        assert_eq!(r.agent_id(), agent.id());
        assert_eq!(r.provider_id(), &provider);
        assert_eq!(r.goal().as_str(), "reconcile the orders ledger");
        assert!(r.purpose().permits(ActionClass::Read));
        assert!(!r.purpose().permits(ActionClass::Delete));
        assert_eq!(r.granted_tools(), [ToolName::new("get_order").unwrap()]);
        assert_eq!(r.approval_classes(), [ActionClass::Delete]);
        assert_eq!(
            r.delegation_id(),
            &ActingUnder::Delegation(*delegation.id())
        );
        assert_eq!(r.max_steps(), 7);
        assert_eq!(r.started_by(), &Initiator::Human(ann()));
        assert_eq!(r.approval(), ActionApproval::NotRequired);
        assert_eq!(*Aggregate::id(&r), *r.id());
    }

    /// Failing, cancelling and halting a running run each end it in its own
    /// status. A cancelled run shown as failed would read as a fault, not an
    /// operator's choice.
    #[test]
    fn each_way_of_stopping_a_run_records_its_own_status() {
        type StopRun = fn(&mut AgentRun<ResolvedTenant>, &AgentIdentity<ResolvedTenant>);

        let ends: [(StopRun, RunStatus); 3] = [
            (|r, _| r.fail(), RunStatus::Failed),
            (
                |r, agent| {
                    cancel_as_owner(r, agent);
                },
                RunStatus::Cancelled,
            ),
            (|r, _| r.halt(), RunStatus::Halted),
        ];

        for (stop, expected) in ends {
            let (mut r, agent) = run(5);

            stop(&mut r, &agent);

            assert_eq!(r.status(), expected);
            assert!(r.status().is_terminal());
        }
    }

    /// A completed run gets a late cancel, fail and halt. A cancelled run gets
    /// a late fail. Each keeps the status it first ended with.
    #[test]
    fn a_stop_that_arrives_after_the_run_ended_changes_nothing() {
        let (mut completed, agent) = run(5);
        completed.complete("done").unwrap();

        cancel_as_owner(&mut completed, &agent);
        completed.fail();
        completed.halt();

        assert_eq!(completed.status(), RunStatus::Completed);

        let (mut cancelled, cancelled_agent) = run(5);
        cancel_as_owner(&mut cancelled, &cancelled_agent);
        cancelled.fail();
        assert_eq!(
            cancelled.status(),
            RunStatus::Cancelled,
            "the first account of why it stopped is the one that stands"
        );
    }

    /// An outsider cannot order cancellation, leaving the run active. Its
    /// owner can cancel it and receives proof naming the run and owner.
    #[test]
    fn only_the_starter_or_someone_with_a_say_cancels_a_run() {
        let (mut r, agent) = run(5);
        let sam = crate::types::Human::new(
            crate::types::HumanAccount::User(crate::types::UserId::new()),
            crate::types::PersonKey::new("sam@corp.test").unwrap(),
        );

        let by_sam = r.order_cancel(&nobody_special(&sam), &agent);

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(r.status(), RunStatus::Running);
        let cancelled = cancel_as_owner(&mut r, &agent).unwrap();
        assert_eq!(cancelled.run_id(), r.id());
        assert!(cancelled.by().is_same_person_as(agent.owner()));
    }

    /// Applying another run's cancellation order is forbidden and leaves
    /// the receiving run active.
    #[test]
    fn an_order_for_another_run_stops_nothing() {
        let (first, agent) = run(5);
        let (mut second, _) = run(5);
        let order = first.order_cancel(&owner_of(&agent), &agent).unwrap();

        let result = second.cancel(&order);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(second.status(), RunStatus::Running);
    }

    /// The worker stops halfway, after cancelling the run but before
    /// withdrawing its approvals. Applying the order again gives the proof
    /// again, so it can finish.
    #[test]
    fn applying_an_order_twice_gives_the_proof_twice() {
        let (mut r, agent) = run(5);
        let order = r.order_cancel(&owner_of(&agent), &agent).unwrap();

        let first = r.cancel(&order).unwrap();
        let again = r.cancel(&order).unwrap();

        assert!(first.is_some());
        assert_eq!(first, again);
    }

    /// A denial issued for another run is forbidden; this run remains
    /// awaiting approval.
    #[test]
    fn a_denial_for_another_run_drops_nothing() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{}"), &agent)
            .unwrap();
        let (other, _) = run(5);

        let result = r.deny_pending(&denied(&other, "delete_order", "{}"), "no");

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(r.status(), RunStatus::AwaitingApproval);
    }

    /// A run is cancelled five seconds after it started. Its update time moves
    /// forward, so the record shows when it stopped.
    #[test]
    fn stopping_a_run_moves_its_updated_stamp() {
        let (mut r, agent) = run(5);
        let before = r.updated_at();
        let frozen = crate::shared::clock::freeze(before + time::Duration::seconds(5));

        cancel_as_owner(&mut r, &agent);

        assert!(r.updated_at() > before);
        drop(frozen);
    }

    /// An allowed `get_order` and a denied `delete_order`, both for id 1, are
    /// recorded. Each step keeps its number, its tool and its arguments, which
    /// say what was really asked for.
    #[test]
    fn a_recorded_step_keeps_its_position_tool_and_arguments() {
        let (mut r, agent) = run(5);
        r.record_allowed(
            calling(&tool("get_order"), "{\"id\":1}"),
            &agent,
            "{\"total\":42}",
        )
        .unwrap();
        r.record_denied(
            call("delete_order", "{\"id\":1}"),
            "outside declared purpose",
        )
        .unwrap();

        let steps = r.steps();
        assert_eq!(steps[0].seq(), 1);
        assert_eq!(steps[0].tool(), Some("get_order"));
        assert_eq!(steps[0].arguments(), Some("{\"id\":1}"));
        assert_eq!(steps[1].seq(), 2);
        assert_eq!(steps[1].arguments(), Some("{\"id\":1}"));
    }

    /// The answer step names no tool and has no arguments. Empty arguments
    /// would read as a tool call made with none.
    #[test]
    fn an_answer_step_names_no_tool_and_no_arguments() {
        let (mut r, _) = run(5);
        r.complete("the total is 42").unwrap();

        let answer = &r.steps()[0];
        assert_eq!(answer.tool(), None);
        assert_eq!(answer.arguments(), None);
    }

    /// A reference to a paused `delete_order` for id 1 carries the tool, the
    /// arguments and the pause. All three are compared when the approval
    /// comes back.
    #[test]
    fn a_pending_call_reference_carries_the_tool_the_arguments_and_the_pause() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();

        let held = PendingCallRef::of(r.pending().unwrap());

        assert_eq!(held.tool(), "delete_order");
        assert_eq!(held.arguments(), "{\"id\":1}");
        assert_eq!(held.at_step(), 1);
    }

    /// A workflow step starts a run at internal exposure, carried from earlier
    /// steps. The new run reports internal before it reads anything.
    #[test]
    fn a_fresh_run_holds_the_exposure_it_was_started_with() {
        let (r, _) = started(StartRunParams {
            exposure: DataClassLevel::Internal,
            ..params(5)
        });

        assert_eq!(r.exposure(), DataClassLevel::Internal);
    }

    /// A public run calls `get_salary`, a confidential tool. Its exposure
    /// rises to confidential, and the step records what it read.
    #[test]
    fn reading_from_a_more_sensitive_tool_raises_the_exposure() {
        let (mut r, agent) = run(5);

        r.record_allowed(calling(&tool("get_salary"), "{}"), &agent, "{}")
            .unwrap();

        assert_eq!(r.exposure(), DataClassLevel::Confidential);
        assert_eq!(r.steps()[0].read(), DataClassLevel::Confidential);
    }

    /// After reading salaries, a run refuses a public weather call as a leak
    /// and retains its confidential exposure.
    #[test]
    fn a_run_that_read_confidential_data_calls_no_public_tool() {
        let (mut r, agent) = run(5);
        r.record_allowed(calling(&tool("get_salary"), "{}"), &agent, "{}")
            .unwrap();
        let weather = tool("get_weather");

        let leak = r.record_allowed(calling(&weather, "{}"), &agent, "{}");

        assert!(matches!(leak, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            r.admit(&calling(&weather, "{}")),
            Err(CallRefusal::WouldLeak { .. })
        ));
        assert_eq!(r.exposure(), DataClassLevel::Confidential);
    }

    /// Recording a high-risk deletion without approval is forbidden and adds
    /// no step to the run.
    #[test]
    fn a_high_risk_call_is_not_recorded_without_approval() {
        let (mut r, agent) = run(5);

        let result = r.record_allowed(
            calling(&tool("delete_order"), "{\"id\":\"*\"}"),
            &agent,
            "deleted",
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(r.steps().is_empty());
    }

    /// An approved `delete_order` for id 1 is recorded as run. The run then
    /// holds no approved call and has one step.
    #[test]
    fn the_approved_call_is_recorded_and_then_released() {
        let (mut r, agent) = run(5);
        let delete = tool("delete_order");
        r.await_approval(calling(&delete, "{\"id\":1}"), &agent)
            .unwrap();
        r.approve_pending(&released(&r, "delete_order", "{\"id\":1}"))
            .unwrap();

        r.record_allowed(calling(&delete, "{\"id\":1}"), &agent, "ok")
            .unwrap();

        assert!(r.approved_call().is_none());
        assert_eq!(r.steps().len(), 1);
    }

    /// Approval to delete order 1 cannot record a deletion of order 2; the
    /// conflict leaves the approved call held.
    #[test]
    fn another_call_is_not_recorded_while_an_approved_one_waits() {
        let (mut r, agent) = run(5);
        let delete = tool("delete_order");
        r.await_approval(calling(&delete, "{\"id\":1}"), &agent)
            .unwrap();
        r.approve_pending(&released(&r, "delete_order", "{\"id\":1}"))
            .unwrap();

        let result = r.record_allowed(calling(&delete, "{\"id\":2}"), &agent, "ok");

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert!(r.approved_call().is_some());
    }

    /// A tool absent from the run's grant is refused both during admission
    /// and when recording an allowed call.
    #[test]
    fn a_tool_the_run_was_not_given_is_refused() {
        let (mut r, agent) = run(5);
        let drop_tables = tool("drop_tables");

        let result = r.record_allowed(calling(&drop_tables, "{}"), &agent, "ok");

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(
            r.admit(&calling(&drop_tables, "{}")),
            Err(CallRefusal::NotGranted)
        );
    }

    /// A run declared for reads, writes and deletes asks for `pay_invoice`.
    /// The tool was given, but moving money is outside the purpose.
    #[test]
    fn a_tool_outside_the_purpose_is_refused() {
        let (r, _) = run(5);

        assert_eq!(
            r.admit(&calling(&tool("pay_invoice"), "{}")),
            Err(CallRefusal::OutsidePurpose)
        );
    }

    /// Resolving a delete call against the read tool is refused as unknown
    /// because their tool names differ.
    #[test]
    fn a_call_is_checked_against_the_tool_it_names() {
        let get_order = tool("get_order");

        let result =
            ResolvedCall::resolve(call("delete_order", "{}"), &get_order, &PathValues::new());

        assert!(matches!(result, Err(CallRefusal::UnknownTool)));
    }

    /// A stored run without a delegation cannot call a listed tool; admission
    /// refuses it for missing authority.
    #[test]
    fn a_run_under_no_delegation_calls_nothing() {
        let (r, _) = run(5);
        let row = AgentRunRow {
            delegation_id: ActingUnder::NoDelegation,
            ..stored(&r)
        };
        let r = AgentRun::<ResolvedTenant>::reconstitute(row).unwrap();

        assert_eq!(
            r.admit(&calling(&tool("get_order"), "{}")),
            Err(CallRefusal::NoAuthority)
        );
    }

    /// A run has read salaries. It may send to confidential and restricted
    /// tools, but not to public or internal ones.
    #[test]
    fn a_run_may_not_send_what_it_read_to_a_less_cleared_tool() {
        let (mut r, agent) = run(5);
        r.record_allowed(calling(&tool("get_salary"), "{}"), &agent, "{}")
            .unwrap();

        assert!(!r.may_send_to(DataClassLevel::Public));
        assert!(!r.may_send_to(DataClassLevel::Internal));
        assert!(r.may_send_to(DataClassLevel::Confidential));
        assert!(r.may_send_to(DataClassLevel::Restricted));
    }

    /// A run that has read only public data may send to a public tool.
    #[test]
    fn a_run_that_has_read_nothing_sensitive_may_send_anywhere() {
        let (r, _) = run(5);

        assert!(r.may_send_to(DataClassLevel::Public));
    }

    /// A completed run is asked to record a `get_salary` call. It is refused,
    /// and the exposure stays public.
    #[test]
    fn a_step_on_a_finished_run_leaves_the_exposure_alone() {
        let (mut r, agent) = run(5);
        r.complete("done").unwrap();

        let refused = r.record_allowed(calling(&tool("get_salary"), "{}"), &agent, "{}");

        assert!(refused.is_err());
        assert_eq!(r.exposure(), DataClassLevel::Public);
    }

    fn stored(run: &AgentRun<ResolvedTenant>) -> AgentRunRow {
        AgentRunRow {
            id: run.id,
            agent_id: run.agent_id,
            provider_id: run.provider_id,
            goal: run.goal.clone(),
            purpose: run.purpose.clone(),
            granted_tools: run.granted_tools.clone(),
            approval_classes: run.approval_classes.clone(),
            approval: run.approval,
            delegation_id: run.delegation_id,
            max_steps: run.max_steps,
            spend_limit: run.spend_limit,
            spend_check: run.spend_check,
            usage: run.usage,
            spent: run.spent,
            started_by: run.started_by.clone(),
            exposure: run.exposure,
            origin: run.origin,
            steps: run.steps.clone(),
            state: run.state.clone(),
            check: run.check,
            created_at: run.created_at,
            updated_at: run.updated_at,
        }
    }

    /// A stored run with steps 2 and 1 swapped is refused as corrupt. The same
    /// run in order reads back fine.
    #[test]
    fn a_stored_run_with_steps_out_of_sequence_is_refused() {
        let (mut run, agent) = run(5);
        let lookup = tool("lookup");
        run.record_allowed(calling(&lookup, "{}"), &agent, "ok")
            .unwrap();
        run.record_allowed(calling(&lookup, "{}"), &agent, "ok")
            .unwrap();
        let mut row = stored(&run);
        row.steps.swap(0, 1);

        assert!(AgentRun::<ResolvedTenant>::reconstitute(stored(&run)).is_ok());
        assert!(refused_as_corrupt(
            &AgentRun::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored run containing three tool calls under a two-step limit is
    /// refused as corrupt.
    #[test]
    fn a_stored_run_with_more_calls_than_its_limit_is_refused() {
        let (mut run, agent) = run(3);
        let lookup = tool("lookup");
        for _ in 0..3 {
            run.record_allowed(calling(&lookup, "{}"), &agent, "ok")
                .unwrap();
        }
        let row = AgentRunRow {
            max_steps: 2,
            ..stored(&run)
        };

        assert!(refused_as_corrupt(
            &AgentRun::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Lowering stored exposure below a recorded salary read makes the run
    /// corrupt and prevents reconstruction.
    #[test]
    fn a_stored_run_whose_exposure_fell_below_what_it_read_is_refused() {
        let (mut run, agent) = run(5);
        run.record_allowed(calling(&tool("get_salary"), "{}"), &agent, "{}")
            .unwrap();
        let row = AgentRunRow {
            exposure: DataClassLevel::Public,
            ..stored(&run)
        };

        assert!(refused_as_corrupt(
            &AgentRun::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored approval assigned to the wrong next step is refused as
    /// corrupt, while the original approved run reconstructs successfully.
    #[test]
    fn a_stored_approved_call_at_a_step_the_run_never_paused_at_is_refused() {
        let (mut run, agent) = run(5);
        run.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();
        run.approve_pending(&released(&run, "delete_order", "{\"id\":1}"))
            .unwrap();
        let mut forged = run.pending().unwrap().clone();
        forged.at_step = 4;
        let row = AgentRunRow {
            state: RunState::Running(NextCall::Approved(forged)),
            ..stored(&run)
        };

        assert!(AgentRun::<ResolvedTenant>::reconstitute(stored(&run)).is_ok());
        assert!(refused_as_corrupt(
            &AgentRun::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A held call approved before the run started makes its stored row corrupt.
    #[test]
    fn a_stored_call_approved_before_the_run_started_is_refused() {
        let (mut run, agent) = run(5);
        run.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();
        let mut forged = run.pending().unwrap().clone();
        forged.approved = CallApproval::Approved(run.created_at - time::Duration::DAY);
        let row = AgentRunRow {
            state: RunState::Running(NextCall::Approved(forged)),
            ..stored(&run)
        };

        assert!(refused_as_corrupt(
            &AgentRun::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored step timestamp before the run's creation is refused as corrupt.
    #[test]
    fn a_stored_step_recorded_before_the_run_started_is_refused() {
        let (mut run, agent) = run(5);
        run.record_allowed(calling(&tool("lookup"), "{}"), &agent, "ok")
            .unwrap();
        let mut row = stored(&run);
        row.steps[0].at = run.created_at - time::Duration::MINUTE;

        assert!(refused_as_corrupt(
            &AgentRun::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored run still active after spending beyond its cap is refused
    /// as corrupt.
    #[test]
    fn a_stored_run_past_its_spend_limit_still_going_is_refused() {
        let (run, _) = run(5);
        let row = AgentRunRow {
            spend_limit: Restriction::To(Spend::from_micros(100)),
            spent: Spend::from_micros(101),
            ..stored(&run)
        };

        assert!(refused_as_corrupt(
            &AgentRun::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Stored runs cannot skip a reached spending check or set its threshold
    /// at the spending cap; both inconsistent rows are refused as corrupt.
    #[test]
    fn a_stored_run_that_skipped_its_spend_check_is_refused() {
        let (run, _) = run(5);
        let skipped = AgentRunRow {
            spend_check: SpendCheck::AskAt(Spend::from_micros(500)),
            spent: Spend::from_micros(600),
            ..stored(&run)
        };
        let at_its_limit = AgentRunRow {
            spend_limit: Restriction::To(Spend::from_micros(500)),
            spend_check: SpendCheck::AskAt(Spend::from_micros(500)),
            ..stored(&run)
        };

        assert!(refused_as_corrupt(
            &AgentRun::<ResolvedTenant>::reconstitute(skipped)
        ));
        assert!(refused_as_corrupt(
            &AgentRun::<ResolvedTenant>::reconstitute(at_its_limit)
        ));
    }

    /// A run that announced its start is saved and read back. The copy read
    /// from storage has announced nothing, so loading it records nothing.
    #[test]
    fn a_run_read_back_from_storage_has_raised_nothing() {
        let (mut run, _) = run(5);
        run.announce_start(RunNames::new(
            crate::types::EventLabel::of("nightly-report"),
            crate::types::EventLabel::of("prod-deepseek"),
        ));

        let mut read_back = AgentRun::<ResolvedTenant>::reconstitute(stored(&run)).unwrap();

        assert!(crate::test_support::events::raised(&mut read_back).is_empty());
    }
}
