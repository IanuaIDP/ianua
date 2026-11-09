//! Agent run steps: an agent run made from one step of a workflow.
//!
//! The run is built here, from the step. So it carries exactly the step's
//! agent, tools, approval classes, purpose and step cap. It acts for the
//! person the execution acts for. It is given only the fields the step
//! maps. It holds the sensitivity of the step's input from its first step.
//!
//! A code step whose sandbox version holds an agent starts the same kind
//! of run, made from the version's rules and the step's mapping, its
//! answers held to the version's check. Its run is settled on the step as
//! any other run is, once its check passed or it ended another way.

use crate::domains::agents::authority::capability::CapabilitySet;
use crate::domains::agents::authority::delegation::{ActingUnder, Delegation};
use crate::domains::agents::execution::run::{
    AgentRun, CancelOrder, RunCheck, RunGoal, RunStarter, RunStatus, RunStep, StartRunParams,
    StepOutcome,
};
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::{FieldName, FlowData};
use crate::domains::workflows::design::node::checking::{VERDICT_INSTRUCTION, Verdict, notes_of};
use crate::domains::workflows::design::node::{AgentRunStep, Checks, Node, NodeKey, NodeKind};
use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::acting::ActingAuthority;
use crate::domains::workflows::execution::record::ExecutionRecord;
use crate::domains::workflows::execution::step::{StepFailure, StepRefusal, StepState, Underway};
use crate::domains::workflows::execution::steps::deferral::ensure_due_again;
use crate::domains::workflows::execution::steps::work::{ReadyStep, Settled};
use crate::domains::workflows::sandbox::version::SandboxVersion;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::chain::EventOrigin;
use crate::types::UntrustedText;

/// The field an agent run's answer is found under in its step's output.
pub const ANSWER_FIELD: &str = "answer";

/// The field a checking step's verdict is found under: `ok`, `not_ok` or
/// `unclear`.
pub(crate) const VERDICT_FIELD: &str = "verdict";

/// The field a checking step's reasons are found under.
pub(crate) const NOTES_FIELD: &str = "notes";

/// The authority an agent run step's run acts under.
pub enum RunAuthority<'a, T: TenantScope> {
    /// No delegation. The run may then call no tool.
    NoDelegation,
    /// This delegation, from the person the execution acts for to the
    /// step's agent.
    Delegation(&'a Delegation<T>),
}

/// What a run a step starts stands on, checked as it starts.
pub struct RunBacking<'a, T: TenantScope> {
    /// The authority the run acts under.
    pub authority: &'a RunAuthority<'a, T>,
    /// The agent the run is made for, as it stands now.
    pub agent: &'a AgentIdentity<T>,
    /// What the person the execution acts for holds now.
    pub acting: &'a ActingAuthority,
}

/// What starting an agent run step came to.
#[derive(Debug)]
pub enum AgentRunStart<T: TenantScope> {
    /// This run, for the application to save and drive. The step waits for
    /// it.
    Started(Box<AgentRun<T>>, Vec<ExecutionRecord>),
    /// The step failed before any run was made.
    ///
    /// That happens when the agent may not act, the person does not hold
    /// what the run needs now, or no live delegation backs the run. It also
    /// happens when an approval right before the step has lapsed, or the
    /// goal with the input composed in is too large.
    Refused(Vec<ExecutionRecord>),
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// Starts the ready agent run step `key` as `agent`, under `authority`.
    ///
    /// The step fails, with a record, unless all of these hold:
    /// - `agent` is the step's agent and may act right now,
    /// - `acting` shows the person the execution acts for may still run
    ///   workflows and use the step's model provider, and still holds
    ///   everything the delegation grants,
    /// - when the step grants any tool, `authority` is a live delegation
    ///   from that person to that agent, which the server may present,
    /// - every approval right before the step still holds,
    /// - the goal, with the step's input composed in, is not too large.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::NotFound`] for an absent step; [`DomainError::InvalidTransition`]
    /// unless ready or if the execution ended; [`DomainError::Conflict`] after timeout
    /// or before a plan-limited step is due again (see [`Self::defer_agent_run`]);
    /// or [`DomainError::Validation`] unless the step is an agent run.
    pub fn start_agent_run(
        &mut self,
        key: &NodeKey,
        authority: &RunAuthority<'_, T>,
        agent: &AgentIdentity<T>,
        acting: &ActingAuthority,
    ) -> Result<AgentRunStart<T>, DomainError> {
        let ready = self.ready_step(key)?;
        ensure_due_again(ready.attempt, crate::shared::clock::now())?;
        let NodeKind::AgentRun(step) = ready.node.kind() else {
            return Err(DomainError::invalid(message!(
                "workflows-this-step-does-not-start-an",
                "this step does not start an agent run"
            )));
        };
        let step = step.clone();
        let backing = RunBacking {
            authority,
            agent,
            acting,
        };
        Ok(self.start_run_of(ready, &step, RunCheck::Unchecked, &backing))
    }

    /// Starts the ready code step `key`, whose sandbox `version` holds an
    /// agent, as a run of that agent under the version's rules, backed by
    /// `backing`. The run is given the fields the step maps, and its
    /// answers are held to the version's check before it completes.
    ///
    /// The step fails, with a record, for every reason an agent run step
    /// does; see [`start_agent_run`](Self::start_agent_run).
    ///
    /// # Errors
    ///
    /// As [`start_agent_run`](Self::start_agent_run), and
    /// [`DomainError::Validation`] unless the step is a code step naming
    /// `version`, and `version` holds an agent.
    pub fn start_held_agent(
        &mut self,
        key: &NodeKey,
        version: &SandboxVersion<T>,
        backing: &RunBacking<'_, T>,
    ) -> Result<AgentRunStart<T>, DomainError> {
        let ready = self.ready_step(key)?;
        ensure_due_again(ready.attempt, crate::shared::clock::now())?;
        let NodeKind::Code(code) = ready.node.kind() else {
            return Err(DomainError::invalid(message!(
                "workflows-this-step-does-not-run-code",
                "this step does not run code"
            )));
        };
        if code.version() != *version.id() {
            return Err(DomainError::invalid(message!(
                "workflows-the-version-is-not-the-step-s",
                "the sandbox version is not the one the step names"
            )));
        }
        let Some(held) = version.held_agent() else {
            return Err(DomainError::invalid(message!(
                "workflows-the-version-holds-no-agent",
                "the sandbox version holds no agent"
            )));
        };
        let step = held.step_for(code.inputs());
        let check = RunCheck::Sandbox {
            version: *version.id(),
            tries: held.tries(),
        };
        Ok(self.start_run_of(ready, &step, check, backing))
    }

    /// Starts the ready step a run of `step` is made for, its answers held
    /// to `check`, or fails it with the reason it may not start.
    fn start_run_of(
        &mut self,
        ready: ReadyStep,
        step: &AgentRunStep,
        check: RunCheck,
        backing: &RunBacking<'_, T>,
    ) -> AgentRunStart<T> {
        let cleared = self.cleared_run(step, backing.authority, backing.agent, backing.acting);
        if let Err(refusal) = cleared {
            return self.refuse_run(&ready, StepFailure::Refused(refusal));
        }
        if !self.approvals_before_still_hold(&ready.node) {
            return self.refuse_run(&ready, StepFailure::ApprovalLapsed);
        }
        let Ok(goal) = goal_of(step, &ready) else {
            return self.refuse_run(&ready, StepFailure::InputTooLarge);
        };
        let params = self.run_params(step, goal, &ready);
        let Ok(run) = self.started_run(params, backing.authority, backing.agent) else {
            return self.refuse_run(&ready, StepFailure::Refused(StepRefusal::NoDelegation));
        };
        let run = run.checked_by(check);
        let records = self.begin_step(
            ready,
            Underway::AgentRun(*run.id()),
            crate::shared::clock::now(),
        );
        AgentRunStart::Started(Box::new(run), records)
    }

    /// A run of `agent` with `params`, started for the person this
    /// execution acts for, under `authority`.
    fn started_run(
        &self,
        params: StartRunParams,
        authority: &RunAuthority<'_, T>,
        agent: &AgentIdentity<T>,
    ) -> Result<AgentRun<T>, DomainError> {
        let starter = RunStarter::acting_for(&self.acting_for);
        match authority {
            RunAuthority::Delegation(delegation) => {
                AgentRun::start(starter, params, delegation, agent)
            }
            RunAuthority::NoDelegation => AgentRun::start_without_tools(starter, params, agent),
        }
    }

    /// The delegation a run of `step` acts under.
    ///
    /// It is given only when `agent` is the step's agent and may act, the
    /// person the execution acts for still holds what the run needs, and
    /// the delegation backs the run.
    fn cleared_run(
        &self,
        step: &AgentRunStep,
        authority: &RunAuthority<'_, T>,
        agent: &AgentIdentity<T>,
        acting: &ActingAuthority,
    ) -> Result<ActingUnder, StepRefusal> {
        if agent.id() != step.agent_id() || !agent.may_act_at(crate::shared::clock::now()) {
            return Err(StepRefusal::AgentMayNotAct);
        }
        let empty = CapabilitySet::empty();
        let granted = match authority {
            RunAuthority::Delegation(delegation) => delegation.granted(),
            RunAuthority::NoDelegation => &empty,
        };
        if !acting.may_run_agent_for(&self.acting_for, step.provider_id(), granted) {
            return Err(StepRefusal::PersonLacksAuthority);
        }
        self.acting_under(step, authority)
    }

    fn refuse_run(&mut self, ready: &ReadyStep, failure: StepFailure) -> AgentRunStart<T> {
        AgentRunStart::Refused(self.fail(ready.index, failure))
    }

    fn run_params(&self, step: &AgentRunStep, goal: RunGoal, ready: &ReadyStep) -> StartRunParams {
        StartRunParams {
            provider_id: *step.provider_id(),
            goal,
            purpose: step.purpose().clone(),
            granted_tools: step.tools().to_vec(),
            approval_classes: step.approval_classes().to_vec(),
            max_steps: step.max_steps(),
            exposure: ready.exposure,
            origin: EventOrigin::Execution(self.chain_depth),
            spend_limit: step.spend_cap(),
            ask_past: step.ask_past(),
        }
    }

    /// The delegation a run of `step` acts under.
    ///
    /// It is none when the step grants no tool and none is given. Otherwise
    /// it is a live delegation from the person the execution acts for to
    /// the step's agent. It must not be sender-constrained, so the server
    /// may present it for the run.
    fn acting_under(
        &self,
        step: &AgentRunStep,
        authority: &RunAuthority<'_, T>,
    ) -> Result<ActingUnder, StepRefusal> {
        let delegation = match authority {
            RunAuthority::NoDelegation if step.tools().is_empty() => {
                return Ok(ActingUnder::NoDelegation);
            }
            RunAuthority::NoDelegation => return Err(StepRefusal::NoDelegation),
            RunAuthority::Delegation(delegation) => delegation,
        };
        let backs_this_run = *delegation.delegator() == self.acting_for.principal()
            && delegation.delegate() == step.agent_id()
            && delegation.is_valid(crate::shared::clock::now())
            && !delegation.constraints().is_sender_constrained();
        if !backs_this_run {
            return Err(StepRefusal::NoDelegation);
        }
        Ok(ActingUnder::Delegation(*delegation.id()))
    }

    /// Settles the agent run step `key` from how `run` ended.
    ///
    /// A completed run hands on its answer, carrying everything the run
    /// read. Any other end fails the step. A run still under way when the
    /// execution ended is recorded, and nothing goes on from it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is neither
    ///   running nor abandoned.
    /// - [`DomainError::InvalidTransition`] when `run` has not ended.
    /// - [`DomainError::Conflict`] once a running execution ran out of
    ///   time.
    /// - [`DomainError::Forbidden`] when `run` is not the step's run.
    pub fn settle_agent_run(
        &mut self,
        key: &NodeKey,
        run: &AgentRun<T>,
    ) -> Result<Vec<ExecutionRecord>, DomainError> {
        let step = self.reporting_step(key)?;
        if step.underway != Underway::AgentRun(*run.id()) {
            return Err(DomainError::forbidden(message!(
                "workflows-this-run-is-not-the-step",
                "this run is not the step's run"
            )));
        }
        let checks = match self.graph().node(key).map(Node::kind) {
            Some(NodeKind::AgentRun(agent_step)) => agent_step.checks().clone(),
            _ => Checks::Nothing,
        };
        let settled = settled_by(run, step.exposure.max(run.exposure()), &checks)?;
        Ok(self.settle_reported(step, settled))
    }

    /// The orders to stop every agent run this execution gave up when it
    /// ended, in the name of the person it acts for.
    ///
    /// An execution that is cancelled, runs out of time or fails leaves its
    /// steps' runs going. Ann cancels a workflow while its agent drafts
    /// replies to customers. Without these, the run keeps drafting and
    /// sending for a workflow nobody runs any more. A run whose late result
    /// was already recorded is no longer given up, and gets none.
    #[must_use]
    pub fn abandoned_run_orders(&self) -> Vec<CancelOrder> {
        self.steps()
            .filter_map(|(_, state)| match state {
                StepState::Abandoned {
                    underway: Underway::AgentRun(run_id),
                    ..
                } => Some(CancelOrder::for_abandoned_run(
                    *run_id,
                    self.acting_for.clone(),
                )),
                StepState::Waiting
                | StepState::Ready { .. }
                | StepState::Running { .. }
                | StepState::Succeeded { .. }
                | StepState::Failed(_)
                | StepState::Skipped
                | StepState::Stopped
                | StepState::Abandoned { .. } => None,
            })
            .collect()
    }
}

/// The step's goal with the fields it maps from its input composed in.
///
/// Nothing else of what came before is added. A step that maps nothing
/// hands the model its instruction alone.
fn goal_of(step: &AgentRunStep, ready: &ReadyStep) -> Result<RunGoal, DomainError> {
    let given = step.inputs().apply(&ready.input)?;
    let goal = if given.is_empty() {
        step.goal().resolve(&[])?
    } else {
        step.goal().resolve(&[given.render()])?
    };
    match step.checks() {
        Checks::Nothing => Ok(goal),
        Checks::Step(_) => Ok(RunGoal::new(format!(
            "{}{VERDICT_INSTRUCTION}",
            goal.as_str()
        ))?),
    }
}

/// An agent run's answer as its step's output, a map holding it under
/// [`ANSWER_FIELD`]; a checking step's also holds its verdict under
/// [`VERDICT_FIELD`] and its reasons under [`NOTES_FIELD`].
fn answer_output(answer: &str, checks: &Checks) -> Result<FlowData, DomainError> {
    let mut fields = vec![(FieldName::new(ANSWER_FIELD)?, FlowData::text(answer)?)];
    if let Checks::Step(_) = checks {
        fields.push((
            FieldName::new(VERDICT_FIELD)?,
            FlowData::text(Verdict::of(answer).as_str())?,
        ));
        fields.push((
            FieldName::new(NOTES_FIELD)?,
            FlowData::text(notes_of(answer))?,
        ));
    }
    FlowData::map(fields)
}

/// What an ended run settles its step with, its output carrying data as
/// sensitive as `reached`: a completed run's answer, read as a verdict when
/// the step `checks` another's work, else the way it ended. A run still
/// under way is refused.
fn settled_by<T: TenantScope>(
    run: &AgentRun<T>,
    reached: DataClassLevel,
    checks: &Checks,
) -> Result<Settled, DomainError> {
    match (run.status(), run.answer()) {
        (RunStatus::Completed, Some(answer)) => Ok(match answer_output(answer, checks) {
            Ok(output) => Settled::Output(output, reached),
            Err(_) => Settled::Failure(StepFailure::OutputTooLarge),
        }),
        (RunStatus::Running | RunStatus::AwaitingApproval | RunStatus::Paused, _) => {
            Err(DomainError::invalid_transition(message!(
                "workflows-the-agent-run-has-not-ended",
                "the agent run has not ended"
            )))
        }
        (
            status @ (RunStatus::Completed
            | RunStatus::Failed
            | RunStatus::Cancelled
            | RunStatus::Halted
            | RunStatus::OverBudget),
            _,
        ) => Ok(Settled::Failure(StepFailure::Reported(why_ended(
            run, status,
        )))),
    }
}

/// Why `run` ended `status` without an answer to hand on: what its check
/// last said when that ended it, else how it ended.
fn why_ended<T: TenantScope>(run: &AgentRun<T>, status: RunStatus) -> UntrustedText {
    let last = run.steps().last().map(RunStep::outcome);
    match last {
        Some(StepOutcome::CheckFailed(said)) if status == RunStatus::Failed => {
            UntrustedText::from(format!("the agent's answer did not pass its check: {said}"))
        }
        Some(_) | None => UntrustedText::from(format!("the agent run ended {}", status.as_str())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::DelegationConstraints;
    use crate::domains::agents::authority::delegation::{
        Delegate, GrantDelegationParams, HeldBy, HeldResources, ReviewDuty,
    };
    use crate::domains::agents::execution::run::{RunNames, SpendCheck};
    use crate::domains::agents::execution::usage::Spend;
    use crate::domains::agents::identity::agent::SuspendedBy;
    use crate::domains::agents::identity::control::AgentControl;
    use crate::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::data::FlowValue;
    use crate::domains::workflows::design::node::{AgentRunParams, Port};
    use crate::domains::workflows::execution::ExecutionStatus;
    use crate::domains::workflows::execution::record::{ExecutionEnd, StepRecord};
    use crate::domains::workflows::execution::step::StepState;
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, STEP_ASK_PAST, STEP_SPEND_CAP, SeesAll, acting, agent, agent_execution,
        agent_step, ann, append_row, bob, control_by, copy, delegation, delegation_with, draft,
        edge, frozen_at, held_code, held_version, key, managing, offered, path, publish_as,
        running_agent, runs_workflows, stage_run, started, state,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::restriction::Restriction;
    use crate::test_support::authority::assumed_authority;
    use crate::types::{ActionClass, EventLabel, Human, Initiator, Seconds, TenantId};

    const TOOLS: &[&str] = &["search_orders"];

    /// Bob's approval permits an agent run a minute later. Attempting the
    /// same step two hours later fails because approval lapsed.
    #[test]
    fn an_agent_run_after_its_approval_closed_is_not_started() {
        let agent = agent();
        let approved_at_noon = || {
            let _noon = frozen_at(0);
            let mut execution = started(
                vec![
                    crate::domains::workflows::execution::tests::fixtures::approval("ok"),
                    agent_step(*agent.id(), &[]),
                ],
                vec![edge("ok", Port::Next, "summarise")],
            );
            crate::domains::workflows::execution::tests::fixtures::approve(&mut execution, "ok");
            execution
        };
        let mut prompt = approved_at_noon();
        let mut late = approved_at_noon();

        {
            let _soon = frozen_at(60);
            running_agent(&mut prompt, &agent);
        }
        let _hours_later = frozen_at(7200);
        let lapsed = refused_with(&mut late, &RunAuthority::NoDelegation, &agent);

        assert_eq!(lapsed, StepState::Failed(StepFailure::ApprovalLapsed));
    }

    fn refused_with(
        execution: &mut Execution,
        authority: &RunAuthority<'_, ResolvedTenant>,
        acting_agent: &AgentIdentity<ResolvedTenant>,
    ) -> StepState {
        let person = acting(execution.acting_for());
        let started = execution
            .start_agent_run(&key("summarise"), authority, acting_agent, &person)
            .unwrap();
        assert!(matches!(started, AgentRunStart::Refused(_)));
        state(execution, "summarise")
    }

    fn no_delegation() -> StepState {
        StepState::Failed(StepFailure::Refused(StepRefusal::NoDelegation))
    }

    fn agent_may_not_act() -> StepState {
        StepState::Failed(StepFailure::Refused(StepRefusal::AgentMayNotAct))
    }

    /// Ann's tool-using step fails for lack of a delegation when given none,
    /// Bob's delegation, a delegation to another agent, or her expired one.
    #[test]
    fn a_tool_calling_run_needs_a_live_delegation_from_the_acting_person_to_its_agent() {
        let agent = agent();
        let past = frozen_at(-3600);
        let acting = agent_execution(&agent, TOOLS).acting_for().clone();
        let expired = delegation(&acting, &agent);
        drop(past);
        let _now = frozen_at(0);
        let from_someone_else = delegation(&bob(), &agent);
        let another = crate::domains::workflows::execution::tests::fixtures::agent();
        let to_another_agent = delegation(&acting, &another);
        let fresh = || agent_execution(&agent, TOOLS);

        assert_eq!(
            refused_with(&mut fresh(), &RunAuthority::NoDelegation, &agent),
            no_delegation()
        );
        for refused in [&from_someone_else, &to_another_agent, &expired] {
            assert_eq!(
                refused_with(&mut fresh(), &RunAuthority::Delegation(refused), &agent),
                no_delegation()
            );
        }
    }

    /// Ann revokes the delegation she gave the step's agent. The agent run
    /// step is refused for having no delegation, as an agent outside a
    /// workflow would be.
    #[test]
    fn a_revoked_delegation_does_not_back_a_run() {
        let agent = agent();
        let mut execution = agent_execution(&agent, TOOLS);
        let mut taken_back = delegation(execution.acting_for(), &agent);
        taken_back
            .revoke(crate::domains::agents::authority::delegation::Revoker::Platform)
            .unwrap();

        let refused = refused_with(
            &mut execution,
            &RunAuthority::Delegation(&taken_back),
            &agent,
        );

        assert_eq!(refused, no_delegation());
    }

    /// Ann's delegation is bound to the agent's own key. The server cannot
    /// prove that key, so the delegation does not back the run and the step
    /// is refused.
    #[test]
    fn a_sender_constrained_delegation_does_not_back_a_run() {
        let agent = agent();
        let mut execution = agent_execution(&agent, TOOLS);
        let bound = delegation_with(
            execution.acting_for(),
            &agent,
            DelegationConstraints::new(Seconds::new(600), 1)
                .unwrap()
                .sender_constrained(),
        );

        let refused = refused_with(&mut execution, &RunAuthority::Delegation(&bound), &agent);

        assert_eq!(refused, no_delegation());
    }

    /// Ann gives the step's agent a live delegation. The run starts and
    /// acts under that delegation.
    #[test]
    fn a_live_delegation_backs_the_run_it_starts() {
        let agent = agent();
        let mut execution = agent_execution(&agent, TOOLS);
        let live = delegation(execution.acting_for(), &agent);
        let person = acting(execution.acting_for());

        let started = execution
            .start_agent_run(
                &key("summarise"),
                &RunAuthority::Delegation(&live),
                &agent,
                &person,
            )
            .unwrap();

        let AgentRunStart::Started(run, _) = started else {
            panic!("the agent run step was refused");
        };
        assert_eq!(run.delegation_id(), &ActingUnder::Delegation(*live.id()));
    }

    /// A step with no tools, write approvals, a cap of 5 steps and one of
    /// two in spending, asking a person past one, starts a run. The run has
    /// the same agent, tools, approvals, caps and amount to ask at, acts for
    /// the same person, and starts at the input's internal level.
    #[test]
    fn the_run_a_step_starts_carries_exactly_the_steps_bounds() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);

        let run = running_agent(&mut execution, &agent);

        assert_eq!(run.agent_id(), agent.id());
        assert!(run.granted_tools().is_empty());
        assert_eq!(run.approval_classes(), &[ActionClass::Write]);
        assert_eq!(run.max_steps(), 5);
        assert_eq!(run.spend_limit(), Restriction::To(STEP_SPEND_CAP));
        assert_eq!(run.spend_check(), SpendCheck::AskAt(STEP_ASK_PAST));
        assert_eq!(run.delegation_id(), &ActingUnder::NoDelegation);
        assert_eq!(
            run.started_by(),
            &Initiator::Human(execution.acting_for().clone())
        );
        assert_eq!(run.exposure(), DataClassLevel::Internal);
        assert!(matches!(
            state(&execution, "summarise"),
            StepState::Running {
                underway: Underway::AgentRun(id),
                ..
            } if id == *run.id()
        ));
    }

    /// Ann caps a step's spending at nothing. The step is refused: a run
    /// that may spend nothing could never ask its model anything.
    #[test]
    fn a_step_that_may_spend_nothing_is_refused() {
        let capped_at_nothing = AgentRunParams {
            spend_cap: Restriction::To(Spend::from_micros(0)),
            ..stage_run()
        };

        let step = AgentRunStep::new(capped_at_nothing);

        assert!(matches!(step, Err(DomainError::Validation(_))));
    }

    /// Ann caps a step at two units and asks to be asked past two as well.
    /// The step is refused: the run would stop at its cap before anyone
    /// could be asked.
    #[test]
    fn a_step_asking_at_its_cap_is_refused() {
        let at_the_cap = AgentRunParams {
            spend_cap: Restriction::To(STEP_SPEND_CAP),
            ask_past: Restriction::To(STEP_SPEND_CAP),
            ..stage_run()
        };

        let step = AgentRunStep::new(at_the_cap);

        assert!(matches!(step, Err(DomainError::Validation(_))));
    }

    /// An earlier step produced a `salary` field, and the agent step maps
    /// only `orders`. The run's goal holds the orders and never the salary.
    #[test]
    fn a_run_is_given_only_the_fields_its_step_maps() {
        let agent = agent();
        let mut execution = started(
            vec![
                copy("records", &[("salary", "trigger.ok")]),
                agent_step(*agent.id(), &[]),
            ],
            vec![edge("records", Port::Next, "summarise")],
        );

        let run = running_agent(&mut execution, &agent);

        assert!(run.goal().as_str().contains("orders"));
        assert!(!run.goal().as_str().contains("salary"));
    }

    /// Losing the delegated workflow-view right, use of the model provider,
    /// or all authority prevents Ann's agent run and records the missing
    /// authority. Holding everything the run needs lets it start.
    #[test]
    fn a_person_who_no_longer_holds_what_the_run_needs_stops_it() {
        let agent = agent();
        let lacks_the_grant = runs_workflows();
        let lacks_the_provider = CapabilitySet::new(
            vec![
                SystemPermission::Workflows(WorkflowAction::Run),
                SystemPermission::Workflows(WorkflowAction::View),
            ],
            Vec::new(),
        );
        let holds_everything = lacks_the_provider
            .clone()
            .with_resources(runs_workflows().resources().to_vec());

        for refused in [lacks_the_grant, lacks_the_provider, CapabilitySet::empty()] {
            let AgentRunStart::Refused(records) = run_with_view_delegation(&agent, refused) else {
                panic!("a run started for someone lacking what it needs");
            };
            assert!(records.contains(&ExecutionRecord::step(
                &key("summarise"),
                StepRecord::Failed(StepFailure::Refused(StepRefusal::PersonLacksAuthority))
            )));
        }
        assert!(matches!(
            run_with_view_delegation(&agent, holds_everything),
            AgentRunStart::Started(..)
        ));
    }

    /// Starts a tool-using step under a view delegation and the person's current rights.
    fn run_with_view_delegation(
        agent: &AgentIdentity<ResolvedTenant>,
        held: CapabilitySet,
    ) -> AgentRunStart<ResolvedTenant> {
        let mut execution = agent_execution(agent, TOOLS);
        let person = execution.acting_for().clone();
        let viewing = view_delegation(&person, agent);
        execution
            .start_agent_run(
                &key("summarise"),
                &RunAuthority::Delegation(&viewing),
                agent,
                &ActingAuthority::assumed(person, held),
            )
            .unwrap()
    }

    /// Lends the person's workflow-view permission to this agent for ten minutes.
    fn view_delegation(
        person: &Human,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> Delegation<ResolvedTenant> {
        let granted = CapabilitySet::new(
            vec![SystemPermission::Workflows(WorkflowAction::View)],
            Vec::new(),
        );
        let held = view_held_by(person, &granted);
        Delegation::grant(
            GrantDelegationParams {
                granted,
                constraints: DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
                name: None,
            },
            &held,
            &Delegate {
                agent,
                duty: ReviewDuty::NotReviewing,
            },
        )
        .unwrap()
    }

    /// Works out the view delegation ceiling from this person's standing rights.
    fn view_held_by(person: &Human, granted: &CapabilitySet) -> HeldBy {
        let control = AgentControl::new(assumed_authority(
            person,
            TenantId::new(),
            granted.http(),
            &[],
        ));
        HeldBy::worked_out::<ResolvedTenant>(
            &control,
            granted,
            &HeldResources::answered(person.principal(), Vec::new()),
            &[],
        )
        .unwrap()
    }

    /// A workflow starts an agent run, and the run announces "agent run
    /// started". The run and that event are marked with the execution's
    /// chain depth. A workflow triggered on it continues the chain, so the
    /// chain still ends.
    #[test]
    fn a_run_a_workflow_starts_marks_its_events_with_the_chain() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        let mut run = running_agent(&mut execution, &agent);
        run.announce_start(RunNames::new(
            EventLabel::of("order-summariser"),
            EventLabel::of("provider"),
        ));

        let started = crate::test_support::events::raised(&mut run);

        assert_eq!(
            run.origin(),
            EventOrigin::Execution(execution.chain_depth())
        );
        assert_eq!(
            started[0].origin(),
            EventOrigin::Execution(execution.chain_depth())
        );
    }

    /// Offering a different agent from the one named by the step fails the
    /// step because that agent may not act.
    #[test]
    fn an_agent_other_than_the_steps_may_not_run_it() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);

        let refused = refused_with(
            &mut execution,
            &RunAuthority::NoDelegation,
            &crate::domains::workflows::execution::tests::fixtures::agent(),
        );

        assert_eq!(refused, agent_may_not_act());
    }

    /// A suspended agent, a revoked one and one held until it attests again
    /// each try to run a step. Each step is refused on the record because
    /// the agent may not act.
    #[test]
    fn an_agent_that_may_not_act_right_now_does_not_run_a_step() {
        let mut suspended = agent();
        suspended.suspend(SuspendedBy::Monitor).unwrap();
        let mut revoked = agent();
        let revoker = revoked.owner().clone();
        revoked.revoke(&control_by(&revoker)).unwrap();
        let mut held = agent();
        let holder = held.owner().clone();
        held.require_reattestation(&control_by(&holder)).unwrap();

        for blocked in [suspended, revoked, held] {
            let mut execution = agent_execution(&blocked, &[]);
            let person = acting(execution.acting_for());
            let started = execution
                .start_agent_run(
                    &key("summarise"),
                    &RunAuthority::NoDelegation,
                    &blocked,
                    &person,
                )
                .unwrap();

            let AgentRunStart::Refused(records) = started else {
                panic!("a blocked agent started a run");
            };
            assert!(records.contains(&ExecutionRecord::step(
                &key("summarise"),
                StepRecord::Failed(StepFailure::Refused(StepRefusal::AgentMayNotAct))
            )));
            assert_eq!(state(&execution, "summarise"), agent_may_not_act());
        }
    }

    /// A run completes with "three orders are late". The step succeeds,
    /// and its output holds that text under `answer`.
    #[test]
    fn a_completed_run_hands_its_answer_on_under_answer() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        let mut run = running_agent(&mut execution, &agent);
        run.complete("three orders are late").unwrap();

        execution.settle_agent_run(&key("summarise"), &run).unwrap();

        let StepState::Succeeded { output, .. } = state(&execution, "summarise") else {
            panic!("the agent run step did not succeed");
        };
        assert_eq!(
            output.at(&path(ANSWER_FIELD)).map(FlowData::value),
            Some(FlowValue::Text("three orders are late"))
        );
    }

    /// A run fails. Its step fails with the reason reported, and the
    /// execution ends as failed.
    #[test]
    fn a_failed_run_fails_its_step_and_the_execution() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        let mut run = running_agent(&mut execution, &agent);
        run.fail();

        execution.settle_agent_run(&key("summarise"), &run).unwrap();

        assert!(matches!(
            state(&execution, "summarise"),
            StepState::Failed(StepFailure::Reported(_))
        ));
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
    }

    /// A run that is still going is reported to its step. That is refused
    /// as a wrong move, and the step keeps waiting.
    #[test]
    fn a_run_still_going_does_not_settle_its_step() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        let run = running_agent(&mut execution, &agent);

        let settled = execution.settle_agent_run(&key("summarise"), &run);

        assert!(matches!(settled, Err(DomainError::InvalidTransition(_))));
    }

    /// A completed agent run from another execution cannot settle this
    /// step. Reporting its answer is forbidden, and this step keeps running.
    #[test]
    fn another_run_does_not_settle_the_step() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        running_agent(&mut execution, &agent);
        let mut elsewhere = agent_execution(&agent, &[]);
        let mut other = running_agent(&mut elsewhere, &agent);
        other.complete("someone else's answer").unwrap();

        let settled = execution.settle_agent_run(&key("summarise"), &other);

        assert!(matches!(settled, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            state(&execution, "summarise"),
            StepState::Running { .. }
        ));
    }

    /// Ann cancels an execution while its agent run is still going. The run
    /// then completes. Its success is recorded, and the execution stays
    /// cancelled by Ann.
    #[test]
    fn a_run_left_behind_by_a_cancelled_execution_is_recorded_when_it_ends() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        let mut run = running_agent(&mut execution, &agent);
        execution.cancel(&managing(&ann())).unwrap();
        run.complete("done after all").unwrap();

        let records = execution.settle_agent_run(&key("summarise"), &run).unwrap();

        assert_eq!(
            records,
            vec![ExecutionRecord::step(
                &key("summarise"),
                StepRecord::Succeeded(crate::domains::workflows::design::node::Port::Next)
            )]
        );
        assert!(matches!(
            state(&execution, "summarise"),
            StepState::Succeeded { .. }
        ));
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Cancelled(ann().principal()))
        );
    }

    /// Ann cancels an execution while its agent run is still going. The
    /// execution gives one order to stop that run, in Ann's name. While it
    /// ran, it gave none.
    #[test]
    fn a_run_given_up_by_an_ended_execution_is_ordered_to_stop() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        let run = running_agent(&mut execution, &agent);
        let while_running = execution.abandoned_run_orders();

        execution.cancel(&managing(&ann())).unwrap();
        let orders = execution.abandoned_run_orders();

        assert!(while_running.is_empty());
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0].run_id(), run.id());
        assert_eq!(orders[0].by(), execution.acting_for());
    }

    /// Ann cancels an execution, and its run's late result is recorded
    /// after all. The run is no longer given up, so no order stops it.
    #[test]
    fn a_run_whose_late_result_was_recorded_gets_no_order() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        let mut run = running_agent(&mut execution, &agent);
        execution.cancel(&managing(&ann())).unwrap();
        run.complete("done after all").unwrap();

        execution.settle_agent_run(&key("summarise"), &run).unwrap();

        assert!(execution.abandoned_run_orders().is_empty());
    }

    /// A finished run is reported to its step twice, once in a running
    /// execution and once in a cancelled one. Each second report is
    /// refused, so the result is recorded once.
    #[test]
    fn a_run_reported_twice_is_recorded_once() {
        let agent = agent();
        let mut live = agent_execution(&agent, &[]);
        let mut run = running_agent(&mut live, &agent);
        run.complete("done").unwrap();
        live.settle_agent_run(&key("summarise"), &run).unwrap();
        let mut ended = agent_execution(&agent, &[]);
        let mut late_run = running_agent(&mut ended, &agent);
        ended.cancel(&managing(&ann())).unwrap();
        late_run.complete("done after all").unwrap();
        ended
            .settle_agent_run(&key("summarise"), &late_run)
            .unwrap();

        let again_live = live.settle_agent_run(&key("summarise"), &run);
        let again_late = ended.settle_agent_run(&key("summarise"), &late_run);

        assert!(matches!(again_live, Err(DomainError::InvalidTransition(_))));
        assert!(matches!(again_late, Err(DomainError::InvalidTransition(_))));
    }

    /// The nodes of a graph where `writer` proposes a fix and `checker`
    /// checks it, as the step `summarise`.
    fn fix_then_check(
        writer: &AgentIdentity<ResolvedTenant>,
        checker: &AgentIdentity<ResolvedTenant>,
    ) -> Vec<crate::domains::workflows::design::node::Node> {
        let proposing = agent_step(*writer.id(), &[]).kind().clone();
        let checking = AgentRunStep::new(AgentRunParams {
            agent_id: *checker.id(),
            checks: Checks::Step(key("fix")),
            ..stage_run()
        })
        .unwrap();
        vec![
            crate::domains::workflows::execution::tests::fixtures::node(
                "fix",
                proposing,
                crate::domains::workflows::design::node::Join::All,
            ),
            crate::domains::workflows::execution::tests::fixtures::node(
                "summarise",
                NodeKind::AgentRun(checking),
                crate::domains::workflows::design::node::Join::All,
            ),
        ]
    }

    /// The Triage bot proposes a fix; the Code reviewer, another agent,
    /// checks it and answers "NOT OK" with its reason. The check's run is
    /// asked for a verdict, and its step hands on `not_ok` and the reason
    /// beside the whole answer.
    #[test]
    fn a_checking_run_hands_on_its_verdict_and_notes() {
        let writer = agent();
        let checker = agent();
        let mut execution = after_proposed_fix(&writer, &checker);

        let mut check = running_agent(&mut execution, &checker);
        check.complete("NOT OK\nThe change has no test.").unwrap();
        execution
            .settle_agent_run(&key("summarise"), &check)
            .unwrap();

        assert!(
            check
                .goal()
                .as_str()
                .contains("Start your answer with one line")
        );
        let StepState::Succeeded { output, .. } = state(&execution, "summarise") else {
            panic!("the check did not succeed");
        };
        let text = |field: &str| output.at(&path(field)).map(FlowData::value);
        assert_eq!(text(VERDICT_FIELD), Some(FlowValue::Text("not_ok")));
        assert_eq!(
            text(NOTES_FIELD),
            Some(FlowValue::Text("The change has no test."))
        );
    }

    /// Finishes the writer's proposal, leaving the independent checker ready to run.
    fn after_proposed_fix(
        writer: &AgentIdentity<ResolvedTenant>,
        checker: &AgentIdentity<ResolvedTenant>,
    ) -> Execution {
        let mut execution = started(
            fix_then_check(writer, checker),
            vec![edge("fix", Port::Next, "summarise")],
        );
        let person = acting(execution.acting_for());
        let AgentRunStart::Started(mut fix, _) = execution
            .start_agent_run(&key("fix"), &RunAuthority::NoDelegation, writer, &person)
            .unwrap()
        else {
            panic!("the fix was refused");
        };
        fix.complete("change the timeout to 30s").unwrap();
        execution.settle_agent_run(&key("fix"), &fix).unwrap();
        execution
    }

    /// Publishing rejects a draft where an agent checks its own work and
    /// one where the checked step does not precede the checking step.
    #[test]
    fn a_check_of_the_same_agent_or_of_no_earlier_step_is_not_published() {
        let writer = agent();
        let checker = agent();
        let mut own = draft(
            fix_then_check(&writer, &writer),
            vec![edge("fix", Port::Next, "summarise")],
        );
        let mut unordered = draft(fix_then_check(&writer, &checker), Vec::new());

        let offered = [offered(append_row())];
        let own_published = publish_as(&mut own, &ann(), &offered, &SeesAll);
        let unordered_published = publish_as(&mut unordered, &ann(), &offered, &SeesAll);

        assert!(matches!(own_published, Err(DomainError::Validation(_))));
        assert!(matches!(
            unordered_published,
            Err(DomainError::Validation(_))
        ));
    }

    /// Constructing a checking step with a search-orders tool returns a
    /// validation error; checking steps cannot be given tools.
    #[test]
    fn a_checking_step_is_given_no_tool() {
        let given_a_tool = AgentRunStep::new(AgentRunParams {
            checks: Checks::Step(key("fix")),
            tools: vec![
                crate::domains::agents::execution::tool::ToolName::new("search_orders").unwrap(),
            ],
            ..stage_run()
        });

        assert!(matches!(given_a_tool, Err(DomainError::Validation(_))));
    }

    type HeldVersion = crate::domains::workflows::sandbox::version::SandboxVersion<ResolvedTenant>;

    /// The worker starts the agent `version` holds for the `reply` step.
    fn start_held(
        execution: &mut Execution,
        version: &HeldVersion,
        acting_agent: &AgentIdentity<ResolvedTenant>,
    ) -> Result<AgentRunStart<ResolvedTenant>, DomainError> {
        let person = acting(execution.acting_for());
        let backing = RunBacking {
            authority: &RunAuthority::NoDelegation,
            agent: acting_agent,
            acting: &person,
        };
        execution.start_held_agent(&key("reply"), version, &backing)
    }

    /// The run of the agent `version` holds, started for the `reply` step.
    fn held_run(
        execution: &mut Execution,
        version: &HeldVersion,
        acting_agent: &AgentIdentity<ResolvedTenant>,
    ) -> AgentRun<ResolvedTenant> {
        let Ok(AgentRunStart::Started(run, _)) = start_held(execution, version, acting_agent)
        else {
            panic!("the held agent was refused");
        };
        *run
    }

    /// An execution whose `reply` step names a version holding `agent`.
    fn replying(agent: &AgentIdentity<ResolvedTenant>) -> (Execution, HeldVersion) {
        let version = held_version(*agent.id());
        let step = held_code("reply", *version.id());
        (started(vec![step], Vec::new()), version)
    }

    /// Ann's code step names a version holding a reply drafter. A run of
    /// that agent starts, its answers held to the version's check with the
    /// version's two tries, and the step waits on it.
    #[test]
    fn a_version_holding_an_agent_starts_a_checked_run() {
        let agent = agent();
        let (mut execution, version) = replying(&agent);

        let run = held_run(&mut execution, &version, &agent);

        let tries = crate::domains::agents::execution::run::CheckTries::new(2).unwrap();
        assert_eq!(
            run.check(),
            RunCheck::Sandbox {
                version: *version.id(),
                tries
            }
        );
        assert!(matches!(
            state(&execution, "reply"),
            StepState::Running { underway: Underway::AgentRun(id), .. } if id == *run.id()
        ));
    }

    /// The step names one version. Another version holding the same agent
    /// is refused, and the step stays ready.
    #[test]
    fn a_version_the_step_does_not_name_is_refused() {
        let agent = agent();
        let (mut execution, _) = replying(&agent);
        let other = held_version(*agent.id());

        let refused = start_held(&mut execution, &other, &agent);

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert!(matches!(
            state(&execution, "reply"),
            StepState::Ready { .. }
        ));
    }

    /// The check passes the drafted reply. The step's output is the answer.
    #[test]
    fn an_answer_that_passed_its_check_is_the_steps_output() {
        let agent = agent();
        let (mut execution, version) = replying(&agent);
        let mut run = held_run(&mut execution, &version, &agent);
        run.record_answer("We are looking into it.").unwrap();
        run.record_check(crate::domains::agents::execution::run::CheckVerdict::Passed)
            .unwrap();

        execution.settle_agent_run(&key("reply"), &run).unwrap();

        let StepState::Succeeded { output, .. } = state(&execution, "reply") else {
            panic!("the step did not succeed");
        };
        assert_eq!(
            output.field(&FieldName::new(ANSWER_FIELD).unwrap()),
            Some(&FlowData::text("We are looking into it.").unwrap())
        );
    }

    /// The drafter promises a refund on both of its tries. The step fails,
    /// naming what the check said.
    #[test]
    fn an_answer_that_never_passed_fails_the_step_with_what_the_check_said() {
        let agent = agent();
        let (mut execution, version) = replying(&agent);
        let mut run = held_run(&mut execution, &version, &agent);
        for answer in ["Refund approved.", "Refund approved, really."] {
            run.record_answer(answer).unwrap();
            run.record_check(
                crate::domains::agents::execution::run::CheckVerdict::Broken(
                    UntrustedText::record("no promises of refunds"),
                ),
            )
            .unwrap();
        }

        execution.settle_agent_run(&key("reply"), &run).unwrap();

        let StepState::Failed(StepFailure::Reported(reason)) = state(&execution, "reply") else {
            panic!("the step did not fail as reported");
        };
        assert!(reason.as_str().contains("no promises of refunds"));
    }
}
