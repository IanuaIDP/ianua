//! How a run takes its steps: asking its model, recording tool calls, and
//! ending.

use crate::domains::agents::execution::model_provider::ModelProvider;
use crate::domains::agents::execution::run::call::{PendingCall, StepCall, StepOutcome, ToolCall};
use crate::domains::agents::execution::run::cancel::{CancelOrder, RunCancelled};
use crate::domains::agents::execution::run::check::RunCheck;
use crate::domains::agents::execution::run::gate::Admission;
use crate::domains::agents::execution::run::status::{NextCall, RunState, RunStatus};
use crate::domains::agents::execution::run::target::ResolvedCall;
use crate::domains::agents::execution::run::{AgentRun, RunStep};
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;

/// Whether the call being recorded is the approved one the run holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HeldCall {
    /// It is, and its approval still stands.
    Approved,
    /// It is, but its approval lapsed before the call was made.
    Lapsed,
    /// The run holds no approved call.
    None,
}

impl HeldCall {
    /// What the run's approved `held` call is now.
    fn of(held: &PendingCall) -> Self {
        if held.approval_lapsed_at(clock::now()) {
            return Self::Lapsed;
        }
        Self::Approved
    }
}

impl<T: TenantScope> AgentRun<T> {
    /// Refuses to ask `provider` for the run's next step.
    ///
    /// The app calls this before every model step. The model is sent all the
    /// run has read, as tool results. So it must be the run's own provider,
    /// still active, and cleared for the run's exposure. A run reads
    /// restricted HR data through a tool. Without this check, its next step
    /// sends that data to an outside model the tenant cleared for public
    /// data only.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `provider` is not the run's.
    /// - [`DomainError::Forbidden`] when `provider` is disabled.
    /// - [`DomainError::Forbidden`] when `provider` is cleared for less
    ///   sensitive data than the run has read.
    pub fn ensure_may_ask(&self, provider: &ModelProvider<T>) -> Result<(), DomainError> {
        if provider.id() != &self.provider_id {
            return Err(DomainError::forbidden(message!(
                "agents-the-run-reasons-with-another-model",
                "the run reasons with another model provider"
            )));
        }
        if !provider.is_active() {
            return Err(DomainError::forbidden(message!(
                "agents-the-run-s-model-provider-is",
                "the run's model provider is disabled"
            )));
        }
        if !self.may_send_to(provider.clearance()) {
            return Err(DomainError::forbidden(message!(
                "agents-the-run-has-read-data-and-2",
                format!(
                    "the run has read {} data and its model provider is cleared only for {} data",
                    self.exposure.as_str(),
                    provider.clearance().as_str()
                )
            )));
        }
        Ok(())
    }

    /// Records a call that ran, with its result.
    ///
    /// The call must pass [`Self::admit`] now, and `agent` must be the run's
    /// agent and free to act. A call that needs approval must be the call a
    /// person approved, made before the approval lapsed. The run's exposure
    /// rises to the tool's data class whatever came back. An error body is
    /// still the tool's data.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] for the wrong or inactive agent, a call
    /// refused by [`Self::admit`], or missing or expired approval.
    /// Returns [`DomainError::Conflict`] when another approved call is held first,
    /// or [`DomainError::InvalidTransition`] when the run is not running or has no
    /// steps left.
    pub fn record_allowed(
        &mut self,
        call: ResolvedCall<'_, T>,
        agent: &AgentIdentity<T>,
        result: impl Into<String>,
    ) -> Result<(), DomainError> {
        self.ensure_agent_may_act(agent)?;
        self.ensure_step_left()?;
        let admission = self.admit(&call)?;
        ensure_approved(admission, self.held_call(call.call())?)?;
        let read = call.tool().classification();
        self.push(
            StepCall::Tool(call.into_call()),
            StepOutcome::Allowed(result.into()),
            read,
        )?;
        self.state = RunState::Running(NextCall::Model);
        self.exposure = self.exposure.max(read);
        Ok(())
    }

    /// Records a tool call that was refused. When it is the approved call the
    /// run holds, that call is done with, even if its approval lapsed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the run holds another approved call
    ///   to deal with first.
    /// - [`DomainError::InvalidTransition`] when the run is not running.
    /// - [`DomainError::InvalidTransition`] when the run has no step left.
    pub fn record_denied(
        &mut self,
        call: ToolCall,
        reason: impl Into<String>,
    ) -> Result<(), DomainError> {
        self.ensure_step_left()?;
        self.held_call(&call)?;
        self.push(
            StepCall::Tool(call),
            StepOutcome::Denied(reason.into()),
            DataClassLevel::Public,
        )?;
        self.state = RunState::Running(NextCall::Model);
        Ok(())
    }

    /// Whether `call` is the approved call the run holds. Any other call
    /// waits until that one is made or refused.
    pub(super) fn held_call(&self, call: &ToolCall) -> Result<HeldCall, DomainError> {
        match &self.state {
            RunState::Running(NextCall::Approved(held)) if held.call() == call => {
                Ok(HeldCall::of(held))
            }
            RunState::Running(NextCall::Approved(_)) => Err(DomainError::conflict(message!(
                "agents-the-run-must-first-settle-the",
                "the run must first settle the call a person approved"
            ))),
            RunState::Running(NextCall::Model)
            | RunState::AwaitingApproval(_)
            | RunState::Paused(_)
            | RunState::Completed
            | RunState::Failed
            | RunState::Cancelled
            | RunState::Halted
            | RunState::OverBudget => Ok(HeldCall::None),
        }
    }

    /// Refuses an agent other than the run's, or one that may not act now.
    ///
    /// Ann's agent is suspended in an incident while its run is under way.
    /// Without this check, the run carries on calling tools with the
    /// authority its agent just lost.
    pub(super) fn ensure_agent_may_act(&self, agent: &AgentIdentity<T>) -> Result<(), DomainError> {
        if agent.id() != &self.agent_id {
            return Err(DomainError::forbidden(message!(
                "agents-the-agent-given-is-not-the",
                "the agent given is not the run's agent"
            )));
        }
        if !agent.may_act_at(clock::now()) {
            return Err(DomainError::forbidden(message!(
                "agents-the-run-s-agent-may-not",
                "the run's agent may not act: it is suspended, revoked or must re-attest"
            )));
        }
        Ok(())
    }

    /// Refuses another tool call once the run has taken every step it was
    /// allowed.
    ///
    /// Only the agent's own calls are checked against the limit. A person
    /// denying a paused call, or the run ending, is always recorded.
    pub(super) fn ensure_step_left(&self) -> Result<(), DomainError> {
        if self.steps_taken() >= self.max_steps {
            return Err(DomainError::invalid_transition(message!(
                "agents-the-run-has-taken-every-step",
                "the run has taken every step it was allowed"
            )));
        }
        Ok(())
    }

    /// Records the final answer and completes the run.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the run is not running, or
    ///   is held to a check, which completes it only once its check passes.
    pub fn complete(&mut self, answer: impl Into<String>) -> Result<(), DomainError> {
        if self.check != RunCheck::Unchecked {
            return Err(DomainError::invalid_transition(message!(
                "agents-a-checked-run-completes-through-its-check",
                "a run held to a check completes only once its check passes"
            )));
        }
        self.push(
            StepCall::Model,
            StepOutcome::Answered(answer.into()),
            DataClassLevel::Public,
        )?;
        self.status().try_transition(RunStatus::Completed)?;
        self.state = RunState::Completed;
        self.touch();
        Ok(())
    }

    /// Fails the run, at the step limit or on an error.
    ///
    /// Does nothing once the run has ended.
    pub fn fail(&mut self) {
        self.settle(RunState::Failed);
    }

    /// A person's order to stop the run, checked now, for the worker driving
    /// the run to apply with [`cancel`](Self::cancel).
    ///
    /// The person who started it may, and so may the agent's owner or
    /// someone allowed to change agents. Sam cannot stop Ann's runs. An
    /// order for a run that has ended is still given, and changes nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `agent` is not the run's agent.
    /// - [`DomainError::Forbidden`] when the person neither started the run
    ///   nor may change the agent.
    pub fn order_cancel(
        &self,
        by: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
    ) -> Result<CancelOrder, DomainError> {
        if agent.id() != &self.agent_id {
            return Err(DomainError::forbidden(message!(
                "agents-the-agent-is-not-the-run",
                "the agent is not the run's agent"
            )));
        }
        if !self.started_by.is(by.by()) {
            by.ensure_may(agent.owner(), AgentAction::Update)?;
        }
        Ok(CancelOrder::new(self.id, by.by().clone()))
    }

    /// Cancels the run on `order`, and gives back the proof its pending
    /// approvals are withdrawn on.
    ///
    /// The person's say was checked when they gave the order, so the worker
    /// needs none. A run that ended another way first keeps how it ended,
    /// and gives back no proof. A run already cancelled gives the proof
    /// again, so a worker that stopped halfway can finish withdrawing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `order` is for another run.
    pub fn cancel(&mut self, order: &CancelOrder) -> Result<Option<RunCancelled>, DomainError> {
        if order.run_id() != &self.id {
            return Err(DomainError::forbidden(message!(
                "agents-the-cancel-order-is-for-another",
                "the cancel order is for another run"
            )));
        }
        self.settle(RunState::Cancelled);
        if self.status() != RunStatus::Cancelled {
            return Ok(None);
        }
        Ok(Some(RunCancelled::of(order)))
    }

    /// Halts the run because the acting agent may not act.
    ///
    /// Does nothing once the run has ended.
    pub fn halt(&mut self) {
        self.settle(RunState::Halted);
    }

    /// Ends the run in `to`, unless it has already ended.
    ///
    /// The run loop, an operator's cancel and the agent status check can all
    /// end a run at about the same time. A run completes, then a late cancel
    /// arrives. The run stays completed, because that is how it really ended.
    fn settle(&mut self, to: RunState) {
        if self.status().try_transition(to.status()).is_err() {
            return;
        }
        self.state = to;
        self.touch();
    }

    /// Adds a step that brought `read` into the run.
    pub(super) fn push(
        &mut self,
        call: StepCall,
        outcome: StepOutcome,
        read: DataClassLevel,
    ) -> Result<(), DomainError> {
        if self.status() != RunStatus::Running {
            return Err(DomainError::invalid_transition(message!(
                "agents-cannot-add-a-step-to-a",
                "cannot add a step to a finished run"
            )));
        }
        let seq = self.next_step();
        self.touch();
        self.steps.push(RunStep {
            seq,
            call,
            outcome,
            read,
            at: self.updated_at,
        });
        Ok(())
    }
}

/// Refuses a call that needs an approval it does not have.
fn ensure_approved(admission: Admission, held: HeldCall) -> Result<(), DomainError> {
    match (admission, held) {
        (_, HeldCall::Lapsed) => Err(DomainError::forbidden(message!(
            "agents-the-approval-for-this-call-lapsed",
            "the approval for this call lapsed before the call was made"
        ))),
        (Admission::NeedsApproval, HeldCall::None) => Err(DomainError::forbidden(message!(
            "agents-this-call-needs-a-person-s",
            "this call needs a person's approval before it runs"
        ))),
        (Admission::Proceed, HeldCall::None) | (_, HeldCall::Approved) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use crate::domains::agents::execution::run::tests::fixtures::{
        agent, call, calling, params, provider, run, started, tool,
    };
    use crate::domains::agents::execution::run::{CallRefusal, ResolvedCall, StartRunParams};
    use crate::domains::agents::execution::tool::tests::fixtures::{MANAGE, holding, person};
    use crate::domains::agents::execution::tool::{PathValue, PathValues};
    use crate::domains::agents::identity::agent::SuspendedBy;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::shared::errors::DomainError;

    /// Suspending a run's agent forbids recording an allowed tool call or
    /// awaiting approval for another call, leaving the step list empty.
    #[test]
    fn a_run_whose_agent_was_suspended_makes_no_more_calls() {
        let (mut r, mut agent) = run(5);
        agent.suspend(SuspendedBy::Monitor).unwrap();

        let call = r.record_allowed(calling(&tool("get_order"), "{}"), &agent, "ok");
        let pause = r.await_approval(calling(&tool("delete_order"), "{}"), &agent);

        assert!(matches!(call, Err(DomainError::Forbidden(_))));
        assert!(matches!(pause, Err(DomainError::Forbidden(_))));
        assert!(r.steps().is_empty());
    }

    /// Recording a call with another active agent is forbidden because that
    /// identity does not own the run.
    #[test]
    fn a_call_recorded_with_another_agent_is_refused() {
        let (mut r, _) = run(5);
        let other = agent();

        let result = r.record_allowed(calling(&tool("get_order"), "{}"), &other, "ok");

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A run on a provider cleared for internal data has read only public
    /// data. It may ask that provider.
    #[test]
    fn a_run_may_ask_its_active_provider_cleared_for_what_it_read() {
        let model = provider(DataClassLevel::Internal);
        let (r, _) = started(StartRunParams {
            provider_id: *model.id(),
            ..params(5)
        });

        assert!(r.ensure_may_ask(&model).is_ok());
    }

    /// After reading salary data, a run cannot ask its model provider when
    /// that provider is cleared only for internal data.
    #[test]
    fn a_run_does_not_ask_a_model_cleared_below_what_it_read() {
        let model = provider(DataClassLevel::Internal);
        let (mut r, agent) = started(StartRunParams {
            provider_id: *model.id(),
            ..params(5)
        });
        r.record_allowed(calling(&tool("get_salary"), "{}"), &agent, "{}")
            .unwrap();

        assert!(matches!(
            r.ensure_may_ask(&model),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Disabling a provider prevents a run already using it from asking it again.
    #[test]
    fn a_run_does_not_ask_a_disabled_provider() {
        let bob = person("bob@corp.test");
        let mut model = provider(DataClassLevel::Restricted);
        let (r, _) = started(StartRunParams {
            provider_id: *model.id(),
            ..params(5)
        });
        model.disable(&holding(&bob, &MANAGE)).unwrap();

        assert!(matches!(
            r.ensure_may_ask(&model),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A run cannot ask a different provider even when it has restricted clearance.
    #[test]
    fn a_run_does_not_ask_a_provider_it_was_not_started_on() {
        let (r, _) = run(5);

        assert!(matches!(
            r.ensure_may_ask(&provider(DataClassLevel::Restricted)),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Filling an item placeholder with `admin` produces an admin action;
    /// the resolved call is refused as outside a read/write/delete purpose.
    #[test]
    fn a_call_is_classed_by_the_path_it_goes_to() {
        let (r, _) = run(5);
        let get_item = tool("get_item");
        let to_admin = PathValues::new().with("kind", PathValue::new("admin").unwrap());
        let resolved = ResolvedCall::resolve(call("get_item", "{}"), &get_item, &to_admin).unwrap();

        assert_eq!(resolved.target().as_str(), "/items/admin");
        assert_eq!(r.admit(&resolved), Err(CallRefusal::OutsidePurpose));
    }

    /// A call to `/items/{kind}` that gives no `kind` is refused before any
    /// other check, not sent with the template as written.
    #[test]
    fn a_call_that_leaves_its_path_unfilled_is_refused() {
        let get_item = tool("get_item");

        let result = ResolvedCall::resolve(call("get_item", "{}"), &get_item, &PathValues::new());

        assert!(matches!(result, Err(CallRefusal::UnfilledPath)));
    }
}
