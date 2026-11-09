//! How a run pauses on a call until a person decides, and resumes: on an
//! approval, a denial, a reply in words, or a revised call.

use crate::domains::agents::events::steering::RunSteering;
use crate::domains::agents::execution::run::AgentRun;
use crate::domains::agents::execution::run::call::{
    CallApproval, CallReply, DeniedCall, PendingCall, PendingCallRef, ReleasedCall, RevisedCall,
    StepCall, StepOutcome,
};
use crate::domains::agents::execution::run::status::{NextCall, RunState, RunStatus};
use crate::domains::agents::execution::run::target::ResolvedCall;
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;

/// Why a run failed on a call no person could be asked about.
const APPROVAL_LIMIT_REACHED: &str =
    "approval limit reached: the plan allows no more open approval requests";

impl<T: TenantScope> AgentRun<T> {
    /// Pauses the run, holding `call` until a person decides.
    ///
    /// Only a call [`Self::admit`] allows is shown to a person, and only
    /// while the run's agent may act. The held call names the step it paused
    /// at, so an approval names this pause and no other.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `agent` is not the run's agent, or
    ///   may not act.
    /// - [`DomainError::Forbidden`] when [`Self::admit`] refuses the call.
    /// - [`DomainError::Conflict`] when the run holds another approved call
    ///   to make first.
    /// - [`DomainError::InvalidTransition`] when the run is not running.
    /// - [`DomainError::InvalidTransition`] when the run has no step left.
    pub fn await_approval(
        &mut self,
        call: ResolvedCall<'_, T>,
        agent: &AgentIdentity<T>,
    ) -> Result<(), DomainError> {
        self.ensure_agent_may_act(agent)?;
        if self.status() != RunStatus::Running {
            return Err(DomainError::invalid_transition(message!(
                "agents-only-a-running-run-can-pause",
                "only a running run can pause for approval"
            )));
        }
        self.ensure_step_left()?;
        self.admit(&call)?;
        self.held_call(call.call())?;
        self.status().try_transition(RunStatus::AwaitingApproval)?;
        let class = call.class();
        self.state = RunState::AwaitingApproval(PendingCall {
            call: call.into_call(),
            class,
            at_step: self.next_step(),
            approved: CallApproval::Awaiting,
        });
        self.touch();
        Ok(())
    }

    /// Resumes the run on `released`, so its next step makes the held call.
    ///
    /// `released` proves an approval request this run raised granted the
    /// exact call it holds, at this pause. The run takes the approval now.
    /// The call must be made within
    /// `APPROVED_CALL_WINDOW` of it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the proof is for another run.
    /// - [`DomainError::InvalidTransition`] when the run is not awaiting
    ///   approval.
    /// - [`DomainError::Conflict`] when the held call changed since the
    ///   approver saw it, or the approval was for an earlier pause.
    pub fn approve_pending(&mut self, released: &ReleasedCall) -> Result<(), DomainError> {
        if released.run_id() != &self.id {
            return Err(DomainError::forbidden(message!(
                "agents-the-approval-was-granted-for-another",
                "the approval was granted for another run"
            )));
        }
        let RunState::AwaitingApproval(pending) = &self.state else {
            return Err(DomainError::invalid_transition(message!(
                "agents-run-is-not-awaiting-approval",
                "run is not awaiting approval"
            )));
        };
        if !released.call().matches(pending) {
            return Err(DomainError::conflict(message!(
                "agents-the-pending-call-changed-since-it",
                "the pending call changed since it was reviewed"
            )));
        }
        let approved = PendingCall {
            approved: CallApproval::Approved(clock::now()),
            ..pending.clone()
        };
        self.status().try_transition(RunStatus::Running)?;
        self.state = RunState::Running(NextCall::Approved(approved));
        self.touch();
        Ok(())
    }

    /// Resumes the run after dropping the denied call and recording its refusal as a step.
    /// The model sees the refusal and can choose another action.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another run's proof;
    /// [`DomainError::InvalidTransition`] unless awaiting approval;
    /// [`DomainError::Conflict`] if the proof names another held call.
    pub fn deny_pending(
        &mut self,
        denied: &DeniedCall,
        reason: impl Into<String>,
    ) -> Result<(), DomainError> {
        self.drop_pending(denied, StepOutcome::Denied(reason.into()))
    }

    /// Fails the run on the call it would hold, because no person can be
    /// asked about it: the tenant's plan allows no more open approval
    /// requests. The call is recorded as refused with
    /// [`APPROVAL_LIMIT_REACHED`], so whoever reads the run sees why it
    /// stopped, and the run ends failed rather than waiting on a request
    /// nobody could raise.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the run is not awaiting
    ///   approval.
    pub fn fail_at_approval_limit(&mut self) -> Result<(), DomainError> {
        let RunState::AwaitingApproval(pending) = &self.state else {
            return Err(DomainError::invalid_transition(message!(
                "agents-run-is-not-awaiting-approval",
                "run is not awaiting approval"
            )));
        };
        let pending = pending.clone();
        self.status().try_transition(RunStatus::Running)?;
        self.state = RunState::Running(NextCall::Model);
        self.push(
            StepCall::Tool(pending.call),
            StepOutcome::Denied(APPROVAL_LIMIT_REACHED.to_owned()),
            DataClassLevel::Public,
        )?;
        self.fail();
        Ok(())
    }

    /// Drops the denied call and records the person's `reply` for the model to read next.
    /// A written reply refuses the call; only approval releases it.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another run's proof;
    /// [`DomainError::InvalidTransition`] unless awaiting approval;
    /// [`DomainError::Conflict`] if the proof names another held call.
    pub fn reply_to_pending(
        &mut self,
        denied: &DeniedCall,
        reply: CallReply,
    ) -> Result<(), DomainError> {
        self.drop_pending(denied, StepOutcome::Replied(reply.into_text()))
    }

    /// Replaces the arguments of the call the run holds with those of
    /// `revised`, as the person `editor` wrote them.
    ///
    /// The run keeps waiting on the revised call, at the same pause, and
    /// gives back the proof the request opened for the old call is
    /// withdrawn on. A new request is opened for the revised call. So an
    /// edit approves nothing by itself, and a high-risk call still needs
    /// two people.
    ///
    /// Only a person allowed to approve agent actions, and cleared for what
    /// the run read, edits a held call. The revised call must call the same
    /// tool, pass every check the run makes, and take the same class of
    /// action. Ann's run holds `read_order(id=1)`. Without the class check,
    /// an edit turns it into a delete under an approval rule meant for
    /// reads.
    ///
    /// Raises `agents.held_call_revised`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `agent` is not the run's agent, or
    ///   may not act.
    /// - [`DomainError::Forbidden`] when `editor` may not approve agent
    ///   actions, or is cleared below what the run read.
    /// - [`DomainError::Forbidden`] when [`Self::admit`] refuses the revised
    ///   call.
    /// - [`DomainError::InvalidTransition`] when the run is not awaiting
    ///   approval.
    /// - [`DomainError::Conflict`] when the revised call names another tool,
    ///   takes another class of action, or changes nothing.
    pub fn revise_pending(
        &mut self,
        editor: &AgentControl<'_>,
        revised: ResolvedCall<'_, T>,
        agent: &AgentIdentity<T>,
    ) -> Result<RevisedCall, DomainError> {
        self.ensure_agent_may_act(agent)?;
        self.ensure_may_edit(editor)?;
        let RunState::AwaitingApproval(pending) = &self.state else {
            return Err(DomainError::invalid_transition(message!(
                "agents-run-is-not-awaiting-approval",
                "run is not awaiting approval"
            )));
        };
        ensure_revises(pending, &revised)?;
        self.admit(&revised)?;
        let previous = PendingCallRef::of(pending);
        let at_step = pending.at_step;
        self.state = RunState::AwaitingApproval(PendingCall {
            class: revised.class(),
            call: revised.into_call(),
            at_step,
            approved: CallApproval::Awaiting,
        });
        self.record_steering(editor.by(), agent, RunSteering::CallRevised);
        Ok(RevisedCall::new(self.id, previous, editor.by().clone()))
    }

    /// Refuses an editor who may not approve agent actions, or is cleared
    /// below what the run read. A run at confidential holds a call quoting
    /// salaries. Without the clearance check, Sam, cleared for public data,
    /// reads them while he edits.
    fn ensure_may_edit(&self, editor: &AgentControl<'_>) -> Result<(), DomainError> {
        if !editor.holds_agent(AgentAction::Approve) {
            return Err(DomainError::forbidden(message!(
                "agents-editing-a-held-call-needs-the",
                "editing a held call needs the permission to approve agent actions"
            )));
        }
        if editor.authority().data_clearance() < self.exposure {
            return Err(DomainError::forbidden(message!(
                "agents-the-editor-is-not-cleared-for",
                "the editor is not cleared for the data the run read"
            )));
        }
        Ok(())
    }

    /// Drops the held call on `denied` and records it as a step with
    /// `outcome`, then resumes the run.
    fn drop_pending(
        &mut self,
        denied: &DeniedCall,
        outcome: StepOutcome,
    ) -> Result<(), DomainError> {
        if denied.run_id() != &self.id {
            return Err(DomainError::forbidden(message!(
                "agents-the-denial-was-made-for-another-2",
                "the denial was made for another run"
            )));
        }
        let RunState::AwaitingApproval(pending) = &self.state else {
            return Err(DomainError::invalid_transition(message!(
                "agents-run-is-not-awaiting-approval",
                "run is not awaiting approval"
            )));
        };
        if !denied.call().matches(pending) {
            return Err(DomainError::conflict(message!(
                "agents-the-denial-was-made-for-another",
                "the denial was made for another call than the one held"
            )));
        }
        let pending = pending.clone();
        self.status().try_transition(RunStatus::Running)?;
        self.state = RunState::Running(NextCall::Model);
        self.push(
            StepCall::Tool(pending.call),
            outcome,
            DataClassLevel::Public,
        )?;
        Ok(())
    }
}

/// Refuses a revised call that names another tool than the held one, takes
/// another class of action, or changes nothing.
fn ensure_revises<T: TenantScope>(
    held: &PendingCall,
    revised: &ResolvedCall<'_, T>,
) -> Result<(), DomainError> {
    if revised.call().tool() != held.tool() {
        return Err(DomainError::conflict(message!(
            "agents-an-edit-changes-the-call-s",
            "an edit changes the call's arguments, never its tool"
        )));
    }
    if revised.class() != held.class() {
        return Err(DomainError::conflict(message!(
            "agents-an-edit-may-not-change-the",
            "an edit may not change the class of action the call takes"
        )));
    }
    if revised.call() == held.call() {
        return Err(DomainError::conflict(message!(
            "agents-the-edit-changes-nothing",
            "the edit changes nothing"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::domains::agents::execution::run::pause::APPROVAL_LIMIT_REACHED;
    use crate::domains::agents::execution::run::tests::fixtures::{
        calling, denied, params, run, started, tool,
    };
    use crate::domains::agents::execution::run::{
        CallReply, PendingCallRef, RunStatus, StartRunParams, StepOutcome,
    };
    use crate::domains::agents::execution::tool::tests::fixtures::{holding, person, registered};
    use crate::domains::agents::execution::tool::{ToolMethod, ToolName};
    use crate::domains::authorization::permission::{
        AgentAction, DataAccessAction, SystemPermission,
    };
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::shared::errors::DomainError;
    use crate::test_support::events::raised_names;
    use crate::types::DeclaredAction;

    /// What Bob holds: the right to approve agent actions.
    const APPROVE: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::Approve)];

    /// What Carl holds: the right to approve, and clearance for confidential
    /// data.
    const APPROVE_CONFIDENTIAL: [SystemPermission; 2] = [
        SystemPermission::Agents(AgentAction::Approve),
        SystemPermission::Data(DataAccessAction::Confidential),
    ];

    /// Bob changes the held `delete_order` call from order 1 to order 2. The
    /// run still waits, now on the revised call at the same pause, and hands
    /// back the call as it was so its old request is withdrawn.
    #[test]
    fn an_approver_revises_the_arguments_of_a_held_call() {
        let (mut r, agent) = run(5);
        let delete = tool("delete_order");
        r.await_approval(calling(&delete, "{\"id\":1}"), &agent)
            .unwrap();
        let before = PendingCallRef::of(r.pending().unwrap());
        raised_names(&mut r);
        let bob = person("bob@corp.test");

        let revised = r
            .revise_pending(
                &holding(&bob, &APPROVE),
                calling(&delete, "{\"id\":2}"),
                &agent,
            )
            .unwrap();

        assert_eq!(r.status(), RunStatus::AwaitingApproval);
        assert_eq!(r.pending().unwrap().arguments(), "{\"id\":2}");
        assert_eq!(r.pending().unwrap().at_step(), before.at_step());
        assert_eq!(revised.previous(), &before);
        assert_eq!(raised_names(&mut r), ["agents.held_call_revised"]);
    }

    /// A person without approval rights cannot revise a held delete to target
    /// every order; the original arguments remain held.
    #[test]
    fn a_person_who_may_not_approve_cannot_revise_a_held_call() {
        let (mut r, agent) = run(5);
        let delete = tool("delete_order");
        r.await_approval(calling(&delete, "{\"id\":1}"), &agent)
            .unwrap();
        let sam = person("sam@corp.test");

        let result = r.revise_pending(
            &holding(&sam, &[]),
            calling(&delete, "{\"id\":\"all\"}"),
            &agent,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(r.pending().unwrap().arguments(), "{\"id\":1}");
    }

    /// Editing a confidential run's held call requires matching clearance:
    /// an internal-data approver is refused and a confidential-data approver succeeds.
    #[test]
    fn an_editor_must_be_cleared_for_what_the_run_read() {
        let (mut r, agent) = started(StartRunParams {
            exposure: DataClassLevel::Confidential,
            granted_tools: vec![ToolName::new("delete_salary").unwrap()],
            ..params(5)
        });
        let delete = registered(
            "delete_salary",
            ToolMethod::Delete,
            "/salaries/{id}",
            DeclaredAction::Undeclared,
            DataClassLevel::Confidential,
        );
        r.await_approval(calling(&delete, "{\"id\":1}"), &agent)
            .unwrap();
        let (bob, carl) = (person("bob@corp.test"), person("carl@corp.test"));

        let by_bob = r.revise_pending(
            &holding(&bob, &APPROVE),
            calling(&delete, "{\"id\":2}"),
            &agent,
        );
        let by_carl = r.revise_pending(
            &holding(&carl, &APPROVE_CONFIDENTIAL),
            calling(&delete, "{\"id\":2}"),
            &agent,
        );

        assert!(matches!(by_bob, Err(DomainError::Forbidden(_))));
        assert!(by_carl.is_ok());
    }

    /// A revision cannot switch the held read to a different tool or repeat
    /// the unchanged call; both attempts return conflicts.
    #[test]
    fn a_revision_keeps_the_tool_and_changes_something() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("read_order"), "{\"id\":1}"), &agent)
            .unwrap();
        let bob = person("bob@corp.test");

        let other_tool = r.revise_pending(
            &holding(&bob, &APPROVE),
            calling(&tool("delete_order"), "{\"id\":1}"),
            &agent,
        );
        let unchanged = r.revise_pending(
            &holding(&bob, &APPROVE),
            calling(&tool("read_order"), "{\"id\":1}"),
            &agent,
        );

        assert!(matches!(other_tool, Err(DomainError::Conflict(_))));
        assert!(matches!(unchanged, Err(DomainError::Conflict(_))));
    }

    /// A run that waits on nobody has no call to revise.
    #[test]
    fn a_run_not_awaiting_approval_has_no_call_to_revise() {
        let (mut r, agent) = run(5);
        let bob = person("bob@corp.test");

        let result = r.revise_pending(
            &holding(&bob, &APPROVE),
            calling(&tool("delete_order"), "{\"id\":1}"),
            &agent,
        );

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// Bob answers a held `delete_order` with "archive it instead". The
    /// call is dropped, the reply is the step the model reads next, and the
    /// run goes on.
    #[test]
    fn a_reply_in_words_drops_the_call_and_tells_the_model() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();

        r.reply_to_pending(
            &denied(&r, "delete_order", "{\"id\":1}"),
            CallReply::new("archive it instead").unwrap(),
        )
        .unwrap();

        assert_eq!(r.status(), RunStatus::Running);
        assert!(r.pending().is_none());
        assert_eq!(
            r.steps()[0].outcome(),
            &StepOutcome::Replied("archive it instead".to_owned())
        );
    }

    /// The run would hold `delete_order` for a person, but the plan allows
    /// no more open approval requests. The run fails, holding nothing, and
    /// its last step refuses the call with the reason.
    #[test]
    fn a_run_at_the_approval_limit_fails_with_the_reason_on_its_step() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();

        r.fail_at_approval_limit().unwrap();

        assert_eq!(r.status(), RunStatus::Failed);
        assert!(r.pending().is_none());
        assert_eq!(
            r.steps()[0].outcome(),
            &StepOutcome::Denied(APPROVAL_LIMIT_REACHED.to_owned())
        );
    }

    /// A run that waits on nobody has no call to fail at the limit.
    #[test]
    fn a_run_not_awaiting_approval_does_not_fail_at_the_limit() {
        let (mut r, _) = run(5);

        let result = r.fail_at_approval_limit();

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert_eq!(r.status(), RunStatus::Running);
    }

    /// A reply denying different call arguments is refused, leaving the run
    /// awaiting approval of its actual held call.
    #[test]
    fn a_reply_for_another_call_is_refused() {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();

        let result = r.reply_to_pending(
            &denied(&r, "delete_order", "{\"id\":9}"),
            CallReply::new("no").unwrap(),
        );

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(r.status(), RunStatus::AwaitingApproval);
    }

    /// A blank reply, and one over four thousand characters, are refused.
    #[test]
    fn a_reply_says_something_and_stays_short() {
        assert!(CallReply::new("   ").is_err());
        assert!(CallReply::new("x".repeat(4001)).is_err());
        assert!(CallReply::new("line one\nline two").is_ok());
    }
}
