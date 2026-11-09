//! Approval steps: people sign off before the workflow goes on.
//!
//! They keep the same rules as an agent's approval:
//! - the person the execution acts for may not approve,
//! - an action that may be high-risk needs two different people, each
//!   present with a fresh second factor, and neither an author of the
//!   workflow,
//! - each approval is for the exact data the approver was shown,
//! - nobody may approve once the decision window has closed.

use time::{Duration, OffsetDateTime};

use crate::domains::agents::oversight::approval::Presence;
use crate::domains::workflows::control::StepApprover;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::design::node::{NodeKey, NodeKind, WorkflowApprovalStep};
use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::progress::no_output;
use crate::domains::workflows::execution::record::{ExecutionRecord, StepRecord};
use crate::domains::workflows::execution::step::{
    ApprovalHold, ApprovalWait, ApprovedBy, FirstApproval, Holding, StepFailure, StepState,
    Underway,
};
use crate::domains::workflows::execution::steps::work::RunningStep;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Human;

/// How long an approval still holds after it is given, however late in its
/// window. So the step after it has time to act on it.
pub(in crate::domains::workflows::execution) const ACT_ON_APPROVAL: Duration =
    Duration::minutes(15);

impl<T: TenantScope> WorkflowExecution<T> {
    /// Asks people to approve the ready approval step `key`, within its
    /// decision window.
    ///
    /// Each person asked is shown its
    /// [`approval_input`](Self::approval_input) and approves that.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not ready.
    /// - [`DomainError::InvalidTransition`] when the execution has ended.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    /// - [`DomainError::Validation`] when it is not an approval step.
    pub fn request_approval(&mut self, key: &NodeKey) -> Result<Vec<ExecutionRecord>, DomainError> {
        let ready = self.ready_step(key)?;
        let NodeKind::Approval(step) = ready.node.kind() else {
            return Err(DomainError::invalid(message!(
                "workflows-this-step-does-not-ask-for",
                "this step does not ask for approval"
            )));
        };
        let now = crate::shared::clock::now();
        let wait = ApprovalWait {
            closes_at: now.saturating_add(step.window().duration()),
            first: FirstApproval::NotGiven,
        };
        Ok(self.begin_step(ready, Underway::Approval(wait), now))
    }

    /// The data the approval step `key` would let through, to show the
    /// people asked to approve it.
    ///
    /// It is the trigger's data and the output of every step before it.
    /// The steps after the approval read only from it. So approvers see the
    /// amount and the payee, not just the step's label.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not waiting
    ///   for approval.
    /// - [`DomainError::InvalidTransition`] when the execution has ended.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    pub fn approval_input(&self, key: &NodeKey) -> Result<FlowData, DomainError> {
        let running = self.running_step(key)?;
        let Underway::Approval(_) = running.underway else {
            return Err(DomainError::invalid_transition(message!(
                "workflows-this-step-is-not-waiting-for",
                "this step is not waiting for approval"
            )));
        };
        self.input_seen_by(&running.seen)
    }

    /// Shows the approval's outgoing data only after checking decision rights and clearance.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without approval rights or sufficient clearance.
    /// [`DomainError::NotFound`] for a missing step.
    /// [`DomainError::InvalidTransition`] unless waiting for approval in a live execution.
    /// [`DomainError::Conflict`] if the execution timed out.
    pub fn shown_to(
        &self,
        key: &NodeKey,
        approver: &StepApprover<'_>,
    ) -> Result<FlowData, DomainError> {
        let running = self.running_step(key)?;
        approver.ensure_entitled(running.exposure)?;
        self.approval_input(key)
    }

    /// `by` approves the approval step `key`, having been shown `shown`.
    ///
    /// `shown` is the [`approval_input`](Self::approval_input) the approver
    /// saw. The approval counts only for that data. When the step needs two
    /// approvers and this is the first, it keeps waiting for a second,
    /// different person. Otherwise the workflow goes on.
    ///
    /// The approver must hold the workflow approve right and be cleared for
    /// the data the step shows. When [`WorkflowApprovalStep::needs_presence`] says
    /// so, they must have proved they are present just now, so a stolen
    /// session cannot approve a payment.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::NotFound`] for an absent step; [`DomainError::InvalidTransition`]
    /// unless awaiting an open decision or if ended; or [`DomainError::Conflict`] for timeout or changed shown data.
    /// Returns [`DomainError::Forbidden`] without approval rights, clearance or high-risk presence,
    /// or for the person acted for, the first approver, or (when two are needed) an author.
    /// These person checks apply across all their accounts.
    pub fn approve(
        &mut self,
        key: &NodeKey,
        approver: &StepApprover<'_>,
        shown: &FlowData,
    ) -> Result<Vec<ExecutionRecord>, DomainError> {
        let (running, wait, step) = self.open_approval(key)?;
        approver.ensure_entitled(running.exposure)?;
        ensure_present_when_needed(&step, approver)?;
        let by = approver.by();
        self.ensure_may_approve(by, &step, &wait)?;
        if self.input_seen_by(&running.seen)? != *shown {
            return Err(DomainError::conflict(message!(
                "workflows-the-approver-was-shown-data-other",
                "the approver was shown data other than what this step lets through"
            )));
        }
        let mut records = vec![ExecutionRecord::step(
            key,
            StepRecord::ApprovalGranted(by.principal()),
        )];
        if step.approvers_needed() == 2 && wait.first == FirstApproval::NotGiven {
            self.await_second(running, &wait, by);
            return Ok(records);
        }
        let hold = self.approval_hold(wait.first.completed_by(by), wait.closes_at);
        records.extend(self.succeed(
            running.index,
            no_output(),
            running.exposure,
            Holding::Approved(hold),
        ));
        Ok(records)
    }

    /// Refuses `by` as an approver of `step` when they are the person the
    /// execution acts for, an author of a step that needs two approvers, or
    /// the person who gave the first approval.
    pub(in crate::domains::workflows::execution) fn ensure_may_approve(
        &self,
        by: &Human,
        step: &WorkflowApprovalStep,
        wait: &ApprovalWait,
    ) -> Result<(), DomainError> {
        if by.is_same_person_as(&self.acting_for) {
            return Err(DomainError::forbidden(message!(
                "workflows-the-person-an-execution-acts-for",
                "the person an execution acts for may not approve its steps"
            )));
        }
        if step.approvers_needed() == 2 && self.authors.includes(by) {
            return Err(DomainError::forbidden(message!(
                "workflows-an-author-of-a-workflow-may",
                "an author of a workflow may not approve its high-risk steps"
            )));
        }
        if let FirstApproval::GivenBy(first) = &wait.first
            && first.is_same_person_as(by)
        {
            return Err(DomainError::forbidden(message!(
                "agents-the-second-approval-must-come-from",
                "the second approval must come from a different person"
            )));
        }
        Ok(())
    }

    /// What an approval `by` gave now covers.
    ///
    /// It holds from now until the end of its window, or [`ACT_ON_APPROVAL`]
    /// from now if that is later. It never runs past the execution's own
    /// deadline.
    pub(in crate::domains::workflows::execution) fn approval_hold(
        &self,
        by: ApprovedBy,
        closes_at: OffsetDateTime,
    ) -> ApprovalHold {
        let from = crate::shared::clock::now();
        let until = closes_at
            .max(from.saturating_add(ACT_ON_APPROVAL))
            .min(self.deadline);
        ApprovalHold { by, from, until }
    }

    /// The approval step `key`, waiting for a decision inside its window.
    fn open_approval(
        &self,
        key: &NodeKey,
    ) -> Result<(RunningStep, ApprovalWait, WorkflowApprovalStep), DomainError> {
        let running = self.running_step(key)?;
        let (Underway::Approval(wait), NodeKind::Approval(step)) =
            (&running.underway, running.node.kind())
        else {
            return Err(DomainError::invalid_transition(message!(
                "workflows-this-step-is-not-waiting-for",
                "this step is not waiting for approval"
            )));
        };
        if crate::shared::clock::now() >= wait.closes_at {
            return Err(DomainError::invalid_transition(message!(
                "workflows-the-approval-s-decision-window-has",
                "the approval's decision window has closed"
            )));
        }
        let (wait, step) = (wait.clone(), step.clone());
        Ok((running, wait, step))
    }

    /// Keeps the first approver while retaining the original decision window.
    fn await_second(&mut self, running: RunningStep, wait: &ApprovalWait, first: &Human) {
        let state = StepState::Running {
            exposure: running.exposure,
            seen: running.seen,
            underway: Underway::Approval(ApprovalWait {
                closes_at: wait.closes_at,
                first: FirstApproval::GivenBy(first.clone()),
            }),
            started_at: running.started_at,
        };
        self.put(running.index, state);
    }

    /// `by` refuses the approval step `key`, and the execution fails.
    ///
    /// `key` may also name a loop waiting for its approval of every item:
    /// a no fails the loop before any pass runs.
    ///
    /// Denying needs the same right and clearance as approving. Sam, with no
    /// right to decide, could otherwise deny every approval in Ann's
    /// workflows and none of them would ever run.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not approve workflow steps,
    ///   or is cleared below the data the step shows.
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not waiting
    ///   for approval.
    /// - [`DomainError::InvalidTransition`] when the execution has ended.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    pub fn deny(
        &mut self,
        key: &NodeKey,
        by: &StepApprover<'_>,
    ) -> Result<Vec<ExecutionRecord>, DomainError> {
        let running = self.running_step(key)?;
        if running.underway.decision_wait().is_none() {
            return Err(DomainError::invalid_transition(message!(
                "workflows-this-step-is-not-waiting-for",
                "this step is not waiting for approval"
            )));
        }
        by.ensure_entitled(running.exposure)?;
        Ok(self.fail(
            running.index,
            StepFailure::ApprovalDenied(by.by().principal()),
        ))
    }

    /// Fails the approval step `key`, or the loop `key` waiting for its
    /// approval of every item, once its decision window closed with nobody
    /// approving it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not waiting
    ///   for approval.
    /// - [`DomainError::InvalidTransition`] when the execution has ended.
    /// - [`DomainError::Conflict`] while the window is open.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    pub fn lapse_approval(&mut self, key: &NodeKey) -> Result<Vec<ExecutionRecord>, DomainError> {
        let running = self.running_step(key)?;
        let Some(wait) = running.underway.decision_wait() else {
            return Err(DomainError::invalid_transition(message!(
                "workflows-this-step-is-not-waiting-for",
                "this step is not waiting for approval"
            )));
        };
        if crate::shared::clock::now() < wait.closes_at {
            return Err(DomainError::conflict(message!(
                "workflows-the-approval-is-still-open",
                "the approval is still open"
            )));
        }
        Ok(self.fail(running.index, StepFailure::ApprovalLapsed))
    }

    /// When the approval step `key`, or the loop `key`'s approval of every
    /// item, can no longer be approved. `None` when it is not waiting for
    /// approval.
    #[must_use]
    pub fn approval_closes(&self, key: &NodeKey) -> Option<OffsetDateTime> {
        let StepState::Running { underway, .. } = self.step(key)? else {
            return None;
        };
        underway.decision_wait().map(|wait| wait.closes_at)
    }
}

/// Refuses an approver of a high-risk step who did not prove they are present.
pub(in crate::domains::workflows::execution) fn ensure_present_when_needed(
    step: &WorkflowApprovalStep,
    approver: &StepApprover<'_>,
) -> Result<(), DomainError> {
    if step.needs_presence() && approver.presence() != Presence::Proven {
        return Err(DomainError::forbidden(message!(
            "workflows-a-high-risk-step-needs-an",
            "a high-risk step needs an approver who proved they are present just now"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::design::node::{Join, Port};
    use crate::domains::workflows::execution::ExecutionStatus;
    use crate::domains::workflows::execution::record::ExecutionEnd;
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, ann, approval, approval_of, approve_as, bob, by_hand, cid, deciding, edge,
        field, frozen_at, instant, key, managing, path, published, start_as, started, state,
        transform, viewing,
    };
    use crate::types::{ActionClass, DeclaredAction, HumanAccount, OrgUserId, PersonKey};

    fn without_the_right(by: &Human) -> StepApprover<'_> {
        StepApprover::assumed(viewing(by), DataClassLevel::Restricted, Presence::Proven)
    }

    /// Without approval rights, Sam can neither approve nor deny Ann's
    /// step. Both attempts are forbidden and the step keeps waiting.
    #[test]
    fn deciding_a_step_needs_the_approve_right() {
        let mut execution = asking(DeclaredAction::Declared(ActionClass::Write));
        let sam = bob();
        let shown = execution.approval_input(&key("check")).unwrap();

        let approved = execution.approve(&key("check"), &without_the_right(&sam), &shown);
        let denied = execution.deny(&key("check"), &without_the_right(&sam));

        assert!(matches!(approved, Err(DomainError::Forbidden(_))));
        assert!(matches!(denied, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            state(&execution, "check"),
            StepState::Running { .. }
        ));
    }

    /// Bob's public-data clearance cannot authorize an approval involving
    /// internal data; his approval returns a forbidden error.
    #[test]
    fn an_approver_must_be_cleared_for_what_the_step_shows() {
        let mut execution = asking(DeclaredAction::Declared(ActionClass::Write));
        let bob = bob();
        let shown = execution.approval_input(&key("check")).unwrap();
        let uncleared =
            StepApprover::assumed(managing(&bob), DataClassLevel::Public, Presence::Proven);

        let approved = execution.approve(&key("check"), &uncleared, &shown);

        assert!(matches!(approved, Err(DomainError::Forbidden(_))));
    }

    /// Bob cannot read the step's internal data with public clearance. Cid,
    /// cleared for them, is shown exactly what the step lets through.
    #[test]
    fn a_step_shows_its_data_only_to_an_approver_cleared_for_it() {
        let execution = asking(DeclaredAction::Declared(ActionClass::Write));
        let bob = bob();
        let cid = cid();
        let uncleared =
            StepApprover::assumed(managing(&bob), DataClassLevel::Public, Presence::Proven);

        let to_bob = execution.shown_to(&key("check"), &uncleared);
        let to_cid = execution.shown_to(&key("check"), &deciding(&cid)).unwrap();

        assert!(matches!(to_bob, Err(DomainError::Forbidden(_))));
        assert_eq!(to_cid, execution.approval_input(&key("check")).unwrap());
    }

    /// A payment approval under Bob's authority is forbidden without proof
    /// of his presence, even with sufficient rights and clearance.
    #[test]
    fn a_high_risk_step_needs_proof_of_presence() {
        let mut execution = asking(DeclaredAction::Declared(ActionClass::Financial));
        let bob = bob();
        let shown = execution.approval_input(&key("check")).unwrap();
        let absent = StepApprover::assumed(
            managing(&bob),
            DataClassLevel::Restricted,
            Presence::NotProven,
        );

        let approved = execution.approve(&key("check"), &absent, &shown);

        assert!(matches!(approved, Err(DomainError::Forbidden(_))));
    }

    fn asking(class: DeclaredAction) -> Execution {
        let mut execution = started(
            vec![approval_of("check", class), transform("after", Join::All)],
            vec![edge("check", Port::Next, "after")],
        );
        execution.request_approval(&key("check")).unwrap();
        execution
    }

    /// Ann cannot approve a run acting for her through another account at
    /// the same address. The approval is forbidden and the step keeps waiting.
    #[test]
    fn the_person_an_execution_acts_for_cannot_approve_its_steps() {
        let mut execution = started(vec![approval("check")], Vec::new());
        execution.request_approval(&key("check")).unwrap();
        let same_person_elsewhere = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            PersonKey::new("ann@corp.test").unwrap(),
        );

        let approved = approve_as(&mut execution, "check", &same_person_elsewhere);

        assert!(matches!(approved, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            state(&execution, "check"),
            StepState::Running { .. }
        ));
    }

    /// Ann cannot approve the payment workflow she authored even when Cid
    /// starts its run. The approval is forbidden and no first approval is kept.
    #[test]
    fn an_author_cannot_approve_a_high_risk_step_of_their_workflow() {
        let workflow = published(
            vec![
                approval_of("check", DeclaredAction::Declared(ActionClass::Financial)),
                transform("after", Join::All),
            ],
            vec![edge("check", Port::Next, "after")],
        );
        let (mut execution, _) =
            start_as(&workflow, &cid(), by_hand(DataClassLevel::Internal)).unwrap();
        execution.request_approval(&key("check")).unwrap();

        let by_author = approve_as(&mut execution, "check", &ann());

        assert!(matches!(by_author, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            state(&execution, "check"),
            StepState::Running {
                underway: Underway::Approval(ApprovalWait {
                    first: FirstApproval::NotGiven,
                    ..
                }),
                ..
            }
        ));
    }

    /// Bob submits an amount of 10,000 instead of the trigger data the
    /// communication approval shows. The mismatch returns a conflict and
    /// leaves the step waiting.
    #[test]
    fn an_approval_for_data_other_than_what_was_shown_is_refused() {
        let mut execution = asking(DeclaredAction::Declared(ActionClass::Communicate));
        let shown = execution.approval_input(&key("check")).unwrap();
        let other =
            FlowData::map(vec![(field("amount"), FlowData::number(10_000.0).unwrap())]).unwrap();

        let mismatched = execution.approve(&key("check"), &deciding(&bob()), &other);

        assert!(shown.at(&path("trigger.ok")).is_some());
        assert!(matches!(mismatched, Err(DomainError::Conflict(_))));
        assert!(matches!(
            state(&execution, "check"),
            StepState::Running { .. }
        ));
    }

    /// Bob approves sending a message, which is not high-risk. The approval
    /// is recorded first, and the step after it runs.
    #[test]
    fn one_approval_lets_a_step_that_is_not_high_risk_go_on() {
        let mut execution = asking(DeclaredAction::Declared(ActionClass::Communicate));

        let records = approve_as(&mut execution, "check", &bob()).unwrap();

        assert_eq!(
            records.first(),
            Some(&ExecutionRecord::step(
                &key("check"),
                StepRecord::ApprovalGranted(bob().principal())
            ))
        );
        assert!(matches!(
            state(&execution, "after"),
            StepState::Succeeded { .. }
        ));
    }

    /// Payment and undeclared actions need two different approvers. Bob's
    /// first approval leaves the step waiting, and his second is forbidden;
    /// Cid's approval then lets the following step succeed.
    #[test]
    fn a_step_that_may_be_high_risk_needs_two_different_people() {
        for class in [
            DeclaredAction::Declared(ActionClass::Financial),
            DeclaredAction::Undeclared,
        ] {
            let mut execution = asking(class);

            let first = approve_as(&mut execution, "check", &bob()).unwrap();
            let still_waiting = state(&execution, "check");
            let again = approve_as(&mut execution, "check", &bob());
            approve_as(&mut execution, "check", &cid()).unwrap();

            assert_eq!(first.len(), 1);
            assert!(matches!(
                still_waiting,
                StepState::Running {
                    underway: Underway::Approval(ApprovalWait {
                        first: FirstApproval::GivenBy(_),
                        ..
                    }),
                    ..
                }
            ));
            assert!(matches!(again, Err(DomainError::Forbidden(_))));
            assert!(matches!(
                state(&execution, "after"),
                StepState::Succeeded { .. }
            ));
        }
    }

    /// Bob approves a step. It succeeds with a null output, so the steps
    /// after it see no data from it.
    #[test]
    fn an_approval_produces_nothing_of_its_own() {
        let mut execution = asking(DeclaredAction::Declared(ActionClass::Communicate));

        approve_as(&mut execution, "check", &bob()).unwrap();

        let StepState::Succeeded { output, .. } = state(&execution, "check") else {
            panic!("the approval did not settle");
        };
        assert_eq!(output, FlowData::null());
    }

    /// Bob refuses an approval. The step fails, naming Bob, and the whole
    /// execution ends as failed.
    #[test]
    fn a_denied_approval_fails_the_execution() {
        let mut execution = asking(DeclaredAction::Declared(ActionClass::Communicate));

        execution.deny(&key("check"), &deciding(&bob())).unwrap();

        assert_eq!(
            state(&execution, "check"),
            StepState::Failed(StepFailure::ApprovalDenied(bob().principal()))
        );
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
    }

    /// An approval opens at time 0 with a one-hour window. Lapsing it at
    /// once is refused. At 3600 Bob's approval is refused and the step
    /// lapses instead.
    #[test]
    fn an_approval_whose_window_closed_lapses_instead_of_being_approved() {
        let clock = frozen_at(0);
        let mut execution = asking(DeclaredAction::Declared(ActionClass::Communicate));
        let early_lapse = execution.lapse_approval(&key("check"));
        drop(clock);
        let _later = frozen_at(3600);

        let late_approval = approve_as(&mut execution, "check", &bob());
        execution.lapse_approval(&key("check")).unwrap();

        assert!(matches!(early_lapse, Err(DomainError::Conflict(_))));
        assert!(matches!(
            late_approval,
            Err(DomainError::InvalidTransition(_))
        ));
        assert_eq!(
            state(&execution, "check"),
            StepState::Failed(StepFailure::ApprovalLapsed)
        );
    }

    fn held(execution: &Execution) -> ApprovalHold {
        let StepState::Succeeded {
            holds: Holding::Approved(hold),
            ..
        } = state(execution, "check")
        else {
            panic!("the approval was not given");
        };
        hold
    }

    fn held_until(execution: &Execution) -> OffsetDateTime {
        held(execution).until
    }

    /// Two approvals have a window ending at 3600. One given at 60 holds to
    /// 3600. One given at 3599 holds [`ACT_ON_APPROVAL`] past 3599, so the
    /// next step still has time to act on it.
    #[test]
    fn a_late_approval_still_leaves_time_to_act_on_it() {
        let mut early = {
            let _clock = frozen_at(0);
            asking(DeclaredAction::Declared(ActionClass::Communicate))
        };
        let mut late = {
            let _clock = frozen_at(0);
            asking(DeclaredAction::Declared(ActionClass::Communicate))
        };

        {
            let _clock = frozen_at(60);
            approve_as(&mut early, "check", &bob()).unwrap();
        }
        let _clock = frozen_at(3599);
        approve_as(&mut late, "check", &bob()).unwrap();

        assert_eq!(held_until(&early), instant(3600));
        assert_eq!(
            held_until(&late),
            instant(3599).saturating_add(ACT_ON_APPROVAL)
        );
    }

    /// Bob approves a message step at 60. Bob and Cid approve a payment
    /// step, Cid last at 120. Each finished step names who approved it and
    /// holds from the moment the last approval was given.
    #[test]
    fn a_finished_approval_records_who_gave_it() {
        let clock = frozen_at(0);
        let mut message = asking(DeclaredAction::Declared(ActionClass::Communicate));
        let mut payment = asking(DeclaredAction::Declared(ActionClass::Financial));
        drop(clock);

        {
            let _clock = frozen_at(60);
            approve_as(&mut message, "check", &bob()).unwrap();
            approve_as(&mut payment, "check", &bob()).unwrap();
        }
        let _clock = frozen_at(120);
        approve_as(&mut payment, "check", &cid()).unwrap();

        assert_eq!(held(&message).by, ApprovedBy::One(bob()));
        assert_eq!(held(&message).from, instant(60));
        assert_eq!(
            held(&payment).by,
            ApprovedBy::Two {
                first: bob(),
                second: cid(),
            }
        );
        assert_eq!(held(&payment).from, instant(120));
    }

    /// An approval opened at time 0 with a one-hour window says it closes
    /// at 3600. The step after it, which is not an approval, gives no time.
    #[test]
    fn a_waiting_approval_says_when_it_closes() {
        let _clock = frozen_at(0);
        let execution = asking(DeclaredAction::Declared(ActionClass::Communicate));

        assert_eq!(
            execution.approval_closes(&key("check")),
            Some(instant(3600))
        );
        assert_eq!(execution.approval_closes(&key("after")), None);
    }
}
