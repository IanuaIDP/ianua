//! How an execution moves on: steps the domain settles itself, steps that
//! become ready or are skipped, and how the execution ends.

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::data::{FieldName, FlowData};
use crate::domains::workflows::design::condition::ConditionRule;
use crate::domains::workflows::design::node::{Node, NodeKey, NodeKind, Port};
use crate::domains::workflows::execution::record::{ExecutionEnd, ExecutionRecord, StepRecord};
use crate::domains::workflows::execution::step::{Attempt, Holding, StepFailure, StepState};
use crate::domains::workflows::execution::steps::schedule::{
    Readiness, StepInput, TriggerData, readiness,
};
use crate::domains::workflows::execution::{ExecutionStatus, WorkflowExecution};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// Where an execution's steps leave it after it moved on as far as it can.
enum Outcome {
    /// A step failed. The execution ends as failed.
    StepFailed,
    /// Every step settled. The execution ends as succeeded.
    AllSettled,
    /// Some step still waits or works. The execution goes on.
    StillGoing,
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// Refuses `by` unless they may stop the execution: the person it acts
    /// for, or someone with full control of workflows.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is neither the person it acts
    ///   for nor has full control of workflows.
    pub fn ensure_cancellable_by(&self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        if by.by().is_same_person_as(&self.acting_for) {
            return Ok(());
        }
        by.ensure_may(WorkflowAction::Manage)
    }

    /// `by` stops the execution, and the record says so.
    ///
    /// The person it acts for may stop it, and so may someone with full
    /// control of workflows. Sam cannot cancel Ann's payroll run halfway.
    /// Steps ready or under way are abandoned, each with a record, so their
    /// outside work is stopped too.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is neither the person it acts
    ///   for nor has full control of workflows.
    /// - [`DomainError::InvalidTransition`] when it already ended.
    /// - [`DomainError::Conflict`] once its run limit passed. It is then
    ///   [`expire`](Self::expire)d, not cancelled.
    pub fn cancel(
        &mut self,
        by: &WorkflowControl<'_>,
    ) -> Result<Vec<ExecutionRecord>, DomainError> {
        self.ensure_cancellable_by(by)?;
        if crate::shared::clock::now() >= self.deadline {
            return Err(DomainError::conflict(message!(
                "workflows-the-execution-ran-out-of-time",
                "the execution ran out of time; it is expired, not cancelled"
            )));
        }
        let mut records = Vec::new();
        self.end(ExecutionEnd::Cancelled(by.by().principal()), &mut records)?;
        Ok(records)
    }

    /// Stops the execution once its run limit has passed. Steps ready or
    /// under way are abandoned, each with a record.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it already ended.
    /// - [`DomainError::Conflict`] while it is still within its limit.
    pub fn expire(&mut self) -> Result<Vec<ExecutionRecord>, DomainError> {
        if crate::shared::clock::now() < self.deadline {
            return Err(DomainError::conflict(message!(
                "workflows-the-execution-is-still-within-its",
                "the execution is still within its run limit"
            )));
        }
        let mut records = Vec::new();
        self.end(ExecutionEnd::TimedOut, &mut records)?;
        Ok(records)
    }

    /// Ends the execution `end`'s way, abandoning every step still ready
    /// or under way.
    pub(super) fn end(
        &mut self,
        end: ExecutionEnd,
        records: &mut Vec<ExecutionRecord>,
    ) -> Result<(), DomainError> {
        self.status = self.status.try_transition(ExecutionStatus::Ended(end))?;
        for (node, state) in self.graph.nodes().iter().zip(self.steps.iter_mut()) {
            let left = match state {
                StepState::Ready { .. } => StepState::Stopped,
                StepState::Running {
                    exposure,
                    seen,
                    underway,
                    ..
                } => StepState::Abandoned {
                    exposure: *exposure,
                    seen: std::mem::take(seen),
                    underway: underway.clone(),
                },
                StepState::Waiting
                | StepState::Succeeded { .. }
                | StepState::Failed(_)
                | StepState::Skipped
                | StepState::Stopped
                | StepState::Abandoned { .. } => continue,
            };
            *state = left;
            records.push(ExecutionRecord::step(node.key(), StepRecord::Abandoned));
        }
        records.push(ExecutionRecord::Ended(end));
        self.touch();
        Ok(())
    }

    /// Refuses any change once the execution ended or ran out of time.
    pub(super) fn ensure_open(&self) -> Result<(), DomainError> {
        if self.status != ExecutionStatus::Running {
            return Err(DomainError::invalid_transition(message!(
                "workflows-the-execution-has-ended",
                "the execution has ended"
            )));
        }
        if crate::shared::clock::now() >= self.deadline {
            return Err(DomainError::conflict(message!(
                "workflows-the-execution-ran-out-of-time-2",
                "the execution ran out of time"
            )));
        }
        Ok(())
    }

    /// The position of the step called `key`.
    pub(super) fn position(&self, key: &NodeKey) -> Result<usize, DomainError> {
        self.graph
            .nodes()
            .iter()
            .position(|node| node.key() == key)
            .ok_or(DomainError::NotFound)
    }

    /// Puts the step at `index` in `state`, then lets everything after it
    /// that can go on, go on.
    pub(super) fn settle(
        &mut self,
        index: usize,
        state: StepState,
        records: &mut Vec<ExecutionRecord>,
    ) {
        self.put(index, state);
        self.advance(records);
    }

    /// Puts the step at `index` in `state`.
    pub(super) fn put(&mut self, index: usize, state: StepState) {
        if let Some(slot) = self.steps.get_mut(index) {
            *slot = state;
        }
        self.touch();
    }

    /// Starts, skips or settles every waiting step that can be, until none
    /// changes.
    ///
    /// Then it ends the execution if a step failed or every step settled.
    pub(super) fn advance(&mut self, records: &mut Vec<ExecutionRecord>) {
        while self.advance_once(records) {}
        let end = match self.outcome() {
            Outcome::StepFailed => ExecutionEnd::Failed,
            Outcome::AllSettled => ExecutionEnd::Succeeded,
            Outcome::StillGoing => return,
        };
        if self.status == ExecutionStatus::Running {
            let _ended = self.end(end, records);
        }
    }

    /// Where the steps leave the execution.
    ///
    /// A failed step ends it as failed. Every step settled ends it as
    /// succeeded. Otherwise it goes on.
    fn outcome(&self) -> Outcome {
        if self.has_failed() {
            return Outcome::StepFailed;
        }
        if self.steps.iter().all(StepState::is_settled) {
            return Outcome::AllSettled;
        }
        Outcome::StillGoing
    }

    fn has_failed(&self) -> bool {
        self.steps
            .iter()
            .any(|state| matches!(state, StepState::Failed(_)))
    }

    /// One pass over the waiting steps. Says whether any changed.
    fn advance_once(&mut self, records: &mut Vec<ExecutionRecord>) -> bool {
        if self.has_failed() {
            return false;
        }
        let trigger = TriggerData {
            input: &self.input,
            exposure: self.exposure,
        };
        let decided: Vec<(usize, Readiness)> = self
            .graph
            .nodes()
            .iter()
            .zip(&self.steps)
            .enumerate()
            .filter(|(_, (_, state))| matches!(state, StepState::Waiting))
            .map(|(index, (node, _))| (index, readiness(&self.graph, &self.steps, node, trigger)))
            .filter(|(_, readiness)| *readiness != Readiness::Wait)
            .collect();
        let changed = !decided.is_empty();
        for (index, readiness) in decided {
            self.apply(index, readiness, records);
        }
        changed
    }

    fn apply(&mut self, index: usize, readiness: Readiness, records: &mut Vec<ExecutionRecord>) {
        let Some(node) = self.graph.nodes().get(index).cloned() else {
            return;
        };
        let state = match readiness {
            Readiness::Wait => return,
            Readiness::Skip => {
                records.push(ExecutionRecord::step(node.key(), StepRecord::Skipped));
                StepState::Skipped
            }
            Readiness::InputTooLarge => failed(&node, StepFailure::InputTooLarge, records),
            Readiness::Start(input) if self.mode.stands_in(node.key()) => {
                stood_in(&node, input, records)
            }
            Readiness::Start(input) => settled_here(&node, input, records),
        };
        if let Some(slot) = self.steps.get_mut(index) {
            *slot = state;
        }
    }

    pub(super) fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

/// The state a step starting with `input` takes.
///
/// It is settled at once when the domain does its work. Otherwise it is
/// ready for outside work.
fn settled_here(node: &Node, input: StepInput, records: &mut Vec<ExecutionRecord>) -> StepState {
    let (output, port) = match node.kind() {
        NodeKind::Condition(rule) => (no_output(), way_out(rule, &input.data)),
        NodeKind::Transform(mapping) => match mapping.apply(&input.data) {
            Ok(output) => (output, Port::Next),
            Err(_) => return failed(node, StepFailure::OutputTooLarge, records),
        },
        NodeKind::AgentRun(_)
        | NodeKind::Action(_)
        | NodeKind::Approval(_)
        | NodeKind::Wait(_)
        | NodeKind::Loop(_)
        | NodeKind::Code(_)
        | NodeKind::Guardrail(_) => return ready_for_outside_work(input),
    };
    records.push(ExecutionRecord::step(
        node.key(),
        StepRecord::Succeeded(port),
    ));
    StepState::Succeeded {
        output,
        exposure: input.exposure,
        seen: input.seen,
        port,
        holds: Holding::ForGood,
    }
}

/// The field a stand-in's output says it stood in under.
pub(crate) const STOOD_IN_FIELD: &str = "stood_in";

/// The field a stand-in's output keeps what the step would have used under.
pub(crate) const WOULD_USE_FIELD: &str = "would_use";

/// The state a step that stands in, in a test, takes: settled at once,
/// with an output saying it stood in and what it would have used. Nothing
/// outside is asked.
fn stood_in(node: &Node, input: StepInput, records: &mut Vec<ExecutionRecord>) -> StepState {
    let Ok(output) = stand_in_output(node, &input.data) else {
        return failed(node, StepFailure::OutputTooLarge, records);
    };
    records.push(ExecutionRecord::step(node.key(), StepRecord::StoodIn));
    StepState::Succeeded {
        output,
        exposure: input.exposure,
        seen: input.seen,
        port: Port::Next,
        holds: Holding::ForGood,
    }
}

/// What a step standing in on `data` gives back: that it stood in, and the
/// inputs it would have been given, when it is given any.
fn stand_in_output(node: &Node, data: &FlowData) -> Result<FlowData, DomainError> {
    let would_use = match node.kind() {
        NodeKind::Action(step) => Some(step.inputs().apply(data)?),
        NodeKind::Code(step) => Some(step.inputs().apply(data)?),
        NodeKind::AgentRun(step) => Some(step.inputs().apply(data)?),
        NodeKind::Approval(_)
        | NodeKind::Wait(_)
        | NodeKind::Condition(_)
        | NodeKind::Transform(_)
        | NodeKind::Loop(_)
        | NodeKind::Guardrail(_) => None,
    };
    let mut fields = vec![(FieldName::new(STOOD_IN_FIELD)?, FlowData::bool(true))];
    if let Some(would_use) = would_use {
        fields.push((FieldName::new(WOULD_USE_FIELD)?, would_use));
    }
    FlowData::map(fields)
}

/// A step starting with `input` whose work is done outside the domain,
/// ready for that work for the first time.
fn ready_for_outside_work(input: StepInput) -> StepState {
    StepState::Ready {
        input: input.data,
        exposure: input.exposure,
        seen: input.seen,
        attempt: Attempt::First,
    }
}

/// The way out of a condition step that tests `rule` on `data`.
fn way_out(rule: &ConditionRule, data: &FlowData) -> Port {
    if rule.holds_for(data) {
        return Port::WhenTrue;
    }
    Port::WhenFalse
}

/// What a step that only decides whether the workflow goes on produces.
///
/// That is a condition, an approval or a wait. It produces nothing of its
/// own. Every later step reads what came before from the steps that made
/// it.
pub(super) fn no_output() -> FlowData {
    FlowData::null()
}

pub(super) fn failed(
    node: &Node,
    failure: StepFailure,
    records: &mut Vec<ExecutionRecord>,
) -> StepState {
    records.push(ExecutionRecord::step(
        node.key(),
        StepRecord::Failed(failure.clone()),
    ));
    StepState::Failed(failure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::account::IntegrationAccount;
    use crate::domains::workflows::data::FlowValue;
    use crate::domains::workflows::design::node::Join;
    use crate::domains::workflows::execution::step::{ActionOutcome, Underway};
    use crate::domains::workflows::execution::tests::fixtures::{
        Check, Execution, acting, action, ann, append, approval, approve, approve_as, bob,
        by_hand_where, condition, copy, deciding, edge, frozen_at, key, managing, offered, path,
        published, sheet_account, start, start_as, started, state, transform, viewing, wait,
    };
    use crate::domains::workflows::execution::{
        ActionCall, ActionClearance, ActionStart, HoursBegin, Offer,
    };
    use crate::domains::workflows::integration::risk_override::TenantOperation;
    use crate::isolation::scope::ResolvedTenant;

    /// A check passes, so "yes" runs and "no" is skipped with a record. All
    /// three settle the moment the run starts, and it ends as succeeded.
    #[test]
    fn a_condition_runs_the_branch_that_holds_and_skips_the_other() {
        let workflow = published(
            vec![
                condition("check"),
                transform("yes", Join::All),
                transform("no", Join::All),
            ],
            vec![
                edge("check", Port::WhenTrue, "yes"),
                edge("check", Port::WhenFalse, "no"),
            ],
        );

        let (execution, records) = start(&workflow);

        assert!(matches!(
            state(&execution, "check"),
            StepState::Succeeded {
                port: Port::WhenTrue,
                ..
            }
        ));
        assert!(matches!(
            state(&execution, "yes"),
            StepState::Succeeded { .. }
        ));
        assert_eq!(state(&execution, "no"), StepState::Skipped);
        assert!(records.contains(&ExecutionRecord::step(&key("no"), StepRecord::Skipped)));
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Succeeded)
        );
    }

    /// "First" runs, then a check, then "last". "Last" reads `first.seen`
    /// past the check, and `trigger.ok`, and gets both values.
    #[test]
    fn a_step_reads_an_earlier_step_by_name_past_the_steps_between() {
        let execution = started(
            vec![
                transform("first", Join::All),
                condition("check"),
                copy("last", &[("seen", "first.seen"), ("ok", "trigger.ok")]),
            ],
            vec![
                edge("first", Port::Next, "check"),
                edge("check", Port::WhenTrue, "last"),
            ],
        );

        let StepState::Succeeded { output, .. } = state(&execution, "last") else {
            panic!("the last step did not run");
        };

        assert_eq!(
            output.at(&path("seen")).map(FlowData::value),
            Some(FlowValue::Bool(true))
        );
        assert_eq!(
            output.at(&path("ok")).map(FlowData::value),
            Some(FlowValue::Bool(true))
        );
    }

    /// "Fetch" reads restricted salaries, then a check runs, then "report"
    /// copies the fetched rows. The report is restricted too, since what a
    /// step can read, it carries.
    #[test]
    fn data_read_further_back_raises_a_later_steps_exposure() {
        let account = sheet_account(&ann(), "google-sheets");
        let spec = offered(crate::domains::workflows::execution::tests::fixtures::append_row());
        let mut execution = fetch_then_report(&account);
        let call = begin_sheet_action(&mut execution, "fetch", &account, &spec);

        execution
            .settle_action(
                &key("fetch"),
                call.call_id,
                ActionOutcome::Succeeded {
                    output: FlowData::text("salaries").unwrap(),
                    exposure: DataClassLevel::Restricted,
                },
            )
            .unwrap();

        let StepState::Succeeded {
            output, exposure, ..
        } = state(&execution, "report")
        else {
            panic!("the report step did not run");
        };
        assert_eq!(exposure, DataClassLevel::Restricted);
        assert_eq!(
            output.at(&path("rows")).map(FlowData::value),
            Some(FlowValue::Text("salaries"))
        );
    }

    /// A sign-off opens after "early", before "late" produces its output.
    /// Bob's approval lets the following step read "early" but gives it null
    /// for "late", which remains outside the inputs covered by the approval.
    #[test]
    fn a_step_after_an_approval_reads_only_what_the_approval_was_asked_about() {
        let account = sheet_account(&ann(), "google-sheets");
        let spec = offered(crate::domains::workflows::execution::tests::fixtures::append_row());
        let mut execution = early_and_late(&account);
        execution.request_approval(&key("sign-off")).unwrap();
        let call = begin_sheet_action(&mut execution, "late", &account, &spec);
        execution
            .settle_action(
                &key("late"),
                call.call_id,
                ActionOutcome::Succeeded {
                    output: FlowData::text("an amount nobody saw").unwrap(),
                    exposure: DataClassLevel::Internal,
                },
            )
            .unwrap();

        approve_as(&mut execution, "sign-off", &bob()).unwrap();

        let StepState::Succeeded { output, seen, .. } = state(&execution, "after") else {
            panic!("the step after the approval did not run");
        };
        assert_eq!(
            output.at(&path("early")).map(FlowData::value),
            Some(FlowValue::Bool(true))
        );
        assert_eq!(output.at(&path("late")), Some(&FlowData::null()));
        assert!(!seen.contains(&key("late")));
    }

    fn approval_joining_any(name: &str) -> Node {
        let step = approval(name);
        Node::new(
            step.key().clone(),
            step.name().clone(),
            step.kind().clone(),
            Join::Any,
        )
    }

    /// Keeps a condition between fetching sheet data and copying them into a report.
    fn fetch_then_report(account: &IntegrationAccount<ResolvedTenant>) -> Execution {
        started(
            vec![
                action("fetch", *account.id()),
                condition("check"),
                copy("report", &[("rows", "fetch")]),
            ],
            vec![
                edge("fetch", Port::Next, "check"),
                edge("check", Port::WhenTrue, "report"),
            ],
        )
    }

    /// Lets the early branch open approval while the parallel sheet action remains ready.
    fn early_and_late(account: &IntegrationAccount<ResolvedTenant>) -> Execution {
        started(
            vec![
                transform("early", Join::All),
                action("late", *account.id()),
                approval_joining_any("sign-off"),
                copy("after", &[("early", "early.seen"), ("late", "late")]),
            ],
            vec![
                edge("early", Port::Next, "sign-off"),
                edge("late", Port::Next, "sign-off"),
                edge("sign-off", Port::Next, "after"),
            ],
        )
    }

    /// Combines the fetched sheet rows with the original trigger's condition value.
    fn fetch_then_combine(account: &IntegrationAccount<ResolvedTenant>) -> Execution {
        started(
            vec![
                action("fetch", *account.id()),
                copy("combine", &[("ok", "trigger.ok"), ("rows", "fetch")]),
            ],
            vec![edge("fetch", Port::Next, "combine")],
        )
    }

    /// Starts Ann's named sheet action after obtaining permission for its exact account.
    fn begin_sheet_action(
        execution: &mut Execution,
        name: &str,
        account: &IntegrationAccount<ResolvedTenant>,
        spec: &TenantOperation,
    ) -> ActionCall {
        let clearance = ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        );
        let ActionStart::Call(call, _) = execution
            .begin_action(
                &key(name),
                Offer::Current(spec),
                &clearance,
                &acting(&ann()),
            )
            .unwrap()
        else {
            panic!("the action was not called");
        };
        call
    }

    /// A check settles with a null output. It only chooses the way on, so
    /// no data is copied again at every step.
    #[test]
    fn a_condition_produces_nothing_of_its_own() {
        let execution = started(
            vec![condition("check"), transform("after", Join::All)],
            vec![edge("check", Port::WhenTrue, "after")],
        );

        let StepState::Succeeded { output, .. } = state(&execution, "check") else {
            panic!("the condition did not settle");
        };

        assert_eq!(output, FlowData::null());
    }

    /// "Left" leads to "after" and "right" does not. "After" reads
    /// `left.seen`, and only "left" is among the steps it saw.
    #[test]
    fn a_step_on_another_branch_is_not_in_the_input() {
        let execution = started(
            vec![
                transform("left", Join::All),
                transform("right", Join::All),
                copy("after", &[("left", "left.seen")]),
            ],
            vec![edge("left", Port::Next, "after")],
        );

        let StepState::Succeeded { output, seen, .. } = state(&execution, "after") else {
            panic!("the step did not run");
        };

        assert_eq!(
            output.at(&path("left")).map(FlowData::value),
            Some(FlowValue::Bool(true))
        );
        assert_eq!(seen, vec![key("left")]);
    }

    fn two_approvals_then(join: Join) -> Execution {
        started(
            vec![
                approval("first"),
                approval("second"),
                transform("after", join),
            ],
            vec![
                edge("first", Port::Next, "after"),
                edge("second", Port::Next, "after"),
            ],
        )
    }

    /// "After" waits for both of two approvals. After the first it is still
    /// waiting. After the second it runs.
    #[test]
    fn a_step_joining_all_waits_for_every_step_before_it() {
        let mut execution = two_approvals_then(Join::All);

        approve(&mut execution, "first");
        let after_one = state(&execution, "after");
        approve(&mut execution, "second");

        assert_eq!(after_one, StepState::Waiting);
        assert!(matches!(
            state(&execution, "after"),
            StepState::Succeeded { .. }
        ));
    }

    /// "After" waits for any one of two approvals. It runs as soon as the
    /// first is given.
    #[test]
    fn a_step_joining_any_starts_on_the_first_step_that_leads_to_it() {
        let mut execution = two_approvals_then(Join::Any);

        approve(&mut execution, "first");

        assert!(matches!(
            state(&execution, "after"),
            StepState::Succeeded { .. }
        ));
    }

    /// A check fails and "after" hangs only off its "when true" edge.
    /// "After" is skipped instead of left waiting.
    #[test]
    fn a_step_every_path_into_which_is_dead_is_skipped() {
        let workflow = published(
            vec![condition("check"), transform("after", Join::Any)],
            vec![edge("check", Port::WhenTrue, "after")],
        );

        let (execution, _) = start_as(
            &workflow,
            &ann(),
            by_hand_where(Check::Fails, DataClassLevel::Public),
        )
        .unwrap();

        assert_eq!(state(&execution, "after"), StepState::Skipped);
    }

    /// "Fetch" returns "three rows" as confidential, and "combine" reads
    /// `trigger.ok` and `fetch`. It gets both values and is confidential,
    /// the higher of the trigger and the fetch.
    #[test]
    fn a_steps_input_holds_the_trigger_and_each_step_before_it_at_the_highest_exposure() {
        let account = sheet_account(&ann(), "google-sheets");
        let spec = offered(crate::domains::workflows::execution::tests::fixtures::append_row());
        let mut execution = fetch_then_combine(&account);
        let call = begin_sheet_action(&mut execution, "fetch", &account, &spec);

        execution
            .settle_action(
                &key("fetch"),
                call.call_id,
                ActionOutcome::Succeeded {
                    output: FlowData::text("three rows").unwrap(),
                    exposure: DataClassLevel::Confidential,
                },
            )
            .unwrap();

        let StepState::Succeeded {
            output, exposure, ..
        } = state(&execution, "combine")
        else {
            panic!("the combining step did not run");
        };
        assert_eq!(
            output.at(&path("ok")).map(FlowData::value),
            Some(FlowValue::Bool(true))
        );
        assert_eq!(
            output.at(&path("rows")).map(FlowData::value),
            Some(FlowValue::Text("three rows"))
        );
        assert_eq!(exposure, DataClassLevel::Confidential);
    }

    /// An execution with a one-day limit starts at time 0. Expiring it at
    /// once is refused. At 86,400 it expires, and its last record says it
    /// timed out.
    #[test]
    fn an_execution_expires_only_after_its_deadline() {
        let clock = frozen_at(0);
        let mut execution = started(vec![wait("pause")], Vec::new());
        let early = execution.expire();
        drop(clock);
        let _later = frozen_at(86_400);

        let records = execution.expire().unwrap();

        assert!(matches!(early, Err(DomainError::Conflict(_))));
        assert_eq!(
            records.last(),
            Some(&ExecutionRecord::Ended(ExecutionEnd::TimedOut))
        );
    }

    /// Ann cancels a run with an approval open and a wait not yet started.
    /// The approval is abandoned and the wait stopped, each with a record,
    /// before the record of the end.
    #[test]
    fn ending_an_execution_abandons_its_ready_and_running_steps() {
        let mut execution = started(vec![approval("asked"), wait("pause")], Vec::new());
        execution.request_approval(&key("asked")).unwrap();

        let records = execution.cancel(&managing(&ann())).unwrap();

        assert_eq!(state(&execution, "pause"), StepState::Stopped);
        assert!(matches!(
            state(&execution, "asked"),
            StepState::Abandoned {
                underway: Underway::Approval(_),
                ..
            }
        ));
        assert_eq!(
            records,
            vec![
                ExecutionRecord::step(&key("asked"), StepRecord::Abandoned),
                ExecutionRecord::step(&key("pause"), StepRecord::Abandoned),
                ExecutionRecord::Ended(ExecutionEnd::Cancelled(ann().principal())),
            ]
        );
    }

    /// A wait is under way when the run reaches its one-day limit. Expiring
    /// the run abandons the wait, and that is the first record.
    #[test]
    fn an_expired_execution_abandons_what_was_under_way() {
        let clock = frozen_at(0);
        let mut execution = started(vec![wait("pause")], Vec::new());
        execution
            .begin_wait(&key("pause"), HoursBegin::NotAsked)
            .unwrap();
        drop(clock);
        let _later = frozen_at(86_400);

        let records = execution.expire().unwrap();

        assert!(matches!(
            state(&execution, "pause"),
            StepState::Abandoned { .. }
        ));
        assert_eq!(
            records.first(),
            Some(&ExecutionRecord::step(&key("pause"), StepRecord::Abandoned))
        );
    }

    /// A wait runs beside an approval, and Bob refuses the approval. The
    /// wait is abandoned with a record, and the execution fails.
    #[test]
    fn a_failure_on_one_branch_abandons_the_work_on_the_others() {
        let mut execution = started(vec![approval("asked"), wait("pause")], Vec::new());
        execution
            .begin_wait(&key("pause"), HoursBegin::NotAsked)
            .unwrap();
        execution.request_approval(&key("asked")).unwrap();

        let records = execution.deny(&key("asked"), &deciding(&bob())).unwrap();

        assert!(matches!(
            state(&execution, "pause"),
            StepState::Abandoned { .. }
        ));
        assert!(records.contains(&ExecutionRecord::step(&key("pause"), StepRecord::Abandoned)));
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
    }

    /// Bob cannot cancel Ann's run with workflow view rights, and the run
    /// remains active. Ann can cancel it with the same rights because it
    /// acts for her.
    #[test]
    fn only_the_person_it_acts_for_or_a_manager_cancels_a_run() {
        let mut execution = started(vec![wait("pause")], Vec::new());

        let by_bob = execution.cancel(&viewing(&bob()));

        assert!(matches!(by_bob, Err(DomainError::Forbidden(_))));
        assert_eq!(execution.status(), ExecutionStatus::Running);
        assert!(execution.cancel(&viewing(&ann())).is_ok());
    }

    /// Ann cancels a run after its one-day limit passed. That is refused,
    /// so the run stays running until it is expired as timed out.
    #[test]
    fn an_execution_past_its_deadline_is_expired_not_cancelled() {
        let clock = frozen_at(0);
        let mut execution = started(vec![wait("pause")], Vec::new());
        drop(clock);
        let _later = frozen_at(86_400);

        let cancelled = execution.cancel(&managing(&ann()));

        assert!(matches!(cancelled, Err(DomainError::Conflict(_))));
        assert_eq!(execution.status(), ExecutionStatus::Running);
    }

    /// Ann cancels a run. Asking for its approval and cancelling again are
    /// both refused, and it stays cancelled by Ann.
    #[test]
    fn nothing_changes_once_an_execution_ended() {
        let mut execution = started(vec![approval("check")], Vec::new());
        execution.cancel(&managing(&ann())).unwrap();

        assert!(execution.request_approval(&key("check")).is_err());
        assert!(execution.cancel(&managing(&ann())).is_err());
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Cancelled(ann().principal()))
        );
    }
}
