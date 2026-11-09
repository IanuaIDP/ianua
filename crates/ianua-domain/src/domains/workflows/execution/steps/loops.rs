//! Loop steps: one pass per item of a list, each an execution of the loop's
//! own steps that reports back here when it ends.
//!
//! A pass acts for the same person, under the same version, authors, chain
//! and deadline as the execution that started it. It starts with its item,
//! its position and what the loop maps from its input, at the exposure the
//! loop step's input carries, so nothing reaches a pass that the loop step
//! was not handed.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::{FieldName, FlowData, FlowValue, MAX_SIZE};
use crate::domains::workflows::design::node::looping::pass_input;
use crate::domains::workflows::design::node::{LoopStep, NodeKey, NodeKind};
use crate::domains::workflows::execution::record::{ExecutionEnd, ExecutionRecord};
use crate::domains::workflows::execution::step::{
    ApprovalWait, FirstApproval, Holding, ItemsApproval, LoopProgress, Pass, StepFailure,
    StepState, Underway,
};
use crate::domains::workflows::execution::steps::work::ReadyStep;
use crate::domains::workflows::execution::{ExecutionStatus, PassOf, WorkflowExecution};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::WorkflowExecutionId;

/// What a change to a loop step asks of the application to keep.
#[derive(Debug)]
pub struct LoopMoves<T: TenantScope> {
    /// What happened to the execution holding the loop.
    pub records: Vec<ExecutionRecord>,
    /// The passes it started, each kept with its own records. A pass whose
    /// steps the domain settles itself may have ended the moment it began;
    /// what it gave back is counted already.
    pub started: Vec<PassStart<T>>,
    /// The passes still running when the loop failed, to be stopped.
    pub stop: Vec<WorkflowExecutionId>,
}

impl<T: TenantScope> LoopMoves<T> {
    pub(super) fn nothing() -> Self {
        Self {
            records: Vec::new(),
            started: Vec::new(),
            stop: Vec::new(),
        }
    }

    /// Moves that only record `records`, starting and stopping no pass.
    pub(super) fn recording(records: Vec<ExecutionRecord>) -> Self {
        Self {
            records,
            ..Self::nothing()
        }
    }
}

/// One pass a loop started, with what happened to it as it began.
#[derive(Debug)]
pub struct PassStart<T: TenantScope> {
    /// The pass.
    pub execution: WorkflowExecution<T>,
    /// What happened to it.
    pub records: Vec<ExecutionRecord>,
}

/// The loop step a change is about, as it stands.
pub(super) struct Looping {
    pub(super) index: usize,
    pub(super) key: NodeKey,
    pub(super) step: LoopStep,
    pub(super) exposure: DataClassLevel,
    pub(super) progress: LoopProgress,
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// Starts the ready loop step `key`: its first passes, as many as it
    /// runs at once.
    ///
    /// The step fails at once, with a record, when no list is found where
    /// it looks, the list holds more items than it allows, or what a pass
    /// would start with is too large. An empty list succeeds at once with
    /// an empty list.
    ///
    /// When the loop's first step asks one approval for every item, no pass
    /// starts yet: the items are fixed now, and people are asked about all
    /// of them within that approval's window.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not ready.
    /// - [`DomainError::InvalidTransition`] when the execution has ended.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    /// - [`DomainError::Validation`] when it is not a loop step.
    pub fn begin_loop(&mut self, key: &NodeKey) -> Result<LoopMoves<T>, DomainError> {
        let ready = self.ready_step(key)?;
        let NodeKind::Loop(step) = ready.node.kind().clone() else {
            return Err(DomainError::invalid(message!(
                "workflows-this-step-is-not-a-loop",
                "this step is not a loop"
            )));
        };
        let mut progress = match progress_of(&step, &ready.input) {
            Ok(progress) => progress,
            Err(failure) => return Ok(LoopMoves::recording(self.fail(ready.index, failure))),
        };
        let now = crate::shared::clock::now();
        let Some(wait) = self.items_wait(&step, &progress, now) else {
            let looping = Looping {
                index: ready.index,
                key: key.clone(),
                step,
                exposure: ready.exposure,
                progress,
            };
            return Ok(self.begin_passes(ready, looping, now));
        };
        progress.wait_for_approval(wait);
        Ok(LoopMoves::recording(self.begin_step(
            ready,
            Underway::Loop(progress),
            now,
        )))
    }

    /// Starts the ready loop step `looping` names at `now`, with its first
    /// passes.
    fn begin_passes(
        &mut self,
        ready: ReadyStep,
        looping: Looping,
        now: OffsetDateTime,
    ) -> LoopMoves<T> {
        let underway = Underway::Loop(looping.progress.clone());
        let mut records = self.begin_step(ready, underway, now);
        let mut moves = self.go_on(looping);
        records.append(&mut moves.records);
        moves.records = records;
        moves
    }

    /// The decision the passes of `step` over `progress` wait for, asked at
    /// `now`; `None` when nobody is asked about every item: its steps hold
    /// no such approval, a test stands in for it, or there is no item.
    fn items_wait(
        &self,
        step: &LoopStep,
        progress: &LoopProgress,
        now: OffsetDateTime,
    ) -> Option<ApprovalWait> {
        if progress.items().is_empty() {
            return None;
        }
        let (node, approval) = step.items_approval()?;
        if self.mode.stands_in(node.key()) {
            return None;
        }
        Some(ApprovalWait {
            closes_at: now.saturating_add(approval.window().duration()),
            first: FirstApproval::NotGiven,
        })
    }

    /// Takes in the ended pass `pass`: what it gave back, then the next
    /// passes, and the loop's result once every pass gave back.
    ///
    /// A pass that did not succeed fails the loop step, and with it this
    /// execution; the passes still running are handed back to be stopped.
    /// A pass still running, one taken in already, or one whose loop is no
    /// longer running changes nothing, so hearing of a pass twice is safe.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `pass` is no pass of a loop of
    ///   this execution.
    pub fn settle_pass(&mut self, pass: &Self) -> Result<LoopMoves<T>, DomainError> {
        let Some(of) = pass.pass.as_ref().filter(|of| of.execution == self.id) else {
            return Err(DomainError::invalid(message!(
                "workflows-this-run-is-no-pass-of-this-loop",
                "this run is no pass of this run's loops"
            )));
        };
        if pass.status == ExecutionStatus::Running {
            return Ok(LoopMoves::nothing());
        }
        let Some(mut looping) = self.looping(&of.step) else {
            return Ok(LoopMoves::nothing());
        };
        let Some(slot) = looping.progress.passes_mut().get_mut(slot_of(of)) else {
            return Ok(LoopMoves::nothing());
        };
        if *slot != Pass::Running(pass.id) {
            return Ok(LoopMoves::nothing());
        }
        match pass.given_back() {
            Ok(done) => *slot = done,
            Err(failure) => return Ok(self.end_loop_without(&looping, failure, &pass.id)),
        }
        Ok(self.go_on(looping))
    }

    /// Stops this pass because its loop ended or failed first. Its steps
    /// ready or under way are abandoned, each with a record.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is no pass of a loop.
    /// - [`DomainError::InvalidTransition`] when it already ended.
    pub fn stop_pass(&mut self) -> Result<Vec<ExecutionRecord>, DomainError> {
        if self.pass.is_none() {
            return Err(DomainError::invalid(message!(
                "workflows-only-a-pass-of-a-loop-is-stopped",
                "only a pass of a loop is stopped with its loop"
            )));
        }
        let mut records = Vec::new();
        self.end(ExecutionEnd::LoopEnded, &mut records)?;
        Ok(records)
    }

    /// The passes still running of every loop step that was under way when
    /// this execution ended. Each is to be stopped.
    #[must_use]
    pub fn abandoned_passes(&self) -> Vec<WorkflowExecutionId> {
        self.steps
            .iter()
            .filter_map(|state| match state {
                StepState::Abandoned {
                    underway: Underway::Loop(progress),
                    ..
                } => Some(progress.running().copied().collect::<Vec<_>>()),
                StepState::Waiting
                | StepState::Ready { .. }
                | StepState::Running { .. }
                | StepState::Succeeded { .. }
                | StepState::Failed(_)
                | StepState::Skipped
                | StepState::Stopped
                | StepState::Abandoned { .. } => None,
            })
            .flatten()
            .collect()
    }

    /// The loop step `key` while it runs in this running execution.
    pub(super) fn looping(&self, key: &NodeKey) -> Option<Looping> {
        let running = self.running_step(key).ok()?;
        let NodeKind::Loop(step) = running.node.kind().clone() else {
            return None;
        };
        let Underway::Loop(progress) = running.underway else {
            return None;
        };
        Some(Looping {
            index: running.index,
            key: key.clone(),
            step,
            exposure: running.exposure,
            progress,
        })
    }

    /// Starts passes until the loop runs as many as it may at once or every
    /// item has one, then keeps what that came to.
    pub(super) fn go_on(&mut self, mut looping: Looping) -> LoopMoves<T> {
        if looping.progress.output_size() > MAX_SIZE {
            return self.end_loop(&looping, StepFailure::OutputTooLarge);
        }
        let (started, filled) = self.fill(&mut looping);
        let mut moves = match filled {
            Ok(()) => self.after_fill(looping),
            Err(failure) => self.end_loop(&looping, failure),
        };
        moves.started = started;
        moves
    }

    /// Starts the next passes of `looping`, recording each in its progress.
    /// The passes started are handed back even when one of them failed.
    fn fill(&self, looping: &mut Looping) -> (Vec<PassStart<T>>, Result<(), StepFailure>) {
        let mut started = Vec::new();
        while self.has_room(looping) {
            let index = looping.progress.passes().len();
            let Some(start) = self.pass_for(looping, index) else {
                return (started, Err(StepFailure::InputTooLarge));
            };
            let pass = match start.execution.status {
                ExecutionStatus::Running => Ok(Pass::Running(start.execution.id)),
                ExecutionStatus::Ended(_) => start.execution.given_back(),
            };
            started.push(start);
            match pass {
                Ok(pass) => looping.progress.passes_mut().push(pass),
                Err(failure) => return (started, Err(failure)),
            }
            if looping.progress.output_size() > MAX_SIZE {
                return (started, Err(StepFailure::OutputTooLarge));
            }
        }
        (started, Ok(()))
    }

    /// Whether another pass may start: nobody is still asked about every
    /// item, an item has none yet and fewer run than the loop allows at
    /// once.
    fn has_room(&self, looping: &Looping) -> bool {
        let progress = &looping.progress;
        let at_once = usize::try_from(looping.step.at_once()).unwrap_or(usize::MAX);
        progress.lets_passes_start()
            && progress.passes().len() < progress.items().len()
            && progress.running().count() < at_once
    }

    /// The pass for item `index`, started and moved on as far as the
    /// domain takes it. `None` when what it would start with is too large.
    fn pass_for(&self, looping: &Looping, index: usize) -> Option<PassStart<T>> {
        let item = looping.progress.items().get(index)?.clone();
        let index = u32::try_from(index).ok()?;
        let input = pass_input(looping.progress.shared(), item, index).ok()?;
        let of = PassOf {
            execution: self.id,
            step: looping.key.clone(),
            index,
        };
        let mut execution = self.pass_run(looping, of, input);
        let mut records = vec![ExecutionRecord::Started];
        execution.advance(&mut records);
        if let ItemsApproval::Given(approved) = looping.progress.approval() {
            records.extend(execution.let_through_items_approval(&approved.by));
        }
        Some(PassStart { execution, records })
    }

    /// The run of the loop's own steps that `of` names, starting with
    /// `input`, acting for this run's person under its version and deadline.
    fn pass_run(&self, looping: &Looping, of: PassOf, input: FlowData) -> Self {
        let now = crate::shared::clock::now();
        Self {
            id: WorkflowExecutionId::new(),
            workflow_id: self.workflow_id,
            version: self.version,
            graph: looping.step.body().clone(),
            acting_for: self.acting_for.clone(),
            authors: self.authors.clone(),
            failure_alert: self.failure_alert,
            mode: self.mode.within(looping.step.body()),
            cause: self.cause,
            pass: Some(of),
            chain_depth: self.chain_depth,
            input,
            exposure: looping.exposure,
            steps: vec![StepState::Waiting; looping.step.body().nodes().len()],
            status: ExecutionStatus::Running,
            deadline: self.deadline,
            created_at: now,
            updated_at: now,
            _scope: PhantomData,
        }
    }

    /// Keeps the loop's progress once its next passes started, or its
    /// result once every pass gave back.
    fn after_fill(&mut self, looping: Looping) -> LoopMoves<T> {
        let progress = looping.progress;
        if progress.done() < progress.items().len() {
            self.keep_progress(looping.index, progress);
            return LoopMoves::nothing();
        }
        let Ok(output) = FlowData::list(outputs(&progress)) else {
            return self.end_loop_at(looping.index, &progress, StepFailure::OutputTooLarge);
        };
        let exposure = passes_exposure(&progress).max(looping.exposure);
        let records = self.succeed(looping.index, output, exposure, Holding::ForGood);
        LoopMoves {
            records,
            ..LoopMoves::nothing()
        }
    }

    /// Fails the loop for `failure`, handing back its running passes to be
    /// stopped.
    fn end_loop(&mut self, looping: &Looping, failure: StepFailure) -> LoopMoves<T> {
        self.end_loop_at(looping.index, &looping.progress, failure)
    }

    /// Fails the loop for `failure`, which the pass `ended` reported, and
    /// hands back the other running passes to be stopped.
    fn end_loop_without(
        &mut self,
        looping: &Looping,
        failure: StepFailure,
        ended: &WorkflowExecutionId,
    ) -> LoopMoves<T> {
        let mut moves = self.end_loop(looping, failure);
        moves.stop.retain(|id| id != ended);
        moves
    }

    fn end_loop_at(
        &mut self,
        index: usize,
        progress: &LoopProgress,
        failure: StepFailure,
    ) -> LoopMoves<T> {
        let stop = progress.running().copied().collect();
        let records = self.fail(index, failure);
        LoopMoves {
            records,
            started: Vec::new(),
            stop,
        }
    }

    /// Writes `progress` into the running loop step at `index`.
    pub(super) fn keep_progress(&mut self, index: usize, progress: LoopProgress) {
        if let Some(StepState::Running { underway, .. }) = self.steps.get_mut(index) {
            *underway = Underway::Loop(progress);
        }
        self.touch();
    }

    /// What this ended pass gave back: the output of each last step that
    /// succeeded, under its key, with the most sensitive data in them.
    ///
    /// A pass that did not succeed gave back nothing, and fails its loop.
    fn given_back(&self) -> Result<Pass, StepFailure> {
        let index = self.pass.as_ref().map_or(0, |of| of.index);
        if self.status != ExecutionStatus::Ended(ExecutionEnd::Succeeded) {
            return Err(StepFailure::PassFailed(index));
        }
        let mut exposure = self.exposure;
        let mut fields: Vec<(FieldName, FlowData)> = Vec::new();
        for (node, state) in self.steps() {
            let StepState::Succeeded {
                output,
                exposure: carried,
                ..
            } = state
            else {
                continue;
            };
            if self.graph.outgoing(node.key()).next().is_some() {
                continue;
            }
            exposure = exposure.max(*carried);
            fields.push((node.key().as_field().clone(), output.clone()));
        }
        FlowData::map(fields)
            .map(|output| Pass::Done {
                execution: self.id,
                output,
                exposure,
            })
            .map_err(|_| StepFailure::OutputTooLarge)
    }
}

/// The progress a loop step starts with over `input`: its items and what
/// every pass is given beside them.
fn progress_of(step: &LoopStep, input: &FlowData) -> Result<LoopProgress, StepFailure> {
    let Some(FlowValue::List(items)) = input.at(step.over()).map(FlowData::value) else {
        return Err(StepFailure::NotAList);
    };
    let count = u32::try_from(items.len()).unwrap_or(u32::MAX);
    if count > step.most() {
        return Err(StepFailure::TooManyItems {
            count,
            most: step.most(),
        });
    }
    let shared = step
        .inputs()
        .apply(input)
        .map_err(|_| StepFailure::InputTooLarge)?;
    Ok(LoopProgress::new(items.to_vec(), shared))
}

/// Where in a loop's passes the pass `of` sits.
fn slot_of(of: &PassOf) -> usize {
    usize::try_from(of.index).unwrap_or(usize::MAX)
}

/// What every pass gave back, in the order of the items.
fn outputs(progress: &LoopProgress) -> Vec<FlowData> {
    progress
        .passes()
        .iter()
        .filter_map(|pass| match pass {
            Pass::Done { output, .. } => Some(output.clone()),
            Pass::Running(_) => None,
        })
        .collect()
}

/// The most sensitive data any pass gave back.
fn passes_exposure(progress: &LoopProgress) -> DataClassLevel {
    progress
        .passes()
        .iter()
        .filter_map(|pass| match pass {
            Pass::Done { exposure, .. } => Some(*exposure),
            Pass::Running(_) => None,
        })
        .max()
        .unwrap_or(DataClassLevel::Public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::data::FieldName;
    use crate::domains::workflows::design::node::{Node, Port};
    use crate::domains::workflows::execution::WorkflowExecutionRow;
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, ann, approval, approve, bob, copy, deciding, each, edge, key, listing, managing,
        started, state, stored,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;

    /// Ann's run lists `issues`, then loops over them with `body`,
    /// `at_once` at a time.
    fn looping_over(issues: &[&str], body: Vec<Node>, at_once: u32) -> Execution {
        started(
            vec![
                listing("search", issues),
                each("each", "search.issues", body, at_once),
            ],
            vec![edge("search", Port::Next, "each")],
        )
    }

    fn begun(execution: &mut Execution) -> LoopMoves<ResolvedTenant> {
        execution.begin_loop(&key("each")).unwrap()
    }

    fn progress(execution: &Execution) -> LoopProgress {
        let StepState::Running {
            underway: Underway::Loop(progress),
            ..
        } = state(execution, "each")
        else {
            panic!("the loop is not running");
        };
        progress
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    /// Ann loops over three issues, writing a note for each. Every pass
    /// settles the moment it starts, so the loop succeeds at once with a
    /// list of the three notes, in the order of the issues, and the run
    /// ends as succeeded.
    #[test]
    fn a_loop_gives_back_what_each_pass_gave_back_in_order() {
        let mut execution = looping_over(
            &["a", "b", "c"],
            vec![copy("note", &[("issue", "trigger.item")])],
            1,
        );

        let moves = begun(&mut execution);

        let StepState::Succeeded { output, .. } = state(&execution, "each") else {
            panic!("the loop did not succeed");
        };
        let FlowValue::List(notes) = output.value() else {
            panic!("the loop gave back no list");
        };
        let issues: Vec<&FlowData> = notes
            .iter()
            .filter_map(|pass| pass.field(&field("note")))
            .filter_map(|note| note.field(&field("issue")))
            .collect();
        assert_eq!(issues, [&text("a"), &text("b"), &text("c")]);
        assert_eq!(moves.started.len(), 3);
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Succeeded)
        );
    }

    /// Each pass acts for Ann, under her run's version, deadline and chain,
    /// at the exposure the loop was handed, and names the loop and its item.
    #[test]
    fn a_pass_acts_as_its_run_does_and_names_its_loop() {
        let mut execution = looping_over(&["a", "b"], vec![approval("check")], 2);

        let moves = begun(&mut execution);

        for (index, start) in (0..).zip(&moves.started) {
            let pass = &start.execution;
            assert_eq!(pass.acting_for(), execution.acting_for());
            assert_eq!(pass.version(), execution.version());
            assert_eq!(pass.deadline(), execution.deadline());
            assert_eq!(pass.chain_depth(), execution.chain_depth());
            assert_eq!(pass.exposure(), execution.exposure());
            assert_eq!(
                pass.pass(),
                Some(&PassOf {
                    execution: *execution.id(),
                    step: key("each"),
                    index,
                })
            );
            assert_eq!(start.records.first(), Some(&ExecutionRecord::Started));
        }
    }

    /// A loop over three issues, two at a time, starts two passes. Once the
    /// first is approved and taken in, the third starts. Once all three
    /// are, the loop succeeds.
    #[test]
    fn a_loop_runs_at_most_its_number_of_passes_at_once() {
        let mut execution = looping_over(&["a", "b", "c"], vec![approval("check")], 2);
        let mut passes: Vec<Execution> = begun(&mut execution)
            .started
            .into_iter()
            .map(|start| start.execution)
            .collect();
        let at_first = progress(&execution).running().count();

        approve(&mut passes[0], "check");
        let next = execution.settle_pass(&passes[0]).unwrap();
        let mut third = next.started.into_iter().next().unwrap().execution;
        approve(&mut passes[1], "check");
        execution.settle_pass(&passes[1]).unwrap();
        approve(&mut third, "check");
        execution.settle_pass(&third).unwrap();

        assert_eq!(at_first, 2);
        assert_eq!(third.pass().map(|of| of.index), Some(2));
        assert!(matches!(
            state(&execution, "each"),
            StepState::Succeeded { .. }
        ));
    }

    /// Bob refuses the first pass's approval. The loop fails naming that
    /// pass, the run fails, and the second pass, still running, is handed
    /// back to be stopped.
    #[test]
    fn a_failed_pass_fails_the_loop_and_stops_the_others() {
        let mut execution = looping_over(&["a", "b"], vec![approval("check")], 2);
        let mut passes: Vec<Execution> = begun(&mut execution)
            .started
            .into_iter()
            .map(|start| start.execution)
            .collect();
        passes[0].request_approval(&key("check")).unwrap();
        passes[0].deny(&key("check"), &deciding(&bob())).unwrap();

        let moves = execution.settle_pass(&passes[0]).unwrap();

        assert_eq!(
            state(&execution, "each"),
            StepState::Failed(StepFailure::PassFailed(0))
        );
        assert_eq!(moves.stop, [*passes[1].id()]);
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
    }

    /// A pass still waiting for its approval, and a pass taken in already,
    /// change nothing when heard of again.
    #[test]
    fn hearing_of_a_pass_twice_or_too_early_changes_nothing() {
        let mut execution = looping_over(&["a", "b"], vec![approval("check")], 1);
        let mut first = begun(&mut execution).started.remove(0).execution;
        let early = execution.settle_pass(&first).unwrap();
        approve(&mut first, "check");
        execution.settle_pass(&first).unwrap();

        let again = execution.settle_pass(&first).unwrap();

        assert!(early.records.is_empty() && early.started.is_empty());
        assert!(again.records.is_empty() && again.started.is_empty());
        assert_eq!(progress(&execution).done(), 1);
    }

    /// An approved pass from another execution cannot settle this run's
    /// loop; settling it returns a validation error.
    #[test]
    fn a_pass_of_another_run_is_refused() {
        let mut execution = looping_over(&["a"], vec![approval("check")], 1);
        let mut other = looping_over(&["a"], vec![approval("check")], 1);
        let mut pass = begun(&mut other).started.remove(0).execution;
        begun(&mut execution);
        approve(&mut pass, "check");

        let settled = execution.settle_pass(&pass);

        assert!(matches!(settled, Err(DomainError::Validation(_))));
    }

    /// A loop allowing ten issues fails on eleven before starting a pass.
    /// Giving the loop a value that is not a list fails it for that reason.
    #[test]
    fn a_list_too_long_or_no_list_at_all_fails_the_loop() {
        let issues: Vec<String> = (0..11).map(|n| format!("issue {n}")).collect();
        let names: Vec<&str> = issues.iter().map(String::as_str).collect();
        let mut too_long = looping_over(&names, vec![approval("check")], 1);
        let mut no_list = started(
            vec![
                listing("search", &["a"]),
                each("each", "search", vec![approval("check")], 1),
            ],
            vec![edge("search", Port::Next, "each")],
        );

        let long = begun(&mut too_long);
        begun(&mut no_list);

        assert!(long.started.is_empty());
        assert_eq!(
            state(&too_long, "each"),
            StepState::Failed(StepFailure::TooManyItems {
                count: 11,
                most: 10
            })
        );
        assert_eq!(
            state(&no_list, "each"),
            StepState::Failed(StepFailure::NotAList)
        );
    }

    /// A search that found nothing gives the loop an empty list. It
    /// succeeds at once with an empty list, starting no pass.
    #[test]
    fn a_loop_over_an_empty_list_succeeds_with_an_empty_list() {
        let mut execution = looping_over(&[], vec![approval("check")], 1);

        let moves = begun(&mut execution);

        assert!(moves.started.is_empty());
        assert!(matches!(
            state(&execution, "each"),
            StepState::Succeeded { output, .. } if output == FlowData::list(Vec::new()).unwrap()
        ));
    }

    /// Ann cancels her run while two passes wait. The loop step is
    /// abandoned, and both passes are named to be stopped. Each, stopped,
    /// ends as its loop did.
    #[test]
    fn a_run_that_ends_hands_back_its_running_passes_to_stop() {
        let mut execution = looping_over(&["a", "b"], vec![approval("check")], 2);
        let mut passes: Vec<Execution> = begun(&mut execution)
            .started
            .into_iter()
            .map(|start| start.execution)
            .collect();

        execution.cancel(&managing(&ann())).unwrap();
        let stopped = passes[0].stop_pass().unwrap();

        assert_eq!(
            execution.abandoned_passes(),
            [*passes[0].id(), *passes[1].id()]
        );
        assert_eq!(
            stopped.last(),
            Some(&ExecutionRecord::Ended(ExecutionEnd::LoopEnded))
        );
    }

    /// Stopping an ordinary execution as though it were a loop pass returns
    /// a validation error.
    #[test]
    fn only_a_pass_is_stopped_with_its_loop() {
        let mut execution = looping_over(&["a"], vec![approval("check")], 1);

        assert!(matches!(
            execution.stop_pass(),
            Err(DomainError::Validation(_))
        ));
    }

    /// A run with its loop under way, and the pass it started, are stored
    /// and read back as they were.
    #[test]
    fn a_running_loop_and_its_pass_are_read_back() {
        let mut execution = looping_over(&["a", "b"], vec![approval("check")], 1);
        let pass = begun(&mut execution).started.remove(0).execution;

        assert!(Execution::reconstitute(stored(&execution)).is_ok());
        assert!(Execution::reconstitute(stored(&pass)).is_ok());
    }

    /// Reconstitution rejects a loop with two running passes when it allows
    /// only one, and a run claiming to have ended with a loop despite not
    /// being a pass. Both rows are corrupt.
    #[test]
    fn a_stored_loop_or_pass_no_loop_could_make_is_corrupt() {
        let mut execution = looping_over(&["a", "b"], vec![approval("check")], 1);
        begun(&mut execution);
        let mut wide = progress(&execution);
        wide.passes_mut()
            .push(Pass::Running(WorkflowExecutionId::new()));
        let too_wide = WorkflowExecutionRow {
            steps: replaced(&execution, &wide),
            ..stored(&execution)
        };
        let not_a_pass = WorkflowExecutionRow {
            status: ExecutionStatus::Ended(ExecutionEnd::LoopEnded),
            ..stored(&execution)
        };

        assert!(refused_as_corrupt(&Execution::reconstitute(too_wide)));
        assert!(refused_as_corrupt(&Execution::reconstitute(not_a_pass)));
    }

    /// `execution`'s step states with the loop's progress replaced.
    fn replaced(execution: &Execution, progress: &LoopProgress) -> Vec<StepState> {
        execution
            .steps()
            .map(|(_, state)| match state {
                StepState::Running {
                    exposure,
                    seen,
                    underway: Underway::Loop(_),
                    started_at,
                } => StepState::Running {
                    exposure: *exposure,
                    seen: seen.clone(),
                    underway: Underway::Loop(progress.clone()),
                    started_at: *started_at,
                },
                other => other.clone(),
            })
            .collect()
    }
}
