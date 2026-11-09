//! What every step whose work happens outside the domain shares.
//!
//! That is finding it ready or under way, starting it, finishing it, and
//! refusing it.

use time::OffsetDateTime;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::design::node::{Node, NodeKey, NodeKind, Port};
use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::record::{ExecutionRecord, StepRecord};
use crate::domains::workflows::execution::step::{
    Attempt, Holding, StepFailure, StepRefusal, StepState, Underway,
};
use crate::domains::workflows::execution::steps::schedule::{TriggerData, input_of};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// A step ready to start.
pub(in crate::domains::workflows::execution) struct ReadyStep {
    pub(in crate::domains::workflows::execution) index: usize,
    pub(in crate::domains::workflows::execution) node: Node,
    pub(in crate::domains::workflows::execution) input: FlowData,
    pub(in crate::domains::workflows::execution) exposure: DataClassLevel,
    pub(in crate::domains::workflows::execution) seen: Vec<NodeKey>,
    pub(in crate::domains::workflows::execution) attempt: Attempt,
}

/// A step whose work is under way.
pub(in crate::domains::workflows::execution) struct RunningStep {
    pub(in crate::domains::workflows::execution) index: usize,
    pub(in crate::domains::workflows::execution) node: Node,
    pub(in crate::domains::workflows::execution) exposure: DataClassLevel,
    pub(in crate::domains::workflows::execution) seen: Vec<NodeKey>,
    pub(in crate::domains::workflows::execution) underway: Underway,
    pub(in crate::domains::workflows::execution) started_at: OffsetDateTime,
}

/// Whether a step reporting back still moves the execution on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::domains::workflows::execution) enum Phase {
    /// The execution is running, and goes on from the step.
    Live,
    /// The execution ended while the step's work was under way. What came
    /// of it is recorded, and nothing goes on from it.
    Late,
}

/// A step whose outside work is reporting what came of it.
pub(in crate::domains::workflows::execution) struct ReportingStep {
    pub(in crate::domains::workflows::execution) index: usize,
    pub(in crate::domains::workflows::execution) exposure: DataClassLevel,
    pub(in crate::domains::workflows::execution) seen: Vec<NodeKey>,
    pub(in crate::domains::workflows::execution) underway: Underway,
    pub(in crate::domains::workflows::execution) phase: Phase,
}

/// What came of a step's outside work.
pub(in crate::domains::workflows::execution) enum Settled {
    /// It produced this, carrying data this sensitive.
    Output(FlowData, DataClassLevel),
    /// It failed.
    Failure(StepFailure),
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// The ready step called `key`.
    pub(in crate::domains::workflows::execution) fn ready_step(
        &self,
        key: &NodeKey,
    ) -> Result<ReadyStep, DomainError> {
        self.ensure_open()?;
        let index = self.position(key)?;
        let (node, state) = self.steps().nth(index).ok_or(DomainError::NotFound)?;
        let StepState::Ready {
            input,
            exposure,
            seen,
            attempt,
        } = state
        else {
            return Err(DomainError::invalid_transition(message!(
                "workflows-this-step-is-not-ready-to",
                "this step is not ready to start"
            )));
        };
        Ok(ReadyStep {
            index,
            node: node.clone(),
            input: input.clone(),
            exposure: *exposure,
            seen: seen.clone(),
            attempt: *attempt,
        })
    }

    /// The running step called `key`.
    pub(in crate::domains::workflows::execution) fn running_step(
        &self,
        key: &NodeKey,
    ) -> Result<RunningStep, DomainError> {
        self.ensure_open()?;
        let index = self.position(key)?;
        let (node, state) = self.steps().nth(index).ok_or(DomainError::NotFound)?;
        let StepState::Running {
            exposure,
            seen,
            underway,
            started_at,
        } = state
        else {
            return Err(DomainError::invalid_transition(message!(
                "workflows-this-step-is-not-running",
                "this step is not running"
            )));
        };
        Ok(RunningStep {
            index,
            node: node.clone(),
            exposure: *exposure,
            seen: seen.clone(),
            underway: underway.clone(),
            started_at: *started_at,
        })
    }

    /// The step called `key` whose outside work reports back.
    ///
    /// It is running in a running execution, or abandoned in one that
    /// ended.
    pub(in crate::domains::workflows::execution) fn reporting_step(
        &self,
        key: &NodeKey,
    ) -> Result<ReportingStep, DomainError> {
        let index = self.position(key)?;
        let (_, state) = self.steps().nth(index).ok_or(DomainError::NotFound)?;
        if let StepState::Abandoned {
            exposure,
            seen,
            underway,
        } = state
        {
            return Ok(ReportingStep {
                index,
                exposure: *exposure,
                seen: seen.clone(),
                underway: underway.clone(),
                phase: Phase::Late,
            });
        }
        let running = self.running_step(key)?;
        Ok(ReportingStep {
            index,
            exposure: running.exposure,
            seen: running.seen,
            underway: running.underway,
            phase: Phase::Live,
        })
    }

    /// The input the steps in `seen` and the trigger make, as a step that
    /// sees them started with.
    pub(in crate::domains::workflows::execution) fn input_seen_by(
        &self,
        seen: &[NodeKey],
    ) -> Result<FlowData, DomainError> {
        let trigger = TriggerData {
            input: &self.input,
            exposure: self.exposure,
        };
        input_of(&self.graph, &self.steps, seen, trigger)
    }

    /// Starts the ready step's outside work at `started_at`.
    ///
    /// Any end of a pause was counted from the same instant. So a stored
    /// row never depends on two readings of the clock.
    pub(in crate::domains::workflows::execution) fn begin_step(
        &mut self,
        ready: ReadyStep,
        underway: Underway,
        started_at: OffsetDateTime,
    ) -> Vec<ExecutionRecord> {
        let mut records = vec![ExecutionRecord::step(ready.node.key(), StepRecord::Started)];
        let state = StepState::Running {
            exposure: ready.exposure,
            seen: ready.seen,
            underway,
            started_at,
        };
        self.settle(ready.index, state, &mut records);
        records
    }

    /// Records what came of a reporting step's work, and goes on from it
    /// while the execution runs.
    pub(in crate::domains::workflows::execution) fn settle_reported(
        &mut self,
        step: ReportingStep,
        settled: Settled,
    ) -> Vec<ExecutionRecord> {
        match (step.phase, settled) {
            (Phase::Live, Settled::Output(output, exposure)) => {
                self.succeed(step.index, output, exposure, Holding::ForGood)
            }
            (Phase::Live, Settled::Failure(failure)) => self.fail(step.index, failure),
            (Phase::Late, settled) => self.record_late(step.index, step.seen, settled),
        }
    }

    fn record_late(
        &mut self,
        index: usize,
        seen: Vec<NodeKey>,
        settled: Settled,
    ) -> Vec<ExecutionRecord> {
        let Some(key) = self.graph.nodes().get(index).map(|node| node.key().clone()) else {
            return Vec::new();
        };
        let (state, happened) = match settled {
            Settled::Output(output, exposure) => (
                StepState::Succeeded {
                    output,
                    exposure,
                    seen,
                    port: Port::Next,
                    holds: Holding::ForGood,
                },
                StepRecord::Succeeded(Port::Next),
            ),
            Settled::Failure(failure) => (
                StepState::Failed(failure.clone()),
                StepRecord::Failed(failure),
            ),
        };
        self.put(index, state);
        vec![ExecutionRecord::step(&key, happened)]
    }

    /// The step at `index` finished with `output`, leaving by its one way
    /// out. Its result stays valid as `holds` says.
    pub(in crate::domains::workflows::execution) fn succeed(
        &mut self,
        index: usize,
        output: FlowData,
        exposure: DataClassLevel,
        holds: Holding,
    ) -> Vec<ExecutionRecord> {
        let mut records = Vec::new();
        if let Some(node) = self.graph.nodes().get(index) {
            records.push(ExecutionRecord::step(
                node.key(),
                StepRecord::Succeeded(Port::Next),
            ));
        }
        let state = StepState::Succeeded {
            output,
            exposure,
            seen: self.seen_by(index),
            port: Port::Next,
            holds,
        };
        self.settle(index, state, &mut records);
        records
    }

    /// The earlier steps the running step at `index` sees.
    fn seen_by(&self, index: usize) -> Vec<NodeKey> {
        match self.steps.get(index) {
            Some(StepState::Running { seen, .. } | StepState::Ready { seen, .. }) => seen.clone(),
            Some(_) | None => Vec::new(),
        }
    }

    /// The step at `index` failed, and with it the execution.
    pub(in crate::domains::workflows::execution) fn fail(
        &mut self,
        index: usize,
        failure: StepFailure,
    ) -> Vec<ExecutionRecord> {
        let mut records = Vec::new();
        if let Some(node) = self.graph.nodes().get(index) {
            records.push(ExecutionRecord::step(
                node.key(),
                StepRecord::Failed(failure.clone()),
            ));
        }
        self.settle(index, StepState::Failed(failure), &mut records);
        records
    }

    /// Fails the ready step `key` because something its work needs before
    /// it may run is missing.
    ///
    /// Examples are no live delegation, an account it may not use, or an
    /// operation no longer offered. The refusal is recorded like any
    /// failure, and the execution fails.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not ready.
    /// - [`DomainError::InvalidTransition`] when the execution has ended.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    /// - [`DomainError::Validation`] when a step of this kind is never
    ///   refused for `refusal`. The record would say the wrong thing.
    pub fn refuse(
        &mut self,
        key: &NodeKey,
        refusal: StepRefusal,
    ) -> Result<Vec<ExecutionRecord>, DomainError> {
        let ready = self.ready_step(key)?;
        if !refusal.fits(ready.node.kind()) {
            return Err(DomainError::invalid(message!(
                "workflows-a-step-is-not-refused-for",
                format!(
                    "a {} step is not refused for {}",
                    ready.node.kind().as_str(),
                    refusal.as_str()
                )
            )));
        }
        Ok(self.fail(ready.index, StepFailure::Refused(refusal)))
    }

    /// Whether every approval right before `node`, reached through
    /// conditions and transforms only, is still valid.
    ///
    /// People approved what the step does for a set window. It must run
    /// inside that window, as an agent's approval must. Checked before any
    /// outside work starts.
    pub(in crate::domains::workflows::execution) fn approvals_before_still_hold(
        &self,
        node: &Node,
    ) -> bool {
        let now = crate::shared::clock::now();
        let mut frontier = vec![node.key()];
        let mut passed: Vec<&NodeKey> = Vec::new();
        while let Some(key) = frontier.pop() {
            for (from, state) in self.leading_into(key) {
                match from.kind() {
                    NodeKind::Approval(_) if !still_holds(state, now) => return false,
                    NodeKind::Condition(_) | NodeKind::Transform(_)
                        if !passed.contains(&from.key()) =>
                    {
                        passed.push(from.key());
                        frontier.push(from.key());
                    }
                    NodeKind::Approval(_)
                    | NodeKind::Condition(_)
                    | NodeKind::Transform(_)
                    | NodeKind::AgentRun(_)
                    | NodeKind::Action(_)
                    | NodeKind::Wait(_)
                    | NodeKind::Loop(_)
                    | NodeKind::Code(_)
                    | NodeKind::Guardrail(_) => {}
                }
            }
        }
        true
    }

    /// Each step an edge leads from into `key`, with where it stands.
    fn leading_into<'a>(&'a self, key: &'a NodeKey) -> Vec<(&'a Node, &'a StepState)> {
        self.graph
            .incoming(key)
            .filter_map(|edge| self.steps().find(|(node, _)| node.key() == edge.from()))
            .collect()
    }
}

/// Whether an approval step's result is still valid at `now`.
///
/// An approval that has not finished covers nothing yet, so this is true
/// for it.
fn still_holds(state: &StepState, now: OffsetDateTime) -> bool {
    match state {
        StepState::Succeeded { holds, .. } => holds.holds_at(now),
        StepState::Waiting
        | StepState::Ready { .. }
        | StepState::Running { .. }
        | StepState::Failed(_)
        | StepState::Skipped
        | StepState::Stopped
        | StepState::Abandoned { .. } => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::execution::ExecutionStatus;
    use crate::domains::workflows::execution::record::ExecutionEnd;
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, action, agent_step, key, started, state, wait,
    };
    use crate::types::{AgentId, IntegrationAccountId};

    fn storing() -> Execution {
        started(
            vec![action("store", IntegrationAccountId::new())],
            Vec::new(),
        )
    }

    /// A ready step that stores a row cannot use its account. It is refused
    /// with that reason on the record, and the execution fails at once
    /// instead of waiting for its deadline.
    #[test]
    fn a_refused_step_fails_on_the_record() {
        let mut execution = storing();
        let refusal = StepFailure::Refused(StepRefusal::AccountNotUsable);

        let records = execution
            .refuse(&key("store"), StepRefusal::AccountNotUsable)
            .unwrap();

        assert_eq!(
            records.first(),
            Some(&ExecutionRecord::step(
                &key("store"),
                StepRecord::Failed(refusal.clone())
            ))
        );
        assert_eq!(state(&execution, "store"), StepState::Failed(refusal));
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
    }

    /// An agent step is refused for lacking a delegation. Refusing it again
    /// is a wrong move, since it has already failed.
    #[test]
    fn only_a_ready_step_is_refused() {
        let mut execution = started(vec![agent_step(AgentId::new(), &[])], Vec::new());
        execution
            .refuse(&key("summarise"), StepRefusal::NoDelegation)
            .unwrap();

        let again = execution.refuse(&key("summarise"), StepRefusal::NoDelegation);

        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
    }

    /// A wait step refused for an unusable account, and an action step
    /// refused for a missing delegation, are both refused. The action step
    /// stays ready, so the record never gives a reason that cannot apply.
    #[test]
    fn a_refusal_that_does_not_fit_the_step_is_refused() {
        let mut pausing = started(vec![wait("pause")], Vec::new());
        let mut storing = storing();

        let on_a_wait = pausing.refuse(&key("pause"), StepRefusal::AccountNotUsable);
        let wrong_reason = storing.refuse(&key("store"), StepRefusal::NoDelegation);

        assert!(matches!(on_a_wait, Err(DomainError::Validation(_))));
        assert!(matches!(wrong_reason, Err(DomainError::Validation(_))));
        assert!(matches!(state(&storing, "store"), StepState::Ready { .. }));
    }
}
