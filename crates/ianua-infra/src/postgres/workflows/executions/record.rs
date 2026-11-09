//! A workflow run as its row holds it: read back into the aggregate, and
//! written out from it, with the agent runs its steps wait on.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::design::authors::Authors;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::design::workflow::FailureAlert;
use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
use ianua_domain::domains::workflows::execution::step::{StepState, Underway};
use ianua_domain::domains::workflows::execution::{
    Cause, ExecutionMode, ExecutionStatus, PassOf, RestartFrom, StoredMode, WorkflowExecution,
    WorkflowExecutionRow,
};
use ianua_domain::domains::workflows::triggers::before::GuardedChange;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::{ChainDepth, EventOrigin};
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{EventType, PrincipalRef, WorkflowExecutionId, WorkflowId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::workflows::executions::words::{CauseKind, ModeKind, StatusKind};

const EXECUTION: Stored = Stored("workflow execution");

const GRAPH: Kept = Kept {
    entity: EXECUTION.0,
    column: "graph",
    shape: 1,
};

const ACTING_FOR: Kept = Kept {
    entity: EXECUTION.0,
    column: "acting_for",
    shape: 1,
};

const AUTHORS: Kept = Kept {
    entity: EXECUTION.0,
    column: "authors",
    shape: 1,
};

const INPUT: Kept = Kept {
    entity: EXECUTION.0,
    column: "input",
    shape: 1,
};

const STEPS: Kept = Kept {
    entity: EXECUTION.0,
    column: "steps",
    shape: 1,
};

const CANCELLED_BY: Kept = Kept {
    entity: EXECUTION.0,
    column: "cancelled_by",
    shape: 1,
};

/// A run as it is read. The store's checked queries fill it.
pub(super) struct ExecutionRecord {
    pub(super) id: Uuid,
    pub(super) workflow_id: Uuid,
    pub(super) version: i32,
    pub(super) graph: Value,
    pub(super) acting_for: Value,
    pub(super) authors: Value,
    pub(super) cause: String,
    pub(super) cause_event: Option<String>,
    pub(super) cause_event_depth: Option<i16>,
    pub(super) restarted_execution_id: Option<Uuid>,
    pub(super) restart_from: Option<String>,
    pub(super) pass_of: Option<Uuid>,
    pub(super) pass_step: Option<String>,
    pub(super) pass_index: Option<i32>,
    pub(super) chain_depth: i16,
    pub(super) input: Value,
    pub(super) exposure: String,
    pub(super) steps: Value,
    pub(super) status: String,
    pub(super) cancelled_by: Option<Value>,
    pub(super) deadline: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
    pub(super) failure_alert: String,
    pub(super) mode: String,
    pub(super) stand_ins: Vec<String>,
    pub(super) cause_change: Option<String>,
}

/// The loop a run is a pass of, as its columns hold it.
struct PassColumns {
    of: Option<Uuid>,
    step: Option<String>,
    index: Option<i32>,
}

/// What started a run, as its columns hold it.
#[derive(Clone, Copy)]
struct CauseColumns<'a> {
    kind: CauseKind,
    event: Option<&'a str>,
    event_depth: Option<i16>,
    restarted: Option<Uuid>,
    from: Option<&'a str>,
    change: Option<&'a str>,
}

/// The optional cause-specific values written beside the cause kind.
pub(super) struct WrittenCause {
    pub(super) event: Option<&'static str>,
    pub(super) event_depth: Option<i16>,
    pub(super) restarted: Option<Uuid>,
    pub(super) from: Option<&'static str>,
    pub(super) change: Option<&'static str>,
}

impl WrittenCause {
    /// Selects only the columns applicable to this cause.
    fn of(cause: Cause) -> Self {
        let (event, event_depth, restarted, from) = match cause {
            Cause::Manual | Cause::Schedule | Cause::Webhook | Cause::Service => {
                (None, None, None, None)
            }
            Cause::Event { event, origin } => (Some(event.as_str()), depth_of(origin), None, None),
            Cause::Restart { of, from } => (None, None, Some(*of.as_uuid()), Some(from.word())),
            Cause::Before { .. } => (None, None, None, None),
        };
        let change = change_of(cause);
        Self {
            event,
            event_depth,
            restarted,
            from,
            change,
        }
    }
}

impl ExecutionRecord {
    /// The run the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule a run keeps.
    pub(super) fn into_execution(self) -> Result<WorkflowExecution<ResolvedTenant>, DomainError> {
        let cause = self.cause()?;
        let pass = pass_from(PassColumns {
            of: self.pass_of,
            step: self.pass_step,
            index: self.pass_index,
        })?;
        let cancelled_by = cancelled_by_from(self.cancelled_by)?;
        WorkflowExecution::reconstitute(WorkflowExecutionRow {
            id: WorkflowExecutionId::from_uuid(self.id),
            workflow_id: WorkflowId::from_uuid(self.workflow_id),
            version: u32::try_from(self.version)
                .map_err(|_| DomainError::corrupt_row(EXECUTION.0, "a negative version"))?,
            graph: GRAPH.open(self.graph)?,
            acting_for: ACTING_FOR.open(self.acting_for)?,
            authors: Authors::from_stored(AUTHORS.open(self.authors)?)?,
            failure_alert: FailureAlert::from_stored(&self.failure_alert)?,
            mode: mode_from(EXECUTION.choice(&self.mode)?, self.stand_ins)?,
            cause,
            pass,
            chain_depth: depth_from(self.chain_depth)?,
            input: INPUT.open(self.input)?,
            exposure: DataClassLevel::from_stored(&self.exposure)?,
            steps: STEPS.open(self.steps)?,
            status: status_from(EXECUTION.choice(&self.status)?, cancelled_by)?,
            deadline: self.deadline,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// Validates the cause columns together before the remaining execution fields are rebuilt.
    fn cause(&self) -> Result<Cause, DomainError> {
        cause_from(CauseColumns {
            kind: EXECUTION.choice(&self.cause)?,
            event: self.cause_event.as_deref(),
            event_depth: self.cause_event_depth,
            restarted: self.restarted_execution_id,
            from: self.restart_from.as_deref(),
            change: self.cause_change.as_deref(),
        })
    }
}

/// Opens a recorded cancelling principal while leaving other execution statuses without one.
fn cancelled_by_from(stored: Option<Value>) -> Result<Option<PrincipalRef>, DomainError> {
    stored.map(|stored| CANCELLED_BY.open(stored)).transpose()
}

/// Whether a run is real or a test, from its mode and the steps a test
/// stood in for: only a test stands in.
fn mode_from(kind: ModeKind, stand_ins: Vec<String>) -> Result<StoredMode, DomainError> {
    let keys = stand_ins
        .into_iter()
        .map(|key| EXECUTION.value("stood-in step", NodeKey::new(key)))
        .collect::<Result<Vec<_>, DomainError>>()?;
    match (kind, keys.is_empty()) {
        (ModeKind::Live, true) => Ok(StoredMode::Live),
        (ModeKind::Test, _) => Ok(StoredMode::Test { stand_ins: keys }),
        (ModeKind::Live, false) => Err(DomainError::corrupt_row(
            EXECUTION.0,
            "a real run with stand-ins",
        )),
    }
}

/// The steps `mode` stands in for, as their column holds them.
fn stand_ins_of(mode: &ExecutionMode) -> Vec<String> {
    match mode {
        ExecutionMode::Live => Vec::new(),
        ExecutionMode::Test(plan) => plan
            .stand_ins()
            .iter()
            .map(|key| key.as_str().to_owned())
            .collect(),
    }
}

/// A stored chain depth.
fn depth_from(stored: i16) -> Result<ChainDepth, DomainError> {
    let depth = u8::try_from(stored)
        .map_err(|_| DomainError::corrupt_row(EXECUTION.0, "a chain depth out of range"))?;
    ChainDepth::from_stored(depth)
}

/// What started a run, from its columns.
fn cause_from(columns: CauseColumns<'_>) -> Result<Cause, DomainError> {
    if (columns.kind == CauseKind::Before) != columns.change.is_some() {
        return Err(contradicted());
    }
    match (columns.kind, columns.event, columns.restarted, columns.from) {
        (CauseKind::Before, None, None, None) => before_cause(columns.change),
        (CauseKind::Manual, None, None, None) => Ok(Cause::Manual),
        (CauseKind::Schedule, None, None, None) => Ok(Cause::Schedule),
        (CauseKind::Webhook, None, None, None) => Ok(Cause::Webhook),
        (CauseKind::Service, None, None, None) => Ok(Cause::Service),
        (CauseKind::Event, Some(event), None, None) => event_cause(event, columns.event_depth),
        (CauseKind::Restart, None, Some(of), Some(from)) => Ok(Cause::Restart {
            of: WorkflowExecutionId::from_uuid(of),
            from: EXECUTION.choice::<RestartFrom>(from)?,
        }),
        (
            CauseKind::Manual
            | CauseKind::Schedule
            | CauseKind::Webhook
            | CauseKind::Event
            | CauseKind::Service
            | CauseKind::Restart
            | CauseKind::Before,
            _,
            _,
            _,
        ) => Err(contradicted()),
    }
}

/// The refusal of a row whose cause columns contradict its cause.
fn contradicted() -> DomainError {
    DomainError::corrupt_row(EXECUTION.0, "a cause its columns contradict")
}

/// The cause of a run started before the change stored as `change`.
fn before_cause(change: Option<&str>) -> Result<Cause, DomainError> {
    let change = change.and_then(|name| GuardedChange::named(name).ok());
    let Some(change) = change else {
        return Err(DomainError::corrupt_row(
            EXECUTION.0,
            "an unknown guarded change",
        ));
    };
    Ok(Cause::Before { change })
}

/// The guarded change `cause` names, for a run started before one.
fn change_of(cause: Cause) -> Option<&'static str> {
    let Cause::Before { change } = cause else {
        return None;
    };
    Some(change.as_str())
}

/// Rebuilds an event cause only after its name and optional chain depth are validated.
fn event_cause(event: &str, depth: Option<i16>) -> Result<Cause, DomainError> {
    Ok(Cause::Event {
        event: EventType::parse(event)
            .ok_or_else(|| DomainError::corrupt_row(EXECUTION.0, "an unknown event"))?,
        origin: match depth {
            None => EventOrigin::Outside,
            Some(depth) => EventOrigin::Execution(depth_from(depth)?),
        },
    })
}

/// The loop a run is a pass of, from its columns: all three set, or none.
fn pass_from(columns: PassColumns) -> Result<Option<PassOf>, DomainError> {
    let (of, step, index) = match (columns.of, columns.step, columns.index) {
        (None, None, None) => return Ok(None),
        (Some(of), Some(step), Some(index)) => (of, step, index),
        (Some(_) | None, Some(_) | None, Some(_) | None) => {
            return Err(DomainError::corrupt_row(
                EXECUTION.0,
                "a pass its columns contradict",
            ));
        }
    };
    Ok(Some(PassOf {
        execution: WorkflowExecutionId::from_uuid(of),
        step: NodeKey::new(step)
            .map_err(|_| DomainError::corrupt_row(EXECUTION.0, "a loop step key"))?,
        index: u32::try_from(index)
            .map_err(|_| DomainError::corrupt_row(EXECUTION.0, "a negative pass"))?,
    }))
}

/// Where a run of `kind` stands, with who stopped a cancelled one.
fn status_from(
    kind: StatusKind,
    cancelled_by: Option<PrincipalRef>,
) -> Result<ExecutionStatus, DomainError> {
    let end = match (kind, cancelled_by) {
        (StatusKind::Running, None) => return Ok(ExecutionStatus::Running),
        (StatusKind::Succeeded, None) => ExecutionEnd::Succeeded,
        (StatusKind::Failed, None) => ExecutionEnd::Failed,
        (StatusKind::TimedOut, None) => ExecutionEnd::TimedOut,
        (StatusKind::LoopEnded, None) => ExecutionEnd::LoopEnded,
        (StatusKind::Cancelled, Some(by)) => ExecutionEnd::Cancelled(by),
        (
            StatusKind::Running
            | StatusKind::Succeeded
            | StatusKind::Failed
            | StatusKind::TimedOut
            | StatusKind::LoopEnded
            | StatusKind::Cancelled,
            _,
        ) => {
            return Err(DomainError::corrupt_row(
                EXECUTION.0,
                "a status its columns contradict",
            ));
        }
    };
    Ok(ExecutionStatus::Ended(end))
}

/// The agent runs `steps` wait on now: those of the steps under way, and
/// of those abandoned while under way, whose runs still report back.
fn runs_waited_on<'a>(steps: impl Iterator<Item = &'a StepState>) -> Vec<Uuid> {
    steps
        .filter_map(|state| match state {
            StepState::Running { underway, .. } | StepState::Abandoned { underway, .. } => {
                match underway {
                    Underway::AgentRun(run) => Some(*run.as_uuid()),
                    Underway::Action { .. }
                    | Underway::Approval(_)
                    | Underway::Timer { .. }
                    | Underway::Loop(_)
                    | Underway::Code(_) => None,
                }
            }
            StepState::Waiting
            | StepState::Ready { .. }
            | StepState::Succeeded { .. }
            | StepState::Failed(_)
            | StepState::Skipped
            | StepState::Stopped => None,
        })
        .collect()
}

/// A run's columns, as they are written, and the agent runs it waits on.
pub(super) struct ExecutionColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) workflow_id: &'a Uuid,
    pub(super) version: i32,
    pub(super) graph: Value,
    pub(super) acting_for: Value,
    pub(super) authors: Value,
    pub(super) cause: &'static str,
    pub(super) cause_detail: WrittenCause,
    pub(super) pass_of: Option<Uuid>,
    pub(super) pass_step: Option<&'a str>,
    pub(super) pass_index: Option<i32>,
    pub(super) chain_depth: i16,
    pub(super) input: Value,
    pub(super) exposure: &'static str,
    pub(super) steps: Value,
    pub(super) status: &'static str,
    pub(super) cancelled_by: Option<Value>,
    pub(super) deadline: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
    pub(super) failure_alert: &'static str,
    pub(super) mode: &'static str,
    pub(super) stand_ins: Vec<String>,
    pub(super) agent_runs: Vec<Uuid>,
}

impl<'a> ExecutionColumns<'a> {
    /// The columns `execution` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON, or a number does not fit its column.
    pub(super) fn of(
        execution: &'a WorkflowExecution<ResolvedTenant>,
    ) -> Result<Self, DomainError> {
        let steps: Vec<&StepState> = execution.steps().map(|(_, state)| state).collect();
        let cause = WrittenCause::of(execution.cause());
        let cancelled_by = cancelled_by_column(execution.status())?;
        Ok(Self {
            id: execution.id().as_uuid(),
            workflow_id: execution.workflow_id().as_uuid(),
            version: i32::try_from(execution.version()).map_err(DomainError::infra)?,
            graph: GRAPH.seal(execution.graph())?,
            acting_for: ACTING_FOR.seal(execution.acting_for())?,
            authors: AUTHORS.seal(execution.authors().as_slice())?,
            cause: CauseKind::of(execution.cause()).word(),
            cause_detail: cause,
            pass_of: execution.pass().map(|of| *of.execution.as_uuid()),
            pass_step: execution.pass().map(|of| of.step.as_str()),
            pass_index: pass_index_column(execution.pass())?,
            chain_depth: i16::from(execution.chain_depth().get()),
            input: INPUT.seal(execution.input())?,
            exposure: execution.exposure().as_str(),
            steps: STEPS.seal(&steps)?,
            status: StatusKind::of(execution.status()).word(),
            cancelled_by,
            deadline: execution.deadline(),
            created_at: execution.created_at(),
            updated_at: execution.updated_at(),
            failure_alert: execution.failure_alert().as_str(),
            mode: ModeKind::of(execution.mode()).word(),
            stand_ins: stand_ins_of(execution.mode()),
            agent_runs: runs_waited_on(steps.into_iter()),
        })
    }
}

/// Serializes the cancelling principal only for a cancelled execution.
fn cancelled_by_column(status: ExecutionStatus) -> Result<Option<Value>, DomainError> {
    match status {
        ExecutionStatus::Ended(ExecutionEnd::Cancelled(by)) => {
            Some(CANCELLED_BY.seal(&by)).transpose()
        }
        ExecutionStatus::Running | ExecutionStatus::Ended(_) => Ok(None),
    }
}

/// Checks that a loop pass index fits the stored column without inventing an index for other runs.
fn pass_index_column(pass: Option<&PassOf>) -> Result<Option<i32>, DomainError> {
    pass.map(|of| i32::try_from(of.index))
        .transpose()
        .map_err(DomainError::infra)
}

/// How deep in its chain an event came from, as its column holds it.
fn depth_of(origin: EventOrigin) -> Option<i16> {
    match origin {
        EventOrigin::Outside => None,
        EventOrigin::Execution(depth) => Some(i16::from(depth.get())),
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
    use ianua_domain::domains::workflows::design::node::{NodeKey, Port};
    use ianua_domain::domains::workflows::execution::step::{Holding, StepFailure, StepRefusal};
    use ianua_domain::domains::workflows::guardrail::finding::{GuardrailCheck, Unchecked};
    use ianua_domain::types::{Human, UserId};
    use serde_json::json;

    use super::*;
    use crate::test_support::rows::workflows::{ann, trigger_data, wait_graph};

    fn person() -> Value {
        json!({
            "account": {"User": "00000000-0000-0000-0000-000000000a11"},
            "person": "ann@acme.example"
        })
    }

    /// The graph a run carries is written in the shape pinned here, and
    /// reads back.
    #[test]
    fn the_graph_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "nodes": [{
                "key": "pause",
                "name": "pause",
                "kind": {"wait": {"duration": 3600}},
                "join": "all"
            }],
            "edges": []
        }});

        assert_eq!(GRAPH.seal(&wait_graph()).unwrap(), stored);
        assert_eq!(GRAPH.open::<WorkflowGraph>(stored).unwrap(), wait_graph());
    }

    /// The person a run acts for and the authors of its version are
    /// written in the shape pinned here, and read back.
    #[test]
    fn the_people_are_stored_in_their_pinned_shape() {
        let acting_for = json!({"v": 1, "value": person()});
        let authors = json!({"v": 1, "value": [person()]});

        assert_eq!(ACTING_FOR.seal(&ann()).unwrap(), acting_for);
        assert_eq!(AUTHORS.seal(&[ann()]).unwrap(), authors);
        assert_eq!(ACTING_FOR.open::<Human>(acting_for).unwrap(), ann());
        assert_eq!(AUTHORS.open::<Vec<Human>>(authors).unwrap(), [ann()]);
    }

    /// The trigger's data is written in the shape pinned here, its map as
    /// its fields in order, and reads back.
    #[test]
    fn the_input_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {"map": [["ok", true]]}});

        assert_eq!(INPUT.seal(&trigger_data()).unwrap(), stored);
        assert_eq!(INPUT.open::<FlowData>(stored).unwrap(), trigger_data());
    }

    /// Where each step stands is written in the shape pinned here, and
    /// reads back.
    #[test]
    fn the_steps_are_stored_in_their_pinned_shape() {
        let steps = vec![
            StepState::Waiting,
            StepState::Succeeded {
                output: FlowData::bool(true),
                exposure: DataClassLevel::Internal,
                seen: vec![NodeKey::new("pause").unwrap()],
                port: Port::Next,
                holds: Holding::ForGood,
            },
            StepState::Failed(StepFailure::Refused(StepRefusal::NoDelegation)),
        ];
        let stored = json!({"v": 1, "value": [
            "waiting",
            {"succeeded": {
                "output": true,
                "exposure": "Internal",
                "seen": ["pause"],
                "port": "next",
                "holds": "for_good"
            }},
            {"failed": {"refused": "no_delegation"}}
        ]});

        assert_eq!(STEPS.seal(&steps).unwrap(), stored);
        assert_eq!(STEPS.open::<Vec<StepState>>(stored).unwrap(), steps);
    }

    /// A loop under way, with one pass finished and one running, reads
    /// from the shape pinned here and is written back in it.
    #[test]
    fn a_loop_under_way_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": [{"running": {
            "exposure": "Internal",
            "seen": [],
            "underway": {"loop": {
                "items": ["a", "b"],
                "shared": {"map": [["channel", "ops"]]},
                "passes": [
                    {"done": {
                        "execution": "01a1a1ae-be67-7c20-ad97-f2dbfd32c854",
                        "output": {"map": [["note", true]]},
                        "exposure": "Internal"
                    }},
                    {"running": "01a1a1ae-be67-7c20-ad97-f2c23f697be4"}
                ]
            }},
            "started_at": "2027-01-15T08:00:00Z"
        }}]});

        let steps = STEPS.open::<Vec<StepState>>(stored.clone()).unwrap();

        assert!(matches!(
            steps.as_slice(),
            [StepState::Running {
                underway: Underway::Loop(_),
                ..
            }]
        ));
        assert_eq!(STEPS.seal(&steps).unwrap(), stored);
    }

    /// A loop waiting for one approval of both its items, no pass started,
    /// reads from the shape pinned here and is written back in it.
    #[test]
    fn a_loop_asking_for_every_item_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": [{"running": {
            "exposure": "Internal",
            "seen": [],
            "underway": {"loop": {
                "items": ["a", "b"],
                "shared": {"map": []},
                "passes": [],
                "approval": {"waiting": {
                    "closes_at": "2027-01-15T09:00:00Z",
                    "first": "not_given"
                }}
            }},
            "started_at": "2027-01-15T08:00:00Z"
        }}]});

        let steps = STEPS.open::<Vec<StepState>>(stored.clone()).unwrap();

        assert!(matches!(
            steps.as_slice(),
            [StepState::Running {
                underway: Underway::Loop(progress),
                ..
            }] if progress.approval().waiting().is_some()
        ));
        assert_eq!(STEPS.seal(&steps).unwrap(), stored);
    }

    /// A guardrail that stopped its run, for what its model-tricks check
    /// found, and one that could not read the classification rules, are
    /// written in the shape pinned here, and read back.
    #[test]
    fn a_stopped_guardrail_is_stored_in_its_pinned_shape() {
        let steps = vec![
            StepState::Failed(StepFailure::GuardrailFound(vec![
                GuardrailCheck::ModelTricks,
            ])),
            StepState::Failed(StepFailure::GuardrailUnchecked(Unchecked::RulesUnreadable)),
        ];
        let stored = json!({"v": 1, "value": [
            {"failed": {"guardrail_found": ["model_tricks"]}},
            {"failed": {"guardrail_unchecked": "rules_unreadable"}}
        ]});

        assert_eq!(STEPS.seal(&steps).unwrap(), stored);
        assert_eq!(STEPS.open::<Vec<StepState>>(stored).unwrap(), steps);
    }

    /// Who stopped a run is written in the shape pinned here, and reads
    /// back.
    #[test]
    fn who_cancelled_is_stored_in_its_pinned_shape() {
        let by = PrincipalRef::User(UserId::from_uuid(Uuid::nil()));
        let stored = json!({"v": 1, "value": {"User": "00000000-0000-0000-0000-000000000000"}});

        assert_eq!(CANCELLED_BY.seal(&by).unwrap(), stored);
        assert_eq!(CANCELLED_BY.open::<PrincipalRef>(stored).unwrap(), by);
    }
}
