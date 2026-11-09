//! The records that a loop started one pass, and that the pass ended, and
//! which record the start or end of an execution is: a run's own, a test's
//! end, or a pass's when it is one.
//!
//! A pass's records stay out of colleagues' feeds: a loop starts and ends
//! a pass for every item. The loop step that fails, and how the run ends,
//! notify.

use time::OffsetDateTime;

use crate::domains::workflows::events::{
    EXECUTION, EventAt, ExecutionRef, WorkflowExecutionEnded, WorkflowExecutionStarted,
    WorkflowTestEnded,
};
use crate::domains::workflows::execution::record::ExecutionEnd;
use crate::domains::workflows::execution::{ExecutionMode, PassOf, WorkflowExecution};
use crate::isolation::scope::TenantScope;
use crate::shared::events::data::{EventData, Reference};
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::scoped;
use crate::types::event_type::WorkflowsEvent;

/// A loop started one pass, for one item of its list.
#[derive(Debug)]
pub(crate) struct WorkflowPassStarted {
    /// The pass.
    pub(crate) execution: ExecutionRef,
    /// The loop it is a pass of.
    pub(crate) pass: PassOf,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowPassStarted => WorkflowsEvent::PassStarted,
    fn payload(&self) -> EventData {
        of_loop(self.execution.payload(), &self.pass)
    }
}

/// One pass of a loop ended.
#[derive(Debug)]
pub(crate) struct WorkflowPassEnded {
    /// The pass.
    pub(crate) execution: ExecutionRef,
    /// The loop it is a pass of.
    pub(crate) pass: PassOf,
    /// How it ended.
    pub(crate) end: ExecutionEnd,
    /// When it ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowPassEnded => WorkflowsEvent::PassEnded,
    fn payload(&self) -> EventData {
        let payload = of_loop(self.execution.payload(), &self.pass).field("end", self.end.as_str());
        match self.end {
            ExecutionEnd::Cancelled(by) => payload.field("cancelled_by", by.label()),
            ExecutionEnd::Succeeded
            | ExecutionEnd::Failed
            | ExecutionEnd::TimedOut
            | ExecutionEnd::LoopEnded => payload,
        }
    }
}

/// The start of `execution`: a run's, or a pass's when it is one.
pub(super) fn started_event<T: TenantScope>(
    execution: &WorkflowExecution<T>,
    at: EventAt,
) -> DomainEvent {
    let EventAt {
        tenant_id,
        reference,
        occurred_at,
    } = at;
    let Some(pass) = execution.pass() else {
        return scoped(
            tenant_id,
            WorkflowExecutionStarted::of(execution, reference, occurred_at),
        );
    };
    scoped(
        tenant_id,
        WorkflowPassStarted {
            execution: reference,
            pass: pass.clone(),
            occurred_at,
        },
    )
}

/// How `execution` ended: a run's end, a test's, or a pass's when it is
/// one.
pub(super) fn ended_event<T: TenantScope>(
    execution: &WorkflowExecution<T>,
    at: EventAt,
    end: ExecutionEnd,
) -> DomainEvent {
    let Some(pass) = execution.pass() else {
        return run_ended_event(execution, at, end);
    };
    let EventAt {
        tenant_id,
        reference,
        occurred_at,
    } = at;
    scoped(
        tenant_id,
        WorkflowPassEnded {
            execution: reference,
            pass: pass.clone(),
            end,
            occurred_at,
        },
    )
}

/// How a run that is no pass ended: a real run's end, which tells people,
/// or a test's, which tells nobody.
fn run_ended_event<T: TenantScope>(
    execution: &WorkflowExecution<T>,
    at: EventAt,
    end: ExecutionEnd,
) -> DomainEvent {
    let EventAt {
        tenant_id,
        reference,
        occurred_at,
    } = at;
    match execution.mode() {
        ExecutionMode::Live => scoped(
            tenant_id,
            WorkflowExecutionEnded {
                execution: reference,
                end,
                alert: execution.failure_alert(),
                occurred_at,
            },
        ),
        ExecutionMode::Test(_) => scoped(
            tenant_id,
            WorkflowTestEnded {
                execution: reference,
                end,
                occurred_at,
            },
        ),
    }
}

/// `payload` naming the run and loop step `pass` belongs to, and its item.
fn of_loop(payload: EventData, pass: &PassOf) -> EventData {
    payload
        .reference(
            "loop_execution",
            Reference::new(
                EXECUTION,
                pass.execution.to_string(),
                pass.execution.to_string(),
            ),
        )
        .field("loop_step", pass.step.as_str().to_owned())
        .field("item", pass.index.to_string())
}
