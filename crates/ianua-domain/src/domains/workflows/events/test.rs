//! The records a test of a draft leaves where a real run's would tell
//! people: a step that ran for real and failed, and how the test ended.
//!
//! A test is a person trying their draft on example data. Its records stay
//! in the audit trail and out of feeds and alerts, so a test that fails
//! never reads as a broken workflow to the tenant's administrators.

use time::OffsetDateTime;

use crate::domains::workflows::design::node::NodeKey;
use crate::domains::workflows::events::{EventAt, ExecutionRef, StepRef, ended_payload};
use crate::domains::workflows::execution::record::ExecutionEnd;
use crate::domains::workflows::execution::step::StepFailure;
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::scoped;
use crate::types::event_type::WorkflowsEvent;

/// In a test, a step that ran for real failed.
#[derive(Debug)]
pub(crate) struct WorkflowTestStepFailed {
    /// The node instance that performed real work during the test and failed.
    pub(crate) step: StepRef,
    /// Why.
    pub(crate) failure: StepFailure,
    /// When it failed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowTestStepFailed => WorkflowsEvent::TestStepFailed,
    fn payload(&self) -> EventData {
        self.step
            .payload()
            .field("failure", self.failure.code())
            .field("detail", self.failure.detail())
    }
}

/// Records a trial execution's terminal outcome separately from live workflow activity.
#[derive(Debug)]
pub(crate) struct WorkflowTestEnded {
    /// The test.
    pub(crate) execution: ExecutionRef,
    /// How it ended.
    pub(crate) end: ExecutionEnd,
    /// When it ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowTestEnded => WorkflowsEvent::TestEnded,
    fn payload(&self) -> EventData {
        ended_payload(&self.execution, self.end)
    }
}

/// The record that the step `key` of a test failed as `failure` says.
pub(super) fn failed_step_event(at: EventAt, key: NodeKey, failure: StepFailure) -> DomainEvent {
    scoped(
        at.tenant_id,
        WorkflowTestStepFailed {
            step: StepRef {
                execution: at.reference,
                key,
            },
            failure,
            occurred_at: at.occurred_at,
        },
    )
}
