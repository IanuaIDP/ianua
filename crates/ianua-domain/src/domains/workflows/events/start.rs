//! The records that an execution started, or that a version did not start
//! for the person it would act for.

use time::OffsetDateTime;

use crate::domains::workflows::events::{ExecutionRef, VersionRef};
use crate::domains::workflows::execution::{Cause, StartRefusal, WorkflowExecution};
use crate::isolation::scope::TenantScope;
use crate::shared::events::event::tenant_event;
use crate::types::PrincipalRef;
use crate::types::event_type::WorkflowsEvent;

/// An execution started.
///
/// One started again after a failed run names that run, so the trail
/// links the two.
#[derive(Debug)]
pub(crate) struct WorkflowExecutionStarted {
    /// The newly started run and the exact definition revision it follows.
    pub(crate) execution: ExecutionRef,
    /// The person it acts for.
    pub(crate) acting_for: PrincipalRef,
    /// What started it.
    pub(crate) cause: Cause,
    /// How many executions, this one included, led to it.
    pub(crate) chain_depth: u8,
    /// Whether it is a real run or a test, so a test is never read as work
    /// done.
    pub(crate) mode: &'static str,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

impl WorkflowExecutionStarted {
    /// The start of `execution`, which `reference` names.
    pub(in crate::domains::workflows::events) fn of<T: TenantScope>(
        execution: &WorkflowExecution<T>,
        reference: ExecutionRef,
        occurred_at: OffsetDateTime,
    ) -> Self {
        Self {
            execution: reference,
            acting_for: execution.acting_for().principal(),
            cause: execution.cause(),
            chain_depth: execution.chain_depth().get(),
            mode: execution.mode().as_str(),
            occurred_at,
        }
    }
}

tenant_event! {
    WorkflowExecutionStarted => WorkflowsEvent::ExecutionStarted,
    fn payload(&self) -> EventData {
        let payload = self
            .execution
            .payload()
            .field("acting_for", self.acting_for.label())
            .field("cause", self.cause.as_str())
            .field("chain_depth", self.chain_depth.to_string())
            .field("mode", self.mode);
        match self.cause {
            Cause::Restart { of, .. } => payload.field("restarts", of.to_string()),
            Cause::Manual
            | Cause::Schedule
            | Cause::Webhook
            | Cause::Service
            | Cause::Event { .. }
            | Cause::Before { .. } => payload,
        }
    }
}

/// A schedule, webhook or event did not start a version, because the person
/// it would act for may not have it run.
///
/// It notifies colleagues. Ann published the nightly payroll run and then
/// left. Each night its schedule is refused, and this tells the team payroll
/// stopped, so someone drafts and publishes it under their own name.
#[derive(Debug)]
pub(crate) struct WorkflowStartRefused {
    /// The version that did not start.
    pub(crate) version: VersionRef,
    /// The person it would have acted for.
    pub(crate) acting_for: PrincipalRef,
    /// What tried to start it.
    pub(crate) cause: &'static str,
    /// Why it did not start.
    pub(crate) refusal: StartRefusal,
    /// When it was refused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowStartRefused => WorkflowsEvent::StartRefused,
    fn payload(&self) -> EventData {
        self.version
            .payload()
            .field("acting_for", self.acting_for.label())
            .field("cause", self.cause)
            .field("refusal", self.refusal.as_str())
    }
}
