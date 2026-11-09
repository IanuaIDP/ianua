//! The records that a step is tried again: an integration turned its call
//! away, or the tenant's plan had no room for its agent run.

use time::OffsetDateTime;

use crate::domains::workflows::events::StepRef;
use crate::domains::workflows::execution::record::TurnedAwayCall;
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;

/// An integration turned an action step's call away, and the step calls
/// again once it is due.
///
/// It stays out of colleagues' feeds. A call that is turned away every time
/// fails the step, and that failure notifies.
#[derive(Debug)]
pub(crate) struct WorkflowStepCallTurnedAway {
    /// The node instance waiting until its refused call can be retried.
    pub(crate) step: StepRef,
    /// The call, and when it is made again.
    pub(crate) call: TurnedAwayCall,
    /// When it was turned away.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowStepCallTurnedAway => WorkflowsEvent::StepCallTurnedAway,
    fn payload(&self) -> EventData {
        self.step
            .payload()
            .field("attempts", self.call.tries.get().to_string())
            .field("scheduled_at", self.call.due.to_string())
            .field("detail", self.call.reason.as_str().to_owned())
    }
}

/// An agent run step was put off because the tenant had as many agent runs
/// in flight as its plan allows, and it is tried again once due.
///
/// It stays out of colleagues' feeds, since a full plan puts a step off
/// every minute until a run ends.
#[derive(Debug)]
pub(crate) struct WorkflowStepDeferred {
    /// The node instance delayed by the tenant's concurrent-run limit.
    pub(crate) step: StepRef,
    /// When it is tried again.
    pub(crate) due: OffsetDateTime,
    /// When it was put off.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowStepDeferred => WorkflowsEvent::StepDeferred,
    fn payload(&self) -> EventData {
        self.step
            .payload()
            .field("scheduled_at", self.due.to_string())
            .field("reason", "active_agent_run_limit")
    }
}
