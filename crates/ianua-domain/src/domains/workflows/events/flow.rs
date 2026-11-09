//! The records of a person making an agent flow and deleting it once its
//! run ended.

use time::OffsetDateTime;

use crate::domains::workflows::events::VersionRef;
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{PrincipalRef, WorkflowExecutionId};

/// A person made an agent flow, published and ready to start at once.
///
/// It stays out of colleagues' feeds: a flow is one person's own run of
/// agents. How its run ends is recorded, and notifies, as any run's end
/// does.
#[derive(Debug)]
pub(crate) struct WorkflowFlowCreated {
    /// The flow, as its one version.
    pub(crate) version: VersionRef,
    /// The person who made it.
    pub(crate) by: PrincipalRef,
    /// When it was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowFlowCreated => WorkflowsEvent::FlowCreated,
    fn payload(&self) -> EventData {
        self.version.payload().field("created_by", self.by.label())
    }
}

/// A flow whose run had ended was deleted, with that run.
#[derive(Debug)]
pub(crate) struct WorkflowFlowDeleted {
    /// The flow, as its one version.
    pub(crate) version: VersionRef,
    /// Its run, deleted with it.
    pub(crate) execution_id: WorkflowExecutionId,
    /// The person who deleted it.
    pub(crate) by: PrincipalRef,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowFlowDeleted => WorkflowsEvent::FlowDeleted,
    fn payload(&self) -> EventData {
        self.version
            .payload()
            .field("execution_id", self.execution_id.to_string())
            .field("deleted_by", self.by.label())
    }
}
