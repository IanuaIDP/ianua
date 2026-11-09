//! The records of a workflow's webhook secret being issued, replaced and
//! revoked. None of them carries the secret or its digest.

use time::OffsetDateTime;

use crate::domains::workflows::events::WORKFLOW;
use crate::shared::events::data::{EventData, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{EventLabel, PrincipalRef, WorkflowId, WorkflowTriggerId};

/// Which workflow's webhook secret an event is about, and who changed it.
#[derive(Debug, Clone)]
pub(crate) struct TriggerSecretRef {
    /// The secret, and the address its webhook is called at.
    pub(crate) trigger_id: WorkflowTriggerId,
    /// The workflow it starts.
    pub(crate) workflow_id: WorkflowId,
    /// The workflow's name when the event fired.
    pub(crate) label: EventLabel,
    /// The person who changed it.
    pub(crate) by: PrincipalRef,
}

impl TriggerSecretRef {
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "workflow",
                Reference::new(WORKFLOW, self.workflow_id.to_string(), self.label.as_str()),
            )
            .field("trigger_id", self.trigger_id.to_string())
            .field("changed_by", self.by.label())
    }
}

/// A secret was issued for a workflow's webhook. It was shown once to the
/// person who issued it; only its digest is kept.
#[derive(Debug)]
pub(crate) struct WorkflowTriggerSecretIssued {
    /// The credential reference and workflow identity, never the bearer value.
    pub(crate) secret: TriggerSecretRef,
    /// When it was issued.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowTriggerSecretIssued => WorkflowsEvent::TriggerSecretIssued,
    fn payload(&self) -> EventData {
        self.secret.payload()
    }
}

/// A workflow's webhook secret was replaced. A call with the old one starts
/// nothing more.
#[derive(Debug)]
pub(crate) struct WorkflowTriggerSecretRotated {
    /// The credential reference whose bearer value was replaced.
    pub(crate) secret: TriggerSecretRef,
    /// When it was replaced.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowTriggerSecretRotated => WorkflowsEvent::TriggerSecretRotated,
    fn payload(&self) -> EventData {
        self.secret.payload()
    }
}

/// A workflow's webhook secret was revoked. Its webhook starts nothing
/// until a new one is issued.
#[derive(Debug)]
pub(crate) struct WorkflowTriggerSecretRevoked {
    /// The credential reference withdrawn from webhook authentication.
    pub(crate) secret: TriggerSecretRef,
    /// When it was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowTriggerSecretRevoked => WorkflowsEvent::TriggerSecretRevoked,
    fn payload(&self) -> EventData {
        self.secret.payload()
    }
}
