//! Events from people and agents checking an agent: approvals, reviews and
//! intent drift.

use time::OffsetDateTime;

use crate::domains::agents::oversight::review::{CitedEvidence, VerdictKind, VerdictNote};
use crate::shared::clock;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::scoped;
use crate::types::event_type::AgentsEvent;
use crate::types::{AgentId, ApprovalId, DelegationId, EventLabel, ReviewAssignmentId, TenantId};

/// An agent paused an action and asked a person to approve it.
#[derive(Debug)]
pub struct AgentApprovalRequested {
    /// The delegation the action would act under.
    pub(crate) delegation_id: DelegationId,
    /// The delegation's name when the event fired, or its id if it has none.
    pub(crate) delegation_label: EventLabel,
    /// The approval request awaiting a decision.
    pub(crate) approval_id: ApprovalId,
    /// The approval's name when the event fired, or its id if it has none.
    pub(crate) approval_label: EventLabel,
    /// When it was requested.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentApprovalRequested => AgentsEvent::ApprovalRequested,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "delegation",
                Reference::new(
                    RefKind::DELEGATION,
                    self.delegation_id.to_string(),
                    self.delegation_label.as_str(),
                ),
            )
            .reference(
                "approval",
                Reference::new(
                    RefKind::APPROVAL,
                    self.approval_id.to_string(),
                    self.approval_label.as_str(),
                ),
            )
    }
}

/// A person approved an agent's paused action.
#[derive(Debug)]
pub(crate) struct AgentApprovalGranted {
    /// The agent whose action was approved.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The approval request that was decided.
    pub(crate) approval_id: ApprovalId,
    /// The approval's name when the event fired, or its id if it has none.
    pub(crate) approval_label: EventLabel,
    /// How long the request waited for this decision, in whole seconds.
    ///
    /// Many very short waits suggest a person approving without reading.
    pub(crate) seconds_to_decide: i64,
    /// When it was approved.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentApprovalGranted => AgentsEvent::ApprovalGranted,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .reference(
                "approval",
                Reference::new(
                    RefKind::APPROVAL,
                    self.approval_id.to_string(),
                    self.approval_label.as_str(),
                ),
            )
            .field("seconds_to_decide", self.seconds_to_decide.to_string())
    }
}

/// A person gave the first of the two approvals a high-risk agent action needs.
///
/// The action still waits for a second, different person.
#[derive(Debug)]
pub(crate) struct AgentApprovalSigned {
    /// The agent whose action is waiting.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The approval request.
    pub(crate) approval_id: ApprovalId,
    /// The approval's label when the event fired.
    pub(crate) approval_label: EventLabel,
    /// How long the request had waited, in whole seconds.
    pub(crate) seconds_to_decide: i64,
    /// When it was signed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentApprovalSigned => AgentsEvent::ApprovalSigned,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .reference(
                "approval",
                Reference::new(
                    RefKind::APPROVAL,
                    self.approval_id.to_string(),
                    self.approval_label.as_str(),
                ),
            )
            .field("seconds_to_decide", self.seconds_to_decide.to_string())
    }
}

/// A person refused an agent's paused action.
#[derive(Debug)]
pub(crate) struct AgentApprovalDenied {
    /// The agent whose action was denied.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The approval request that was decided.
    pub(crate) approval_id: ApprovalId,
    /// The approval's name when the event fired, or its id if it has none.
    pub(crate) approval_label: EventLabel,
    /// When it was denied.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentApprovalDenied => AgentsEvent::ApprovalDenied,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .reference(
                "approval",
                Reference::new(
                    RefKind::APPROVAL,
                    self.approval_id.to_string(),
                    self.approval_label.as_str(),
                ),
            )
    }
}

/// A paused action's request was taken back, undecided, because a person
/// stopped the run that raised it.
///
/// It is recorded apart from a denial, since nobody refused the action. The
/// run will never take it.
#[derive(Debug)]
pub(crate) struct AgentApprovalWithdrawn {
    /// The agent whose run was stopped.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The approval request that was taken back.
    pub(crate) approval_id: ApprovalId,
    /// The approval's name when the event fired, or its id if it has none.
    pub(crate) approval_label: EventLabel,
    /// When it was taken back.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentApprovalWithdrawn => AgentsEvent::ApprovalWithdrawn,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .reference(
                "approval",
                Reference::new(
                    RefKind::APPROVAL,
                    self.approval_id.to_string(),
                    self.approval_label.as_str(),
                ),
            )
    }
}

/// A person assigned one agent to review another.
#[derive(Debug)]
pub(crate) struct AgentReviewerAssigned {
    /// The relationship granting one agent oversight of another.
    pub(crate) assignment_id: ReviewAssignmentId,
    /// The reviewing agent.
    pub(crate) reviewer: AgentId,
    /// The reviewed agent.
    pub(crate) reviewed: AgentId,
    /// When it was assigned.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentReviewerAssigned => AgentsEvent::ReviewerAssigned,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("assignment_id", self.assignment_id.to_string())
            .field("reviewer_agent_id", self.reviewer.to_string())
            .field("reviewed_agent_id", self.reviewed.to_string())
    }
}

/// A person ended a review assignment.
#[derive(Debug)]
pub(crate) struct AgentReviewEnded {
    /// The oversight relationship that no longer permits review.
    pub(crate) assignment_id: ReviewAssignmentId,
    /// When it ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentReviewEnded => AgentsEvent::ReviewEnded,
    fn payload(&self) -> EventData {
        EventData::new().field("assignment_id", self.assignment_id.to_string())
    }
}

/// A reviewer agent's verdict on the agent it reviews.
///
/// The verdict cites the evidence it rests on. It only advises. A person
/// decides whether to act on it. The reviewing agent is the event's actor,
/// so the payload does not name it.
#[derive(Debug)]
pub(crate) struct AgentReviewVerdict {
    /// The reviewed agent.
    pub(crate) reviewed: AgentId,
    /// What the reviewer concluded.
    pub(crate) kind: VerdictKind,
    /// The evidence records it cites.
    pub(crate) cited: CitedEvidence,
    /// The note the reviewer wrote.
    pub(crate) note: VerdictNote,
    /// When it was given.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentReviewVerdict => AgentsEvent::ReviewVerdict,
    fn payload(&self) -> EventData {
        let cited: Vec<String> = self.cited.seqs().iter().map(ToString::to_string).collect();
        EventData::new()
            .field("reviewed_agent_id", self.reviewed.to_string())
            .field("kind", self.kind.as_str())
            .field("cited_seqs", cited.join(","))
            .field("note", self.note.as_str().to_owned())
    }
}

/// An agent's actions drifted from its declared intent.
///
/// The agent performed them, so it is the event's actor and the payload
/// does not name it.
#[derive(Debug)]
pub struct AgentIntentDrift {
    /// The delegation that holds the intent the actions are checked against.
    pub(crate) delegation_id: DelegationId,
    /// The delegation's name when the event fired, or its id if it has none.
    pub(crate) delegation_label: EventLabel,
    /// When the drift was detected.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentIntentDrift => AgentsEvent::IntentDrift,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "delegation",
            Reference::new(
                RefKind::DELEGATION,
                self.delegation_id.to_string(),
                self.delegation_label.as_str(),
            ),
        )
    }
}

impl AgentIntentDrift {
    /// The record that an agent acting under `delegation_id` in `tenant_id`
    /// drifted by trying a way out its egress policy refused, named by the
    /// delegation's id.
    ///
    /// The egress gateway saw it in traffic and reports only the ids: the
    /// delegation may be gone by the time the worker reads the report, and
    /// nothing it holds changes, so no aggregate raises it.
    #[must_use]
    pub fn observed_at_egress(tenant_id: TenantId, delegation_id: DelegationId) -> DomainEvent {
        scoped(
            tenant_id,
            Self {
                delegation_id,
                delegation_label: EventLabel::of(&delegation_id.to_string()),
                occurred_at: clock::now(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;
    use crate::types::EventType;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// The entity a payload field points at: its id and the name it carried
    /// when the event fired. Both are what an audit screen renders and what a
    /// consumer keys on.
    fn entity(payload: &EventData, key: &str) -> (String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => {
                (reference.id().to_owned(), reference.label().to_owned())
            }
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    /// A plain scalar field of a payload.
    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// The agent "nightly-report" asks to run `delete_order`. The request, an
    /// approval and a refusal each name the approval. The request also names
    /// the delegation, and each decision names the agent.
    #[test]
    fn the_approval_events_name_the_request_and_its_context() {
        let agent = AgentId::new();
        let delegation = DelegationId::new();
        let approval = ApprovalId::new();
        let action = "delete_order({\"id\":1})";

        requested_approval(delegation, approval, action);
        granted_approval(agent, approval, action);
        denied_and_withdrawn_approval(agent, approval, action);
    }

    /// Every approval event names the request with its action as the label.
    fn approval_subject(event: &impl DomainEventCore, approval: ApprovalId, action: &str) {
        let kind = event.event_type();
        assert_eq!(
            entity(&event.payload(), "approval"),
            (approval.to_string(), action.to_owned()),
            "{kind}"
        );
    }

    /// Requesting approval names the delegation whose authority the action would use.
    fn requested_approval(delegation: DelegationId, approval: ApprovalId, action: &str) {
        let requested = AgentApprovalRequested {
            delegation_id: delegation,
            delegation_label: EventLabel::of("ledger-write"),
            approval_id: approval,
            approval_label: EventLabel::of(action),
            occurred_at: now(),
        };
        approval_subject(&requested, approval, action);
        assert_eq!(
            entity(&requested.payload(), "delegation"),
            (delegation.to_string(), "ledger-write".to_owned()),
            "the request names the authority the action would exercise"
        );
    }

    /// Granting approval names the agent and records the time taken to decide.
    fn granted_approval(agent: AgentId, approval: ApprovalId, action: &str) {
        let granted = AgentApprovalGranted {
            agent_id: agent,
            agent_label: EventLabel::of("nightly-report"),
            approval_id: approval,
            approval_label: EventLabel::of(action),
            seconds_to_decide: 42,
            occurred_at: now(),
        };
        assert_eq!(text(&granted.payload(), "seconds_to_decide"), "42");
        approval_subject(&granted, approval, action);
        assert_eq!(
            entity(&granted.payload(), "agent"),
            (agent.to_string(), "nightly-report".to_owned()),
            "a decision names the agent it was made about"
        );
    }

    /// Denying names the agent, while withdrawal has its own event type.
    fn denied_and_withdrawn_approval(agent: AgentId, approval: ApprovalId, action: &str) {
        let denied = AgentApprovalDenied {
            agent_id: agent,
            agent_label: EventLabel::of("nightly-report"),
            approval_id: approval,
            approval_label: EventLabel::of(action),
            occurred_at: now(),
        };
        let withdrawn = AgentApprovalWithdrawn {
            agent_id: agent,
            agent_label: EventLabel::of("nightly-report"),
            approval_id: approval,
            approval_label: EventLabel::of(action),
            occurred_at: now(),
        };

        approval_subject(&denied, approval, action);
        approval_subject(&withdrawn, approval, action);
        assert_eq!(
            entity(&denied.payload(), "agent"),
            (agent.to_string(), "nightly-report".to_owned())
        );
        assert_eq!(
            withdrawn.event_type(),
            EventType::Agents(AgentsEvent::ApprovalWithdrawn)
        );
    }

    /// An agent acting under "ledger-read" drifts from that delegation's
    /// intent. The record names the delegation, since the agent is already the
    /// event's actor.
    #[test]
    fn intent_drift_names_the_delegation_whose_intent_was_exceeded() {
        let delegation = DelegationId::new();

        let event = AgentIntentDrift {
            delegation_id: delegation,
            delegation_label: EventLabel::of("ledger-read"),
            occurred_at: now(),
        };
        assert_eq!(
            entity(&event.payload(), "delegation"),
            (delegation.to_string(), "ledger-read".to_owned())
        );
    }

    /// The egress gateway reports a refused way out under a delegation. The
    /// drift record names Acme, the tenant reported, and the delegation by
    /// its id, the only name the report carries.
    #[test]
    fn a_drift_seen_at_egress_names_the_delegation_by_its_id() {
        let acme = TenantId::new();
        let delegation = DelegationId::new();

        let event = AgentIntentDrift::observed_at_egress(acme, delegation);

        assert_eq!(event.tenant_id(), Some(&acme));
        assert_eq!(
            entity(&event.payload(), "delegation"),
            (delegation.to_string(), delegation.to_string())
        );
    }
}
