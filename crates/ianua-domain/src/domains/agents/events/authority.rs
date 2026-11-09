//! Events about what an agent may do: delegations, resource grants and task templates.

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::{Relation, ResourceCapability, ResourceRef};
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEventCore, tenant_event};
use crate::shared::events::raised::TenantEventBody;
use crate::types::event_type::AgentsEvent;
use crate::types::{
    AgentId, DelegationId, DelegationRequestId, EventLabel, EventType, PrincipalRef, TaskTemplateId,
};

/// A delegation was granted to an agent.
#[derive(Debug)]
pub(crate) struct AgentDelegationGranted {
    /// The new delegation ID.
    pub(crate) delegation_id: DelegationId,
    /// The delegation's name when the event fired, or its id if it has none.
    pub(crate) delegation_label: EventLabel,
    /// The agent receiving authority.
    pub(crate) delegate: AgentId,
    /// The delegate's name when the event fired.
    pub(crate) delegate_label: EventLabel,
    /// When it was granted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentDelegationGranted => AgentsEvent::DelegationGranted,
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
                "delegate",
                Reference::new(
                    RefKind::AGENT,
                    self.delegate.to_string(),
                    self.delegate_label.as_str(),
                ),
            )
    }
}

/// A task token was issued for a delegation.
#[derive(Debug)]
pub(crate) struct AgentTokenIssued {
    /// The delegation the token was minted from.
    pub(crate) delegation_id: DelegationId,
    /// The delegation's name when the event fired, or its id if it has none.
    pub(crate) delegation_label: EventLabel,
    /// The agent the token is for.
    pub(crate) delegate: AgentId,
    /// The delegate's name when the event fired.
    pub(crate) delegate_label: EventLabel,
    /// When it was issued.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentTokenIssued => AgentsEvent::TokenIssued,
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
                "delegate",
                Reference::new(
                    RefKind::AGENT,
                    self.delegate.to_string(),
                    self.delegate_label.as_str(),
                ),
            )
    }
}

/// A delegation was revoked.
#[derive(Debug)]
pub(crate) struct AgentDelegationRevoked {
    /// The grant whose authority was withdrawn.
    pub(crate) delegation_id: DelegationId,
    /// The delegation's name when the event fired, or its id if it has none.
    pub(crate) delegation_label: EventLabel,
    /// When it was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentDelegationRevoked => AgentsEvent::DelegationRevoked,
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

/// A delegation gained a relation on one resource.
///
/// The rest of the delegation stays as it was.
#[derive(Debug)]
pub(crate) struct AgentDelegationResourceGranted {
    /// The delegation the resource was added to.
    pub(crate) delegation_id: DelegationId,
    /// The delegation's name when the event fired, or its id if it has none.
    pub(crate) delegation_label: EventLabel,
    /// The relation given, such as `reader`.
    pub(crate) relation: Relation,
    /// The object the relation is on, such as `ledger:2026-q1`.
    pub(crate) resource: ResourceRef,
    /// When it was granted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentDelegationResourceGranted => AgentsEvent::DelegationResourceGranted,
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
            .field("relation", self.relation.as_str())
            .field("resource", self.resource.as_str())
    }
}

/// A delegation lost a relation on one resource.
///
/// The rest of what the delegation gives stays as it was.
#[derive(Debug)]
pub(crate) struct AgentDelegationResourceRevoked {
    /// The delegation the resource was removed from.
    pub(crate) delegation_id: DelegationId,
    /// The delegation's name when the event fired, or its id if it has none.
    pub(crate) delegation_label: EventLabel,
    /// The relation taken away.
    pub(crate) relation: Relation,
    /// The object the relation was on.
    pub(crate) resource: ResourceRef,
    /// When it was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentDelegationResourceRevoked => AgentsEvent::DelegationResourceRevoked,
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
            .field("relation", self.relation.as_str())
            .field("resource", self.resource.as_str())
    }
}

/// Who received or lost a relation, and which relation on which object.
#[derive(Debug, Clone)]
pub(crate) struct ResourceRelationChange {
    /// The principal the relation belongs to.
    pub(crate) subject: PrincipalRef,
    /// The relation and the object it is on.
    pub(crate) capability: ResourceCapability,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

impl ResourceRelationChange {
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("subject", principal_reference(&self.subject))
            .field("relation", self.capability.relation().as_str())
            .field("object", self.capability.resource_ref().as_str())
    }
}

/// The reference an audit record shows for a principal.
pub(super) fn principal_reference(principal: &PrincipalRef) -> Reference {
    let kind = match principal {
        PrincipalRef::User(_) => RefKind::USER,
        PrincipalRef::OrgUser(_) => RefKind::ORG_USER,
        PrincipalRef::Agent(_) => RefKind::AGENT,
        PrincipalRef::Consumer(_) => RefKind::CONSUMER,
    };
    Reference::new(kind, principal.id().to_string(), principal.label())
}

/// A principal was given a relation on a resource.
#[derive(Debug)]
pub(crate) struct AgentResourceRelationGranted(pub(crate) ResourceRelationChange);

impl DomainEventCore for AgentResourceRelationGranted {
    fn event_type(&self) -> EventType {
        AgentsEvent::ResourceRelationGranted.into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.0.occurred_at
    }

    fn payload(&self) -> EventData {
        self.0.payload()
    }
}

impl TenantEventBody for AgentResourceRelationGranted {}

/// A principal's relation on a resource was taken away.
#[derive(Debug)]
pub(crate) struct AgentResourceRelationRevoked(pub(crate) ResourceRelationChange);

impl DomainEventCore for AgentResourceRelationRevoked {
    fn event_type(&self) -> EventType {
        AgentsEvent::ResourceRelationRevoked.into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.0.occurred_at
    }

    fn payload(&self) -> EventData {
        self.0.payload()
    }
}

impl TenantEventBody for AgentResourceRelationRevoked {}

/// What happened to a task template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskTemplateChange {
    /// A person proposed it.
    Proposed,
    /// A second person approved it.
    Approved,
    /// A person retired it.
    Retired,
}

/// A task template was proposed, approved or retired.
#[derive(Debug)]
pub(crate) struct AgentTaskTemplateChanged {
    /// The proposal whose approval or retirement changed.
    pub(crate) template_id: TaskTemplateId,
    /// Its name.
    pub(crate) template_label: EventLabel,
    /// What happened to it.
    pub(crate) change: TaskTemplateChange,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl DomainEventCore for AgentTaskTemplateChanged {
    fn event_type(&self) -> EventType {
        match self.change {
            TaskTemplateChange::Proposed => AgentsEvent::TaskTemplateProposed,
            TaskTemplateChange::Approved => AgentsEvent::TaskTemplateApproved,
            TaskTemplateChange::Retired => AgentsEvent::TaskTemplateRetired,
        }
        .into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        EventData::new()
            .field("template_id", self.template_id.to_string())
            .field("template", self.template_label.as_str())
    }
}

impl TenantEventBody for AgentTaskTemplateChanged {}

/// A person renewed a delegation they granted, so it lives another
/// lifetime from now.
#[derive(Debug)]
pub(crate) struct AgentDelegationRenewed {
    /// The grant whose expiry was extended.
    pub(crate) delegation_id: DelegationId,
    /// The delegation's name when the event fired, or its id if it has none.
    pub(crate) delegation_label: EventLabel,
    /// When it now expires.
    pub(crate) expires_at: OffsetDateTime,
    /// When it was renewed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentDelegationRenewed => AgentsEvent::DelegationRenewed,
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
            .field("expires_at", self.expires_at.to_string())
    }
}

/// What became of a delegation an agent asked a person for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DelegationAsk {
    /// The agent asked.
    Asked,
    /// The person granted it.
    Approved,
    /// The person refused it.
    Denied,
}

/// An agent asked a person for a delegation, or the person answered.
///
/// It names the request and the agent, never the reason the agent gave:
/// that is the agent's own text, shown only to the person asked.
#[derive(Debug)]
pub(crate) struct AgentDelegationAsked {
    /// The proposal linking the asking agent to the person deciding.
    pub(crate) request_id: DelegationRequestId,
    /// The agent asking.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The person asked.
    pub(crate) asked_of: PrincipalRef,
    /// What happened to the request.
    pub(crate) step: DelegationAsk,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl DomainEventCore for AgentDelegationAsked {
    fn event_type(&self) -> EventType {
        match self.step {
            DelegationAsk::Asked => AgentsEvent::DelegationRequested,
            DelegationAsk::Approved => AgentsEvent::DelegationRequestApproved,
            DelegationAsk::Denied => AgentsEvent::DelegationRequestDenied,
        }
        .into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        EventData::new()
            .field("request_id", self.request_id.to_string())
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .reference("asked_of", principal_reference(&self.asked_of))
    }
}

impl TenantEventBody for AgentDelegationAsked {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;

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

    /// Ann gives the agent "nightly-report" the delegation "ledger-read", and a
    /// token is issued from it. Both records name the delegation and the agent,
    /// each by id and by name.
    #[test]
    fn granting_a_delegation_and_issuing_its_token_name_both_sides() {
        let delegation = DelegationId::new();
        let delegate = AgentId::new();

        for event in delegation_events(delegation, delegate) {
            let kind = event.event_type();
            let payload = event.payload();
            assert_eq!(
                entity(&payload, "delegation"),
                (delegation.to_string(), "ledger-read".to_owned()),
                "{kind}"
            );
            assert_eq!(
                entity(&payload, "delegate"),
                (delegate.to_string(), "nightly-report".to_owned()),
                "{kind}"
            );
        }
    }

    /// A delegation grant and token issuance for the same report agent.
    fn delegation_events(
        delegation: DelegationId,
        delegate: AgentId,
    ) -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(AgentDelegationGranted {
                delegation_id: delegation,
                delegation_label: EventLabel::of("ledger-read"),
                delegate,
                delegate_label: EventLabel::of("nightly-report"),
                occurred_at: now(),
            }),
            Box::new(AgentTokenIssued {
                delegation_id: delegation,
                delegation_label: EventLabel::of("ledger-read"),
                delegate,
                delegate_label: EventLabel::of("nightly-report"),
                occurred_at: now(),
            }),
        ]
    }

    /// Ann revokes the delegation "ledger-read". The record carries the tenant
    /// and names the delegation by id and by name.
    #[test]
    fn revoking_a_delegation_names_the_delegation_that_fell() {
        let delegation = DelegationId::new();

        let event = AgentDelegationRevoked {
            delegation_id: delegation,
            delegation_label: EventLabel::of("ledger-read"),
            occurred_at: now(),
        };
        assert_eq!(
            entity(&event.payload(), "delegation"),
            (delegation.to_string(), "ledger-read".to_owned())
        );
    }

    /// A delegation gains, then loses, `reader` on `ledger:2026-q1`. Both
    /// records name the relation and the object, since the delegation alone
    /// does not say what changed.
    #[test]
    fn a_resource_grant_and_its_revocation_name_the_relation_and_the_object() {
        let delegation = DelegationId::new();

        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(AgentDelegationResourceGranted {
                delegation_id: delegation,
                delegation_label: EventLabel::of("ledger-read"),
                relation: Relation::new("reader").unwrap(),
                resource: ResourceRef::new("ledger:2026-q1").unwrap(),
                occurred_at: now(),
            }),
            Box::new(AgentDelegationResourceRevoked {
                delegation_id: delegation,
                delegation_label: EventLabel::of("ledger-read"),
                relation: Relation::new("reader").unwrap(),
                resource: ResourceRef::new("ledger:2026-q1").unwrap(),
                occurred_at: now(),
            }),
        ];

        for event in events {
            let kind = event.event_type();
            let payload = event.payload();
            assert_eq!(
                entity(&payload, "delegation"),
                (delegation.to_string(), "ledger-read".to_owned()),
                "{kind}"
            );
            assert_eq!(text(&payload, "relation"), "reader", "{kind}");
            assert_eq!(text(&payload, "resource"), "ledger:2026-q1", "{kind}");
        }
    }
}
