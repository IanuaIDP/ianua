//! Events recording what the gateway let an agent do, and what it refused.

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::PubSub;
use crate::domains::messaging::topic_name::TopicName;
use crate::domains::routing::egress::{EgressDenial, ServiceIdentity};
use crate::shared::clock;
use crate::shared::events::data::EventData;
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::scoped;
use crate::types::event_type::AgentsEvent;
use crate::types::{ActionClass, AgentId, DelegationId, TenantId, UntrustedText};

/// The agent a gateway or the message relay decided about: the tenant it
/// acts in, and the delegation its task token was minted from.
///
/// Every record of an agent's traffic names all three. The tenant is the
/// one the token was issued for, which the gateway or relay checked before
/// deciding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentAtWork {
    tenant_id: TenantId,
    agent_id: AgentId,
    delegation_id: DelegationId,
}

impl AgentAtWork {
    /// `agent_id` at work in `tenant_id` under `delegation_id`.
    #[must_use]
    pub fn new(tenant_id: TenantId, agent_id: AgentId, delegation_id: DelegationId) -> Self {
        Self {
            tenant_id,
            agent_id,
            delegation_id,
        }
    }
}

/// Policy let an agent make an HTTP request.
///
/// The proxy sends it to the event bus only, so the request never waits for a
/// name lookup or an audit write. Workers read it to watch for drift. One of
/// them writes it into the tamper-evident record later, so every decision about
/// an agent is kept as evidence.
///
/// Workers parse the payload by key. So the ids stay plain values under their
/// `_id` keys.
#[derive(Debug)]
pub struct AgentActionAuthorized {
    /// The acting agent.
    pub(crate) agent_id: AgentId,
    /// The delegation the agent's task token was minted from.
    pub(crate) delegation_id: DelegationId,
    /// The action allowed, as its method and resource.
    pub(crate) action: UntrustedText,
    /// The class the proxy judged the action as.
    pub(crate) action_class: ActionClass,
    /// When it was authorized.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentActionAuthorized => AgentsEvent::ActionAuthorized,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("agent_id", self.agent_id.to_string())
            .field("delegation_id", self.delegation_id.to_string())
            .field("action", self.action.as_str())
            .field("action_class", self.action_class.as_str())
            .field("at_us", unix_micros(self.occurred_at))
    }
}

impl AgentActionAuthorized {
    /// The record that policy let `by` make the request `action`, judged as
    /// `action_class`, at `occurred_at`.
    ///
    /// The proxy sees this in traffic: no aggregate changes, so nothing
    /// raises it, and the proxy names the tenant the agent's token was
    /// issued for. The time is given because the evidence recorder rebuilds
    /// the record from the bus at the instant the proxy decided.
    #[must_use]
    pub fn observed(
        by: AgentAtWork,
        action: UntrustedText,
        action_class: ActionClass,
        occurred_at: OffsetDateTime,
    ) -> DomainEvent {
        scoped(
            by.tenant_id,
            Self {
                agent_id: by.agent_id,
                delegation_id: by.delegation_id,
                action,
                action_class,
                occurred_at,
            },
        )
    }
}

/// The instant as microseconds since the epoch.
///
/// The evidence recorder reads this back exactly. The envelope's display
/// string would lose precision.
fn unix_micros(at: OffsetDateTime) -> String {
    (at.unix_timestamp_nanos() / 1_000).to_string()
}

/// Policy refused an agent's HTTP request.
///
/// Anything policy does not allow is refused. The drift monitor reads this next
/// to [`AgentActionAuthorized`], so many refusals add up to a response. Mallory's
/// agent tries one forbidden path after another. Each try is refused, and
/// together the refusals show the agent drifting from its task.
///
/// Like [`AgentActionAuthorized`], the ids stay plain values for the workers.
#[derive(Debug)]
pub struct AgentActionDenied {
    /// The acting agent.
    pub(crate) agent_id: AgentId,
    /// The delegation the agent's task token was minted from.
    pub(crate) delegation_id: DelegationId,
    /// The action refused, as its method and resource.
    pub(crate) action: UntrustedText,
    /// The class the proxy judged the action as.
    pub(crate) action_class: ActionClass,
    /// Why it was denied.
    pub(crate) reason: UntrustedText,
    /// When it was denied.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentActionDenied => AgentsEvent::ActionDenied,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("agent_id", self.agent_id.to_string())
            .field("delegation_id", self.delegation_id.to_string())
            .field("action", self.action.as_str())
            .field("action_class", self.action_class.as_str())
            .field("reason", self.reason.as_str())
            .field("at_us", unix_micros(self.occurred_at))
    }
}

impl AgentActionDenied {
    /// The record that policy refused `by` the request `action`, judged as
    /// `action_class`, for `reason`, at `occurred_at`.
    ///
    /// The proxy sees this in traffic: no aggregate changes, so nothing
    /// raises it, and the proxy names the tenant the agent's token was
    /// issued for. The time is given because the evidence recorder rebuilds
    /// the record from the bus at the instant the proxy decided.
    #[must_use]
    pub fn observed(
        by: AgentAtWork,
        action: UntrustedText,
        action_class: ActionClass,
        reason: UntrustedText,
        occurred_at: OffsetDateTime,
    ) -> DomainEvent {
        scoped(
            by.tenant_id,
            Self {
                agent_id: by.agent_id,
                delegation_id: by.delegation_id,
                action,
                action_class,
                reason,
                occurred_at,
            },
        )
    }
}

/// The message relay let an agent publish to, or read from, a topic.
///
/// The agent is the event's actor, so the payload does not name it.
#[derive(Debug)]
pub struct AgentMessageAuthorized {
    /// The delegation the agent's task token was minted from.
    pub(crate) delegation_id: DelegationId,
    /// The destination or source permitted by the task token.
    pub(crate) topic: TopicName,
    /// Whether the agent published or read.
    pub(crate) action: PubSub,
    /// When it was authorized.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentMessageAuthorized => AgentsEvent::MessageAuthorized,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("delegation_id", self.delegation_id.to_string())
            .field("topic", self.topic.as_str().to_owned())
            .field("action", self.action.as_str())
    }
}

impl AgentMessageAuthorized {
    /// The record that the relay let `by` publish to, or read from,
    /// `topic`, as `action` says.
    ///
    /// The relay decides on a message and changes nothing it keeps, so no
    /// aggregate raises it. The tenant is the one the agent's token was
    /// issued for, which the relay checked first.
    #[must_use]
    pub fn observed(by: AgentAtWork, topic: TopicName, action: PubSub) -> DomainEvent {
        scoped(
            by.tenant_id,
            Self {
                delegation_id: by.delegation_id,
                topic,
                action,
                occurred_at: clock::now(),
            },
        )
    }
}

/// The message relay refused an agent's publish or read.
///
/// It also fires when the relay drops a message on its way to the agent
/// because the message failed its provenance check. Anything not allowed is
/// refused.
#[derive(Debug)]
pub struct AgentMessageDenied {
    /// The delegation the agent's task token was minted from.
    pub(crate) delegation_id: DelegationId,
    /// The topic the message was attempted on.
    pub(crate) topic: TopicName,
    /// Whether the agent tried to publish or read.
    pub(crate) action: PubSub,
    /// Why it was denied.
    pub(crate) reason: UntrustedText,
    /// When it was denied.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentMessageDenied => AgentsEvent::MessageDenied,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("delegation_id", self.delegation_id.to_string())
            .field("topic", self.topic.as_str().to_owned())
            .field("action", self.action.as_str())
            .field("reason", self.reason.as_str())
    }
}

impl AgentMessageDenied {
    /// The record that the relay refused `by` the `action` on `topic`, or
    /// dropped a message on its way to `by`, for `reason`.
    ///
    /// The relay decides on a message and changes nothing it keeps, so no
    /// aggregate raises it. The tenant is the one the agent's token was
    /// issued for, which the relay checked first.
    #[must_use]
    pub fn observed(
        by: AgentAtWork,
        topic: TopicName,
        action: PubSub,
        reason: UntrustedText,
    ) -> DomainEvent {
        scoped(
            by.tenant_id,
            Self {
                delegation_id: by.delegation_id,
                topic,
                action,
                reason,
                occurred_at: clock::now(),
            },
        )
    }
}

/// A service an agent called tried to send traffic somewhere its egress
/// policy does not allow, while handling that agent's request.
///
/// The egress gateway sends it. The agent's request caused the call, so a
/// worker counts it against the agent as drift. Like the other action events,
/// the ids stay plain values for the workers.
#[derive(Debug)]
pub struct AgentEgressDenied {
    /// The agent whose request caused the call.
    pub(crate) agent_id: AgentId,
    /// The delegation it acted under.
    pub(crate) delegation_id: DelegationId,
    /// The service that tried to go out.
    pub(crate) service: ServiceIdentity,
    /// Where it tried to go, as `host:port`.
    pub(crate) destination: UntrustedText,
    /// Why it was refused. It is the gateway's own reason, so a service
    /// cannot write its own text into the record.
    pub(crate) reason: EgressDenial,
    /// When it was refused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentEgressDenied => AgentsEvent::EgressDenied,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("agent_id", self.agent_id.to_string())
            .field("delegation_id", self.delegation_id.to_string())
            .field("service", self.service.as_str())
            .field("destination", self.destination.as_str())
            .field("reason", self.reason.as_str())
            .field("at_us", unix_micros(self.occurred_at))
    }
}

impl AgentEgressDenied {
    /// The record that the egress gateway refused `service`, called by `by`,
    /// the way out to `destination`, for `reason`, at `occurred_at`.
    ///
    /// The gateway sees this in traffic: no aggregate changes, so nothing
    /// raises it, and the gateway names the tenant whose policy it applied.
    /// The time is given because the worker rebuilds the record from the
    /// bus at the instant the gateway decided.
    #[must_use]
    pub fn observed(
        by: AgentAtWork,
        service: ServiceIdentity,
        destination: UntrustedText,
        reason: EgressDenial,
        occurred_at: OffsetDateTime,
    ) -> DomainEvent {
        scoped(
            by.tenant_id,
            Self {
                agent_id: by.agent_id,
                delegation_id: by.delegation_id,
                service,
                destination,
                reason,
                occurred_at,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// A plain scalar field of a payload.
    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// An agent's HTTP request is allowed, another refused, a publish allowed
    /// and a read refused. Each payload carries the ids as plain values under
    /// fixed keys, because the drift monitor parses them by key.
    #[test]
    fn the_authorization_events_carry_a_machine_readable_payload() {
        let agent = AgentId::new();
        let delegation = DelegationId::new();

        http_decision_payloads(agent, delegation);
        message_decision_payloads(delegation);
    }

    /// HTTP decisions retain the acting ids, request and refusal reason.
    fn http_decision_payloads(agent: AgentId, delegation: DelegationId) {
        let authorized = AgentActionAuthorized {
            agent_id: agent,
            delegation_id: delegation,
            action: UntrustedText::record("GET /orders/1"),
            action_class: ActionClass::Read,
            occurred_at: now(),
        };
        let denied = AgentActionDenied {
            agent_id: agent,
            delegation_id: delegation,
            action: UntrustedText::record("DELETE /orders/1"),
            action_class: ActionClass::Delete,
            reason: UntrustedText::record("outside the delegation"),
            occurred_at: now(),
        };

        let payload = authorized.payload();
        assert_eq!(text(&payload, "agent_id"), agent.to_string());
        assert_eq!(text(&payload, "delegation_id"), delegation.to_string());
        assert_eq!(text(&payload, "action"), "GET /orders/1");
        assert_eq!(text(&denied.payload(), "agent_id"), agent.to_string());
        assert_eq!(
            text(&denied.payload(), "delegation_id"),
            delegation.to_string()
        );
        assert_eq!(text(&denied.payload(), "action"), "DELETE /orders/1");
        assert_eq!(text(&denied.payload(), "reason"), "outside the delegation");
    }

    /// Message decisions retain their topic, action, delegation and refusal reason.
    fn message_decision_payloads(delegation: DelegationId) {
        let published = AgentMessageAuthorized {
            delegation_id: delegation,
            topic: TopicName::new("orders").unwrap(),
            action: PubSub::Publish,
            occurred_at: now(),
        };
        let refused = AgentMessageDenied {
            delegation_id: delegation,
            topic: TopicName::new("payroll").unwrap(),
            action: PubSub::Subscribe,
            reason: UntrustedText::record("not in the delegation's topics"),
            occurred_at: now(),
        };

        assert_eq!(text(&published.payload(), "topic"), "orders");
        assert_eq!(text(&published.payload(), "action"), "publish");
        assert_eq!(
            text(&published.payload(), "delegation_id"),
            delegation.to_string()
        );
        assert_eq!(text(&refused.payload(), "topic"), "payroll");
        assert_eq!(text(&refused.payload(), "action"), "subscribe");
        assert_eq!(
            text(&refused.payload(), "reason"),
            "not in the delegation's topics"
        );
    }

    /// A service an agent called is refused a way out to an unlisted host.
    /// The payload names the gateway's reason, `destination_not_listed`,
    /// under `reason`, so the drift monitor reads one fixed value.
    #[test]
    fn a_refused_egress_carries_the_gateways_reason() {
        let denied = AgentEgressDenied {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            service: ServiceIdentity::new("spiffe://ianua.test/ns/svc/sa/fetcher").unwrap(),
            destination: UntrustedText::record("evil.test:443"),
            reason: EgressDenial::DestinationNotListed,
            occurred_at: now(),
        };

        let payload = denied.payload();

        assert_eq!(text(&payload, "reason"), "destination_not_listed");
        assert_eq!(text(&payload, "destination"), "evil.test:443");
    }

    /// The relay lets an agent of Acme publish to `orders`. The record it
    /// observes names Acme, the tenant the agent's token was issued for,
    /// and carries the delegation and topic, with nobody named as actor yet.
    #[test]
    fn an_observed_relay_decision_names_the_tenant_it_was_given() {
        let acme = TenantId::new();
        let delegation = DelegationId::new();
        let by = AgentAtWork::new(acme, AgentId::new(), delegation);

        let event = AgentMessageAuthorized::observed(
            by,
            TopicName::new("orders").unwrap(),
            PubSub::Publish,
        );

        assert_eq!(event.tenant_id(), Some(&acme));
        assert_eq!(
            event.event_type(),
            crate::types::EventType::Agents(AgentsEvent::MessageAuthorized)
        );
        assert_eq!(text(&event.payload(), "topic"), "orders");
        assert_eq!(
            text(&event.payload(), "delegation_id"),
            delegation.to_string()
        );
        assert!(matches!(event.performed_by(), crate::types::Fact::Unknown));
    }
}
