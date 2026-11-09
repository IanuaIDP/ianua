//! The security signals an agent's events mean, so a relying party hears
//! at once that an agent was suspended, revoked or lost a credential, as it
//! hears it of a person.
//!
//! The signals planner asks this for every agents event, and queues one
//! signal job for each stream that takes what comes back. A tenant-wide
//! stop of every agent is planned there too, one signal per agent it
//! suspended.

use ianua_domain::domains::signals::signal::{
    CredentialChangeType, CredentialKind, NewSecuritySignal, SecuritySignal, SignalEvent,
    SignalSubject,
};
use ianua_domain::shared::events::data::{EventData, FieldValue, RefKind};
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::AgentId;
use ianua_domain::types::event_type::{AgentsEvent, EventType};

/// The signal `event` means for the agent it names, or `None` when it is
/// not an agents event that means one, or names no tenant or agent.
#[must_use]
pub(crate) fn agent_signal(event: &DomainEvent) -> Option<SecuritySignal> {
    let EventType::Agents(kind) = event.event_type() else {
        return None;
    };
    let signal_event = signal_event_of(kind)?;
    let tenant_id = *event.tenant_id()?;
    let agent_id = named_agent(&event.payload())?;
    SecuritySignal::new(NewSecuritySignal {
        tenant_id,
        subject: SignalSubject::Agent(agent_id),
        event: signal_event,
        occurred_at: event.occurred_at(),
    })
    .ok()
}

/// What happened to the agent, as a signal says it, for the agents events
/// a relying party must hear of.
fn signal_event_of(kind: AgentsEvent) -> Option<SignalEvent> {
    match kind {
        AgentsEvent::AgentSuspended => Some(SignalEvent::SessionSuspended),
        AgentsEvent::AgentContained => Some(SignalEvent::SessionRevoked),
        AgentsEvent::AgentRevoked | AgentsEvent::AgentDeleted => Some(SignalEvent::AccountDisabled),
        AgentsEvent::CredentialRevoked => Some(app_credential(CredentialChangeType::Revoke)),
        AgentsEvent::CredentialRotated => Some(app_credential(CredentialChangeType::Update)),
        _ => None,
    }
}

/// A change of `change` to the agent's credential.
fn app_credential(change: CredentialChangeType) -> SignalEvent {
    SignalEvent::CredentialChanged {
        credential: CredentialKind::App,
        change,
    }
}

/// The agent `payload` names under `agent`.
fn named_agent(payload: &EventData) -> Option<AgentId> {
    let FieldValue::Reference(reference) = payload.value("agent")? else {
        return None;
    };
    if reference.kind() != RefKind::AGENT {
        return None;
    }
    uuid::Uuid::parse_str(reference.id())
        .ok()
        .map(AgentId::from_uuid)
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::events::data::Reference;
    use ianua_domain::shared::events::event::{DomainEventCore, TenantDomainEvent};
    use ianua_domain::types::TenantId;
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::test_ctx;

    /// An event of `kind` in the test tenant, naming `payload`.
    struct AgentsEventOf {
        kind: AgentsEvent,
        payload: EventData,
        tenant_id: TenantId,
    }

    impl DomainEventCore for AgentsEventOf {
        fn event_type(&self) -> EventType {
            EventType::Agents(self.kind)
        }

        fn occurred_at(&self) -> OffsetDateTime {
            ianua_domain::shared::clock::now()
        }

        fn payload(&self) -> EventData {
            self.payload.clone()
        }
    }

    impl TenantDomainEvent for AgentsEventOf {
        fn tenant_id(&self) -> &TenantId {
            &self.tenant_id
        }
    }

    /// The event `kind` about the billing agent `agent_id`.
    fn about(kind: AgentsEvent, agent_id: AgentId) -> DomainEvent {
        let payload = EventData::new().reference(
            "agent",
            Reference::new(RefKind::AGENT, agent_id.to_string(), "billing agent"),
        );
        DomainEvent::tenant(Box::new(AgentsEventOf {
            kind,
            payload,
            tenant_id: test_ctx().tenant_id(),
        }))
    }

    /// Ann suspends the billing agent. Receivers are told its sessions are
    /// suspended, naming the agent as the subject.
    #[test]
    fn a_suspended_agent_is_signalled() {
        let agent_id = AgentId::new();

        let signal = agent_signal(&about(AgentsEvent::AgentSuspended, agent_id)).unwrap();

        assert_eq!(signal.subject(), &SignalSubject::Agent(agent_id));
        assert_eq!(signal.event(), &SignalEvent::SessionSuspended);
        assert_eq!(signal.tenant_id(), &test_ctx().tenant_id());
    }

    /// Ann revokes the agent's credential. Receivers are told an app
    /// credential was revoked.
    #[test]
    fn a_revoked_credential_is_signalled() {
        let signal = agent_signal(&about(AgentsEvent::CredentialRevoked, AgentId::new())).unwrap();

        assert_eq!(
            signal.event(),
            &app_credential(CredentialChangeType::Revoke)
        );
    }

    /// Renaming the agent is nothing a receiver must act on, so it is no
    /// signal.
    #[test]
    fn an_agent_update_is_no_signal() {
        assert!(agent_signal(&about(AgentsEvent::AgentUpdated, AgentId::new())).is_none());
    }

    /// An event that names no agent is no signal, rather than a signal
    /// about nobody.
    #[test]
    fn an_event_naming_no_agent_is_no_signal() {
        let event = DomainEvent::tenant(Box::new(AgentsEventOf {
            kind: AgentsEvent::AgentRevoked,
            payload: EventData::new(),
            tenant_id: test_ctx().tenant_id(),
        }));

        assert!(agent_signal(&event).is_none());
    }
}
