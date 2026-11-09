//! Events about an agent's credentials: long-lived ones minted, rotated and
//! revoked, and short-lived ones an attestation earns.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::AgentsEvent;
use crate::types::{AgentCredentialId, AgentId, EventLabel};

/// A long-lived credential was issued for an agent to sign in with.
#[derive(Debug)]
pub(crate) struct AgentCredentialMinted {
    /// The agent the credential authenticates.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The new credential ID.
    pub(crate) credential_id: AgentCredentialId,
    /// The credential's name when the event fired, or its id if it has none.
    pub(crate) credential_label: EventLabel,
    /// When it was minted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentCredentialMinted => AgentsEvent::CredentialMinted,
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
                "credential",
                Reference::new(
                    RefKind::CREDENTIAL,
                    self.credential_id.to_string(),
                    self.credential_label.as_str(),
                ),
            )
    }
}

/// An agent credential was rotated.
#[derive(Debug)]
pub(crate) struct AgentCredentialRotated {
    /// The identity whose signing credential was replaced.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The rotated credential ID.
    pub(crate) credential_id: AgentCredentialId,
    /// The credential's name when the event fired, or its id if it has none.
    pub(crate) credential_label: EventLabel,
    /// When it was rotated.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentCredentialRotated => AgentsEvent::CredentialRotated,
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
                "credential",
                Reference::new(
                    RefKind::CREDENTIAL,
                    self.credential_id.to_string(),
                    self.credential_label.as_str(),
                ),
            )
    }
}

/// An agent credential was revoked.
#[derive(Debug)]
pub(crate) struct AgentCredentialRevoked {
    /// The identity whose credential can no longer authenticate.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The revoked credential ID.
    pub(crate) credential_id: AgentCredentialId,
    /// The credential's name when the event fired, or its id if it has none.
    pub(crate) credential_label: EventLabel,
    /// When it was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentCredentialRevoked => AgentsEvent::CredentialRevoked,
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
                "credential",
                Reference::new(
                    RefKind::CREDENTIAL,
                    self.credential_id.to_string(),
                    self.credential_label.as_str(),
                ),
            )
    }
}

/// An agent proved what it is with a verified attestation and got a
/// short-lived credential.
///
/// The agent attests for itself, so it is the event's actor and the payload
/// does not name it.
#[derive(Debug)]
pub struct AgentBootstrapped {
    /// The short-lived credential issued.
    pub(crate) credential_id: AgentCredentialId,
    /// The credential's name when the event fired, or its id if it has none.
    pub(crate) credential_label: EventLabel,
    /// When it was bootstrapped.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentBootstrapped => AgentsEvent::AgentBootstrapped,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "credential",
            Reference::new(
                RefKind::CREDENTIAL,
                self.credential_id.to_string(),
                self.credential_label.as_str(),
            ),
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

    /// The entity a payload field points at: its id and the name it carried
    /// when the event fired.
    fn entity(payload: &EventData, key: &str) -> (String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => {
                (reference.id().to_owned(), reference.label().to_owned())
            }
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    /// A credential with no name of its own is issued, rotated and revoked.
    /// Each record names the agent, and names the credential by its id in place
    /// of a name.
    #[test]
    fn the_credential_events_name_the_agent_and_the_credential() {
        let agent = AgentId::new();
        let credential = AgentCredentialId::new();

        for event in credential_events(agent, credential) {
            let kind = event.event_type();
            let payload = event.payload();
            assert_eq!(
                entity(&payload, "agent"),
                (agent.to_string(), "nightly-report".to_owned()),
                "{kind}"
            );
            assert_eq!(
                entity(&payload, "credential"),
                (credential.to_string(), credential.to_string()),
                "{kind}"
            );
        }
    }

    /// The lifecycle of one unnamed credential belonging to the report agent.
    fn credential_events(
        agent: AgentId,
        credential: AgentCredentialId,
    ) -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(AgentCredentialMinted {
                agent_id: agent,
                agent_label: EventLabel::of("nightly-report"),
                credential_id: credential,
                credential_label: EventLabel::of(&credential.to_string()),
                occurred_at: now(),
            }),
            Box::new(AgentCredentialRotated {
                agent_id: agent,
                agent_label: EventLabel::of("nightly-report"),
                credential_id: credential,
                credential_label: EventLabel::of(&credential.to_string()),
                occurred_at: now(),
            }),
            Box::new(AgentCredentialRevoked {
                agent_id: agent,
                agent_label: EventLabel::of("nightly-report"),
                credential_id: credential,
                credential_label: EventLabel::of(&credential.to_string()),
                occurred_at: now(),
            }),
        ]
    }

    /// An agent attests for itself and gets a short-lived credential. The agent
    /// is the event's actor, so the payload names only the credential it got.
    #[test]
    fn bootstrapping_names_the_credential_it_issued() {
        let credential = AgentCredentialId::new();

        let event = AgentBootstrapped {
            credential_id: credential,
            credential_label: EventLabel::of(&credential.to_string()),
            occurred_at: now(),
        };
        assert_eq!(
            entity(&event.payload(), "credential"),
            (credential.to_string(), credential.to_string())
        );
    }
}
