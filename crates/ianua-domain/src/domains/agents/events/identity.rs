//! Events about who an agent is: its identity, attestation and credentials.

use time::OffsetDateTime;

use crate::domains::agents::events::authority::principal_reference;
use crate::domains::agents::identity::agent::{AgentIdentity, Handover};
use crate::domains::agents::identity::token_attack::TokenAttack;
use crate::isolation::scope::TenantScope;
use crate::shared::clock;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::scoped;
use crate::types::event_type::AgentsEvent;
use crate::types::{AgentId, EventLabel, PrincipalRef, TenantId};

/// A new agent identity was created.
#[derive(Debug)]
pub(crate) struct AgentIdentityCreated {
    /// The new agent ID.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// When it was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentIdentityCreated => AgentsEvent::AgentCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "agent",
            Reference::new(
                RefKind::AGENT,
                self.agent_id.to_string(),
                self.agent_label.as_str(),
            ),
        )
    }
}

/// An agent's name or description was changed.
#[derive(Debug)]
pub(crate) struct AgentIdentityUpdated {
    /// The identity whose editable profile changed.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// When it was updated.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentIdentityUpdated => AgentsEvent::AgentUpdated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "agent",
            Reference::new(
                RefKind::AGENT,
                self.agent_id.to_string(),
                self.agent_label.as_str(),
            ),
        )
    }
}

/// An agent was suspended.
#[derive(Debug)]
pub(crate) struct AgentIdentitySuspended {
    /// The identity temporarily barred from acting.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// When it was suspended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentIdentitySuspended => AgentsEvent::AgentSuspended,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "agent",
            Reference::new(
                RefKind::AGENT,
                self.agent_id.to_string(),
                self.agent_label.as_str(),
            ),
        )
    }
}

/// Every active agent of the tenant was suspended in one step.
#[derive(Debug)]
pub struct AllAgentsSuspended {
    /// How many agents were running and are now suspended.
    pub(crate) suspended_count: u64,
    /// When they were suspended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AllAgentsSuspended => AgentsEvent::AllAgentsSuspended,
    fn payload(&self) -> EventData {
        EventData::new().field("suspended_count", self.suspended_count.to_string())
    }
}

/// A suspended agent was resumed.
#[derive(Debug)]
pub(crate) struct AgentIdentityResumed {
    /// The identity allowed to act again after suspension.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// When it was resumed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentIdentityResumed => AgentsEvent::AgentResumed,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "agent",
            Reference::new(
                RefKind::AGENT,
                self.agent_id.to_string(),
                self.agent_label.as_str(),
            ),
        )
    }
}

/// An agent was permanently revoked.
#[derive(Debug)]
pub(crate) struct AgentIdentityRevoked {
    /// The identity permanently barred from acting.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// When it was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentIdentityRevoked => AgentsEvent::AgentRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "agent",
            Reference::new(
                RefKind::AGENT,
                self.agent_id.to_string(),
                self.agent_label.as_str(),
            ),
        )
    }
}

/// An agent identity was permanently deleted.
#[derive(Debug)]
pub(crate) struct AgentIdentityDeleted {
    /// The deleted agent's ID.
    pub(crate) agent_id: AgentId,
    /// The agent's name when it was deleted.
    pub(crate) agent_label: EventLabel,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentIdentityDeleted => AgentsEvent::AgentDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "agent",
            Reference::new(
                RefKind::AGENT,
                self.agent_id.to_string(),
                self.agent_label.as_str(),
            ),
        )
    }
}

/// Every delegation an agent holds was revoked in one step to contain it.
///
/// Delegations the agent passed on from those are revoked too.
#[derive(Debug)]
pub struct AgentContained {
    /// The contained agent.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// How many delegations were revoked, counting the agent's own and every
    /// delegation passed on from them.
    pub(crate) revoked_count: u32,
    /// When the agent was contained.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentContained => AgentsEvent::AgentContained,
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
            .field("revoked_count", self.revoked_count.to_string())
    }
}

/// An agent was required to re-attest before it may act again.
#[derive(Debug)]
pub(crate) struct AgentReattestationRequired {
    /// The agent required to re-attest.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// When re-attestation was required.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentReattestationRequired => AgentsEvent::ReattestationRequired,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "agent",
            Reference::new(
                RefKind::AGENT,
                self.agent_id.to_string(),
                self.agent_label.as_str(),
            ),
        )
    }
}

/// An agent was issued an attestation challenge to answer.
#[derive(Debug)]
pub(crate) struct AgentAttestationChallengeIssued {
    /// The agent that has to answer it.
    pub(crate) agent_id: AgentId,
    /// The agent's name.
    pub(crate) agent_label: EventLabel,
    /// When it was issued.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentAttestationChallengeIssued => AgentsEvent::AttestationChallengeIssued,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "agent",
            Reference::new(
                RefKind::AGENT,
                self.agent_id.to_string(),
                self.agent_label.as_str(),
            ),
        )
    }
}

/// An agent's ownership moved from one person to another.
#[derive(Debug)]
pub struct AgentOwnershipTransferred {
    /// The identity whose accountable owner changed.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The owner before.
    pub(crate) from: PrincipalRef,
    /// The owner now.
    pub(crate) to: PrincipalRef,
    /// Why it moved: handed on by choice, or because its owner left.
    pub(crate) handover: Handover,
    /// When it moved.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentOwnershipTransferred => AgentsEvent::AgentOwnershipTransferred,
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
            .reference("previous_owner", principal_reference(&self.from))
            .reference("owner", principal_reference(&self.to))
            .field("handover", self.handover.as_str())
    }
}

/// An agent's owner offered it to another person, who may accept it until
/// the offer lapses.
#[derive(Debug)]
pub struct AgentOwnershipOffered {
    /// The identity offered to a prospective owner.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The owner making the offer.
    pub(crate) owner: PrincipalRef,
    /// The person it was offered to.
    pub(crate) recipient: PrincipalRef,
    /// When the offer lapses unanswered.
    pub(crate) expires_at: OffsetDateTime,
    /// When it was offered.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentOwnershipOffered => AgentsEvent::AgentOwnershipOffered,
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
            .reference("owner", principal_reference(&self.owner))
            .reference("recipient", principal_reference(&self.recipient))
            .field("expires_at", self.expires_at.to_string())
    }
}

/// An offer of an agent ended unaccepted: its owner withdrew it, or the
/// person it was made to declined it.
#[derive(Debug)]
pub struct AgentOwnershipOfferWithdrawn {
    /// The identity whose pending ownership transfer ended.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The person it had been offered to.
    pub(crate) recipient: PrincipalRef,
    /// When it was withdrawn.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentOwnershipOfferWithdrawn => AgentsEvent::AgentOwnershipOfferWithdrawn,
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
            .reference("recipient", principal_reference(&self.recipient))
    }
}

/// An agent's sign-in was refused in a way that cannot happen by accident:
/// a replayed or forged assertion, one naming another agent, or a task
/// token bound to the agent's key presented without its key's proof.
///
/// Whoever tries can repeat it on every request, so it is recorded once a
/// window per agent and kind of attack, saying how many attempts it stands
/// for, and told to the people who run the tenant as a security alert. It
/// never carries the assertion, the token or the proof.
#[derive(Debug)]
pub struct AgentTokenAttackRefused {
    /// The agent the attempts were made as.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The kind of attack the refusals looked like.
    pub(crate) attack: TokenAttack,
    /// How many such refusals this record stands for, this one included.
    pub(crate) attempts: u64,
    /// When the refusal that made this record happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentTokenAttackRefused => AgentsEvent::TokenAttackRefused,
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
            .field("attack", self.attack.as_str())
            .field("attempts", self.attempts.to_string())
    }
}

impl AgentTokenAttackRefused {
    /// The record that `attempts` sign-ins as `agent` of `tenant_id` were
    /// refused as `attack`, the last one now.
    ///
    /// Nothing about the agent changes, so no aggregate raises it: the use
    /// case that refused the sign-in records it, held back to one record a
    /// window per agent and kind of attack.
    #[must_use]
    pub fn observed<T: TenantScope>(
        tenant_id: TenantId,
        agent: &AgentIdentity<T>,
        attack: TokenAttack,
        attempts: u64,
    ) -> DomainEvent {
        scoped(
            tenant_id,
            Self {
                agent_id: *agent.id(),
                agent_label: EventLabel::of(agent.name().as_str()),
                attack,
                attempts,
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

    /// Mallory replays Ann's agent's assertion forty times in an hour. The
    /// one record names the agent, the kind of attack and how many attempts
    /// it stands for, and holds nothing she sent.
    #[test]
    fn a_token_attack_names_the_agent_the_attack_and_the_attempts() {
        let agent = AgentId::new();
        let refused = AgentTokenAttackRefused {
            agent_id: agent,
            agent_label: EventLabel::of("nightly-report"),
            attack: TokenAttack::Replayed,
            attempts: 40,
            occurred_at: now(),
        };

        let payload = refused.payload();

        assert_eq!(
            refused.event_type(),
            crate::types::EventType::from(AgentsEvent::TokenAttackRefused)
        );
        assert_eq!(
            entity(&payload, "agent"),
            (agent.to_string(), "nightly-report".to_owned())
        );
        assert_eq!(text(&payload, "attack"), "replayed");
        assert_eq!(text(&payload, "attempts"), "40");
        assert!(payload.value("assertion").is_none());
    }

    /// The agent "nightly-report" is created, updated, suspended, resumed,
    /// revoked, deleted and told to re-attest. Each record names it by id and
    /// by name, so an audit line always says which agent it is about.
    #[test]
    fn every_agent_lifecycle_event_names_the_agent_it_is_about() {
        let agent = AgentId::new();
        let label = "nightly-report";

        let mut events = active_lifecycle_events(agent, label);
        events.extend(restricted_lifecycle_events(agent, label));
        for event in events {
            let kind = event.event_type();
            assert_eq!(
                entity(&event.payload(), "agent"),
                (agent.to_string(), label.to_owned()),
                "{kind}"
            );
        }
    }

    /// Identity changes from creation through a temporary suspension and resumption.
    fn active_lifecycle_events(agent: AgentId, label: &str) -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(AgentIdentityCreated {
                agent_id: agent,
                agent_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(AgentIdentityUpdated {
                agent_id: agent,
                agent_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(AgentIdentitySuspended {
                agent_id: agent,
                agent_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(AgentIdentityResumed {
                agent_id: agent,
                agent_label: EventLabel::of(label),
                occurred_at: now(),
            }),
        ]
    }

    /// Identity changes that remove the agent or require fresh attestation.
    fn restricted_lifecycle_events(agent: AgentId, label: &str) -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(AgentIdentityRevoked {
                agent_id: agent,
                agent_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(AgentIdentityDeleted {
                agent_id: agent,
                agent_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(AgentReattestationRequired {
                agent_id: agent,
                agent_label: EventLabel::of(label),
                occurred_at: now(),
            }),
        ]
    }

    /// Ann contains the agent "nightly-report", which revokes 12 delegations.
    /// The record names the agent and the count, so Ann sees whether one grant
    /// or a hundred went with it.
    #[test]
    fn containment_names_the_agent_and_how_much_authority_fell() {
        let agent = AgentId::new();

        let event = AgentContained {
            agent_id: agent,
            agent_label: EventLabel::of("nightly-report"),
            revoked_count: 12,
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "agent"),
            (agent.to_string(), "nightly-report".to_owned())
        );
        assert_eq!(text(&payload, "revoked_count"), "12");
    }
}
