//! Events from the channels a person opens between two agents.

use time::OffsetDateTime;

use crate::domains::agents::channels::channel::ChannelScope;
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::MessagingEvent;
use crate::types::{AgentChannelId, AgentId};

/// The reference kind for a channel a person opened between two agents.
const AGENT_CHANNEL: RefKind = RefKind::new("agent_channel");

/// A person opened a channel between two agents.
#[derive(Debug)]
pub(crate) struct AgentChannelOpened {
    /// The newly opened link that permits messages between these agents.
    pub(crate) channel_id: AgentChannelId,
    /// The agent whose area the messages come from.
    pub(crate) sender: AgentId,
    /// The agent that may read them.
    pub(crate) receiver: AgentId,
    /// What may travel.
    pub(crate) scope: ChannelScope,
    /// The most sensitive data that may travel.
    pub(crate) max_class: DataClassLevel,
    /// When the channel closes by itself.
    pub(crate) expires_at: OffsetDateTime,
    /// When it was opened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentChannelOpened => MessagingEvent::ChannelOpened,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("channel", channel_reference(&self.channel_id, &self.scope))
            .field("sender_agent_id", self.sender.to_string())
            .field("receiver_agent_id", self.receiver.to_string())
            .field("scope_kind", self.scope.kind())
            .field("scope", self.scope.as_str().to_owned())
            .field("max_class", self.max_class.as_str())
            .field("expires_at", self.expires_at.to_string())
    }
}

/// A person closed a channel between two agents.
#[derive(Debug)]
pub(crate) struct AgentChannelClosed {
    /// The link whose message permission was withdrawn.
    pub(crate) channel_id: AgentChannelId,
    /// What it carried. The record shows it as the channel's name.
    pub(crate) scope: ChannelScope,
    /// When it was closed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentChannelClosed => MessagingEvent::ChannelClosed,
    fn payload(&self) -> EventData {
        EventData::new().reference("channel", channel_reference(&self.channel_id, &self.scope))
    }
}

fn channel_reference(id: &AgentChannelId, scope: &ChannelScope) -> Reference {
    Reference::new(AGENT_CHANNEL, id.to_string(), scope.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn entity(payload: &EventData, key: &str) -> (RefKind, String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => (
                reference.kind(),
                reference.id().to_owned(),
                reference.label().to_owned(),
            ),
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// Topics published by one sender's agent area.
    fn topics_from(sender: AgentId) -> ChannelScope {
        ChannelScope::Topics(
            crate::domains::agents::authority::capability::TopicPattern::new(format!(
                "agents.{}.>",
                sender.as_uuid().as_simple()
            ))
            .unwrap(),
        )
    }

    /// Ann opens a channel so one agent may read another's topics up to
    /// confidential data. The record names the channel, both agents, the kind
    /// of scope and the highest data class, since the channel widens what the
    /// receiver may read.
    #[test]
    fn a_channel_opening_names_both_agents_and_what_may_travel() {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        let channel_id = AgentChannelId::new();
        let scope = topics_from(sender);
        let opened = AgentChannelOpened {
            channel_id,
            sender,
            receiver,
            scope: scope.clone(),
            max_class: DataClassLevel::Confidential,
            expires_at: now(),
            occurred_at: now(),
        };

        let payload = opened.payload();

        assert_eq!(
            entity(&payload, "channel"),
            (
                AGENT_CHANNEL,
                channel_id.to_string(),
                scope.as_str().to_owned()
            )
        );
        assert_eq!(text(&payload, "sender_agent_id"), sender.to_string());
        assert_eq!(text(&payload, "receiver_agent_id"), receiver.to_string());
        assert_eq!(text(&payload, "max_class"), "confidential");
        assert_eq!(text(&payload, "scope_kind"), "topics");
    }
}
