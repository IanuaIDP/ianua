//! Events about agents seen at work that nobody registered.

use time::OffsetDateTime;

use crate::domains::agents::identity::sighting::SightingSource;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::DomainEventCore;
use crate::shared::events::raised::TenantEventBody;
use crate::types::event_type::AgentsEvent;
use crate::types::{AgentSightingId, EventType};

/// The kind of entity a sighting reference points at.
const SIGHTING: RefKind = RefKind::new("agent_sighting");

/// What happened to a sighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SightingChange {
    /// The unregistered agent was seen for the first time.
    Sighted,
    /// A person registered it as an agent.
    Registered,
    /// A person dismissed it.
    Dismissed,
}

/// An unregistered agent was seen, registered or dismissed.
///
/// It names the sighting and where it was seen, never what the caller
/// called itself: that is the caller's own word, kept on the sighting.
#[derive(Debug)]
pub(crate) struct AgentSightingChanged {
    /// The discovery record whose disposition changed.
    pub(crate) sighting_id: AgentSightingId,
    /// Where it was seen.
    pub(crate) source: SightingSource,
    /// What happened to it.
    pub(crate) change: SightingChange,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl DomainEventCore for AgentSightingChanged {
    fn event_type(&self) -> EventType {
        match self.change {
            SightingChange::Sighted => AgentsEvent::AgentSighted,
            SightingChange::Registered => AgentsEvent::AgentSightingRegistered,
            SightingChange::Dismissed => AgentsEvent::AgentSightingDismissed,
        }
        .into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        let id = self.sighting_id.to_string();
        EventData::new()
            .reference("sighting", Reference::new(SIGHTING, id.clone(), id))
            .field("source", self.source.as_str())
    }
}

impl TenantEventBody for AgentSightingChanged {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;

    /// A first sighting by the gateway is recorded as `agents.agent_sighted`,
    /// naming the sighting by its id and the gateway as its source.
    #[test]
    fn a_sighting_names_itself_and_where_it_was_seen() {
        let sighting_id = AgentSightingId::new();
        let event = AgentSightingChanged {
            sighting_id,
            source: SightingSource::Gateway,
            change: SightingChange::Sighted,
            occurred_at: OffsetDateTime::UNIX_EPOCH,
        };

        let payload = event.payload();

        assert_eq!(event.event_type().to_string(), "agents.agent_sighted");
        assert!(matches!(
            payload.value("sighting"),
            Some(FieldValue::Reference(reference)) if reference.id() == sighting_id.to_string()
        ));
        assert_eq!(
            payload.value("source"),
            Some(&FieldValue::Text("gateway".to_owned()))
        );
    }

    /// Each change has its own event type.
    #[test]
    fn each_change_has_its_own_event() {
        let named = |change| {
            AgentSightingChanged {
                sighting_id: AgentSightingId::new(),
                source: SightingSource::CloudScan,
                change,
                occurred_at: OffsetDateTime::UNIX_EPOCH,
            }
            .event_type()
            .to_string()
        };

        assert_eq!(
            named(SightingChange::Registered),
            "agents.agent_sighting_registered"
        );
        assert_eq!(
            named(SightingChange::Dismissed),
            "agents.agent_sighting_dismissed"
        );
    }
}
