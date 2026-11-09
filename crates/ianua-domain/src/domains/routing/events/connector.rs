//! Events a private-network connector raises.

use time::OffsetDateTime;

use crate::shared::events::data::EventData;
use crate::shared::events::event::DomainEventCore;
use crate::shared::events::raised::TenantEventBody;
use crate::types::event_type::RoutingEvent;
use crate::types::{ConnectorId, EventType, Label};

/// What happened to a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectorChange {
    /// An admin created it, awaiting enrollment.
    Created,
    /// Its agent presented the enrollment code and holds the link now.
    Enrolled,
    /// Its agent was given the next day's certificate for the same key.
    Renewed,
    /// What it may be asked to dial changed.
    Updated,
    /// It was revoked for good.
    Revoked,
    /// It was removed.
    Deleted,
}

/// A connector was created, enrolled, renewed, changed, revoked or removed.
///
/// The gateway reloads the tenant's connectors on each but a renewal, which
/// keeps the key, so a revoked one's link is closed at once.
#[derive(Debug)]
pub(crate) struct ConnectorChanged {
    /// The private-network link whose lifecycle or configuration changed.
    pub(crate) connector_id: ConnectorId,
    /// The link's display label captured when the change occurred.
    pub(crate) name: Label,
    /// What happened.
    pub(crate) change: ConnectorChange,
    /// When.
    pub(crate) occurred_at: OffsetDateTime,
}

impl DomainEventCore for ConnectorChanged {
    fn event_type(&self) -> EventType {
        match self.change {
            ConnectorChange::Created => RoutingEvent::ConnectorCreated,
            ConnectorChange::Enrolled => RoutingEvent::ConnectorEnrolled,
            ConnectorChange::Renewed => RoutingEvent::ConnectorRenewed,
            ConnectorChange::Updated => RoutingEvent::ConnectorUpdated,
            ConnectorChange::Revoked => RoutingEvent::ConnectorRevoked,
            ConnectorChange::Deleted => RoutingEvent::ConnectorDeleted,
        }
        .into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        EventData::new()
            .field("connector_id", self.connector_id.to_string())
            .field("name", self.name.as_str())
    }
}

impl TenantEventBody for ConnectorChanged {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::builders::label;

    /// The "payroll-network" connector is revoked. The event is typed
    /// revoked and names the connector, so the gateway knows whose tunnel to
    /// close.
    #[test]
    fn a_revocation_is_typed_and_names_the_connector() {
        let id = ConnectorId::new();
        let event = ConnectorChanged {
            connector_id: id,
            name: label("payroll-network"),
            change: ConnectorChange::Revoked,
            occurred_at: OffsetDateTime::UNIX_EPOCH,
        };

        assert_eq!(event.event_type().as_str(), "routing.connector_revoked");
        assert_eq!(
            event.payload().value("connector_id"),
            Some(&crate::shared::events::data::FieldValue::Text(
                id.to_string()
            ))
        );
    }
}
