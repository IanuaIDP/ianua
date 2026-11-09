//! Events about the organization's own identity provider.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::organization_event;
use crate::types::{ConnectionId, Label, OrganizationId};

/// The organization added its identity provider.
#[derive(Debug)]
pub struct OrgIdentityProviderAdded {
    /// The membership boundary that owns the newly added sign-in connection.
    pub(crate) organization_id: OrganizationId,
    /// The provider's connection.
    pub(crate) connection_id: ConnectionId,
    /// The name members see.
    pub(crate) name: Label,
    /// When it was added.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgIdentityProviderAdded => crate::types::event_type::OrganizationEvent::OrgIdentityProviderAdded,
    fn payload(&self) -> EventData {
        provider(self.connection_id, &self.name)
    }
}

/// The organization's identity provider was changed, switched on or off.
#[derive(Debug)]
pub struct OrgIdentityProviderChanged {
    /// The membership boundary affected by the connection change.
    pub(crate) organization_id: OrganizationId,
    /// The provider's connection.
    pub(crate) connection_id: ConnectionId,
    /// The name members see, as it is now.
    pub(crate) name: Label,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgIdentityProviderChanged => crate::types::event_type::OrganizationEvent::OrgIdentityProviderChanged,
    fn payload(&self) -> EventData {
        provider(self.connection_id, &self.name)
    }
}

/// The organization removed its identity provider.
#[derive(Debug)]
pub struct OrgIdentityProviderRemoved {
    /// The membership boundary whose sign-in connection was removed.
    pub(crate) organization_id: OrganizationId,
    /// The provider's connection.
    pub(crate) connection_id: ConnectionId,
    /// The name members saw.
    pub(crate) name: Label,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgIdentityProviderRemoved => crate::types::event_type::OrganizationEvent::OrgIdentityProviderRemoved,
    fn payload(&self) -> EventData {
        provider(self.connection_id, &self.name)
    }
}

/// The payload naming the provider.
fn provider(connection_id: ConnectionId, name: &Label) -> EventData {
    EventData::new().reference(
        "connection",
        Reference::new(
            RefKind::CONNECTION,
            connection_id.to_string(),
            name.as_str(),
        ),
    )
}
