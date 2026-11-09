//! Events about an organization's connections to its cloud accounts.

use time::OffsetDateTime;

use crate::domains::organization::cloud::account::ConnectionState;
use crate::domains::tenant::provisioning::infrastructure::CloudProvider;
use crate::shared::events::data::EventData;
use crate::shared::events::event::organization_event;
use crate::types::OrganizationId;

/// An organization started connecting a cloud account.
#[derive(Debug)]
pub struct CloudConnectionStarted {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The cloud being connected.
    pub(crate) provider: CloudProvider,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    CloudConnectionStarted => crate::types::event_type::OrganizationEvent::CloudConnectionStarted,
    fn payload(&self) -> EventData {
        EventData::new().field("provider", self.provider.as_str())
    }
}

/// The credential a customer granted was attached to their cloud connection.
#[derive(Debug)]
pub struct CloudCredentialAttached {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The cloud it grants access to.
    pub(crate) provider: CloudProvider,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    CloudCredentialAttached => crate::types::event_type::OrganizationEvent::CloudCredentialAttached,
    fn payload(&self) -> EventData {
        EventData::new().field("provider", self.provider.as_str())
    }
}

/// A cloud connection's credential was tried, and the result recorded.
#[derive(Debug)]
pub struct CloudAccountVerified {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The cloud that was checked.
    pub(crate) provider: CloudProvider,
    /// Whether the credential worked.
    pub(crate) result: ConnectionState,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    CloudAccountVerified => crate::types::event_type::OrganizationEvent::CloudAccountVerified,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("provider", self.provider.as_str())
            .field("result", self.result.as_str())
    }
}

/// An organization removed a cloud connection.
#[derive(Debug)]
pub struct CloudAccountDisconnected {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The cloud that was disconnected.
    pub(crate) provider: CloudProvider,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    CloudAccountDisconnected => crate::types::event_type::OrganizationEvent::CloudAccountDisconnected,
    fn payload(&self) -> EventData {
        EventData::new().field("provider", self.provider.as_str())
    }
}
