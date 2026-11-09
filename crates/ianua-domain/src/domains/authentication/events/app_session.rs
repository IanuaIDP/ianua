//! Events of an app session reaching services on hosts other than the one it
//! was opened on.
//!
//! The person is the actor on both events and is carried on the envelope.
//! So the payload names only the session and where it went.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{DomainName, Label, ServiceId, SessionId};

/// A session opened on an app's host was set as the cookie of a service that
/// accepts it on a host of its own.
#[derive(Debug)]
pub struct AppSessionHandedOver {
    /// The session handed on.
    pub(crate) session_id: SessionId,
    /// The service whose cookie was set.
    pub(crate) service_id: ServiceId,
    /// That service's name.
    pub(crate) service_name: Label,
    /// The host the cookie was set on.
    pub(crate) host: DomainName,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AppSessionHandedOver => crate::types::event_type::AuthenticationEvent::AppSessionHandedOver,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("session_id", self.session_id.to_string())
            .reference(
                "service",
                service_reference(&self.service_id, &self.service_name),
            )
            .field("host", self.host.as_str())
    }
}

/// A short-lived bearer token was issued, under an app session, for a service
/// that accepts the app's sign-in by token.
#[derive(Debug)]
pub struct AppTokenIssued {
    /// The session the token was fetched under.
    pub(crate) session_id: SessionId,
    /// The service the token is for.
    pub(crate) service_id: ServiceId,
    /// That service's name.
    pub(crate) service_name: Label,
    /// When the token lapses.
    pub(crate) expires_at: OffsetDateTime,
    /// When it was issued.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AppTokenIssued => crate::types::event_type::AuthenticationEvent::AppTokenIssued,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("session_id", self.session_id.to_string())
            .reference(
                "service",
                service_reference(&self.service_id, &self.service_name),
            )
            .field("expires_at", self.expires_at.unix_timestamp().to_string())
    }
}

fn service_reference(service_id: &ServiceId, name: &Label) -> Reference {
    Reference::new(RefKind::SERVICE, service_id.to_string(), name.to_string())
}
