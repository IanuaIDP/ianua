//! Events about the consent a person gives an OAuth client.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, OAuthClientId};

/// A user gave an OAuth client consent.
///
/// The user who gave it is the record's actor, so the payload leaves them
/// out.
#[derive(Debug)]
pub(crate) struct OAuthConsentGranted {
    /// The client it was given to.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label at consent time, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// How many scopes the user gave.
    pub(crate) scope_count: usize,
    /// When consent was given.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    OAuthConsentGranted => crate::types::event_type::OAuthEvent::ConsentGranted,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "client",
                Reference::new(
                    RefKind::CLIENT,
                    self.client_id.to_string(),
                    self.client_label.as_str(),
                ),
            )
            .field("scope_count", self.scope_count.to_string())
    }
}

/// A user withdrew an OAuth client's consent.
///
/// The user who withdrew it is the record's actor, so the payload leaves
/// them out.
#[derive(Debug)]
pub(crate) struct OAuthConsentRevoked {
    /// The client that lost consent.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label at revocation time, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When consent was withdrawn.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    OAuthConsentRevoked => crate::types::event_type::OAuthEvent::ConsentRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.client_label.as_str(),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::event::DomainEventCore;

    /// A user gives "Northwind CLI" three scopes. The payload names the
    /// client and the count, and leaves the user out since they are the
    /// actor.
    #[test]
    fn consent_granted_payload_omits_the_consenting_user() {
        let client_id = OAuthClientId::new();
        let expected_id = client_id.to_string();
        let event = OAuthConsentGranted {
            client_id,
            client_label: EventLabel::of("Northwind CLI"),
            scope_count: 3,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("user_id"), None);
        assert_eq!(payload.get("scope_count"), Some("3"));
        assert_eq!(payload.get("client"), Some(expected_id.as_str()));
    }
}
