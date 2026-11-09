//! Events for emergency break-glass grants and their revocation.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, Text, UserId};

/// An emergency break-glass grant was created.
///
/// A break-glass grant adds named permissions to one user for a short window
/// during an incident. It has an end time and needs a written reason.
#[derive(Debug)]
pub struct BreakGlassGranted {
    /// The user who received emergency access.
    pub(crate) user_id: UserId,
    /// How that user is named in the audit entry. It is taken at grant time,
    /// so the entry stays readable after a rename or deletion.
    pub(crate) user_label: EventLabel,
    /// Why the grant was created. The audit log requires it.
    pub(crate) reason: Text,
    /// When the grant expires.
    pub(crate) expires_at: OffsetDateTime,
    /// When the grant was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    BreakGlassGranted => crate::types::event_type::AuthenticationEvent::BreakGlassGranted,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("reason", self.reason.as_str())
            .field("expires_at", self.expires_at.to_string())
    }
}

/// A break-glass grant was revoked before expiry.
///
/// The user's emergency access ends at once.
#[derive(Debug)]
pub struct BreakGlassRevoked {
    /// The user whose emergency access was revoked.
    pub(crate) user_id: UserId,
    /// How that user is named in the audit entry. It is taken at revocation
    /// time, so the entry stays readable after a rename or deletion.
    pub(crate) user_label: EventLabel,
    /// When the revocation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    BreakGlassRevoked => crate::types::event_type::AuthenticationEvent::BreakGlassRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "user",
            Reference::new(
                RefKind::USER,
                self.user_id.to_string(),
                self.user_label.as_str(),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn reason() -> Text {
        Text::new("reason", "Production incident INC-1234").unwrap()
    }

    /// Alice gets emergency access. The event's payload links to Alice as a
    /// user, with her id and the label "alice@example.com".
    #[test]
    fn granted_payload_references_the_user_receiving_access() {
        let user_id = UserId::new();
        let event = BreakGlassGranted {
            user_id,
            user_label: EventLabel::of("alice@example.com"),
            reason: reason(),
            expires_at: crate::shared::clock::now(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected a user reference");
        };
        assert_eq!(user.kind(), RefKind::USER);
        assert_eq!(user.id(), user_id.to_string());
        assert_eq!(user.label(), "alice@example.com");
    }

    /// A grant is given for "Production incident INC-1234". The payload
    /// carries that reason word for word, so the audit log shows why.
    #[test]
    fn granted_payload_reads_the_reason_verbatim() {
        let event = BreakGlassGranted {
            user_id: UserId::new(),
            user_label: EventLabel::of("alice@example.com"),
            reason: reason(),
            expires_at: crate::shared::clock::now(),
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(
            event.payload().get("reason"),
            Some("Production incident INC-1234")
        );
    }

    /// Alice's emergency access is revoked. The payload links to Alice, the
    /// user losing access, not to whoever revoked it.
    #[test]
    fn revoked_payload_references_the_user_losing_access() {
        let user_id = UserId::new();
        let event = BreakGlassRevoked {
            user_id,
            user_label: EventLabel::of("alice@example.com"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected a user reference");
        };
        assert_eq!(user.id(), user_id.to_string());
        assert_eq!(user.label(), "alice@example.com");
    }
}
