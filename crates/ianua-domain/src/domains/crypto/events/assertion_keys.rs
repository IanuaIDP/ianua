//! Events about a tenant's assertion keys: the platform making one,
//! rotating it by age and retiring a rotated one after the overlap.
//!
//! No person changes these keys. Each event is recorded by the platform,
//! for the trail and for the caches that keep a tenant's signing assertion
//! key, and none is worth a notification.

use time::OffsetDateTime;

use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::KeyId;

/// A tenant got an assertion key that signs where none did: its first, or
/// one after every key was retired.
#[derive(Debug)]
pub struct AssertionKeyCreated {
    /// The new key.
    pub(crate) kid: KeyId,
    /// When the key was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AssertionKeyCreated => crate::types::event_type::CryptoEvent::AssertionKeyCreated,
    fn payload(&self) -> EventData {
        EventData::new().field("kid", self.kid.to_string())
    }
}

/// A tenant's assertion key was rotated by age. The new key signs, and the
/// old one stays published for the overlap so an assertion it signed a
/// moment before still verifies.
#[derive(Debug)]
pub struct AssertionKeyRotated {
    /// The key that signed until now. Its status is now `Rotated`.
    pub(crate) old_kid: KeyId,
    /// The key that signs from now on.
    pub(crate) new_kid: KeyId,
    /// When the rotation happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AssertionKeyRotated => crate::types::event_type::CryptoEvent::AssertionKeyRotated,
    fn payload(&self) -> EventData {
        EventData::new().change("kid", self.old_kid.to_string(), self.new_kid.to_string())
    }
}

/// A rotated assertion key was retired once its overlap was over. Upstreams
/// no longer find it published.
#[derive(Debug)]
pub struct AssertionKeyRetired {
    /// The key retired.
    pub(crate) kid: KeyId,
    /// When it was retired.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AssertionKeyRetired => crate::types::event_type::CryptoEvent::AssertionKeyRetired,
    fn payload(&self) -> EventData {
        EventData::new().field("kid", self.kid.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn kid(value: &str) -> KeyId {
        KeyId::new(value).expect("a short ASCII kid is valid")
    }

    /// Acme's assertion key `a1` is rotated onto `a2`. The payload records
    /// the change from the old kid to the new one, and no key material.
    #[test]
    fn rotation_payload_records_both_sides_of_the_kid_and_nothing_else() {
        let event = AssertionKeyRotated {
            old_kid: kid("a1"),
            new_kid: kid("a2"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        let Some(FieldValue::Change(change)) = payload.value("kid") else {
            panic!("expected a kid change");
        };
        assert_eq!(change.from(), Some("a1"));
        assert_eq!(change.to(), Some("a2"));
        assert_eq!(payload.fields().len(), 1);
    }
}
