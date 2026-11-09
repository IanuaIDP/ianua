//! Events about a tenant's signing keys: creation, rotation and revocation.

use time::OffsetDateTime;

use crate::domains::crypto::signing_key::SigningAlgorithm;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::KeyId;

/// A new signing key was created for the tenant.
///
/// Happens when a tenant is first provisioned, or when a tenant adds a key
/// for another algorithm. The JWKS endpoint should then list the new key.
#[derive(Debug)]
pub struct KeyCreated {
    /// The newly created key.
    pub(crate) kid: KeyId,
    /// The algorithm used by the key.
    pub(crate) algorithm: SigningAlgorithm,
    /// When the key was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    KeyCreated => crate::types::event_type::CryptoEvent::KeyCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("kid", self.kid.to_string())
            .field("algorithm", self.algorithm.to_string())
    }
}

/// A signing key was rotated. The new key signs, and the old key stays in
/// the JWKS so tokens it signed still verify during the grace period.
///
/// Services that verify our tokens should refresh their JWKS cache to pick
/// up the new key.
#[derive(Debug)]
pub struct KeyRotated {
    /// The key that was rotated out. Its status is now `Rotated`.
    pub(crate) old_kid: KeyId,
    /// The new active signing key.
    pub(crate) new_kid: KeyId,
    /// The algorithm used by the new key.
    pub(crate) algorithm: SigningAlgorithm,
    /// When the rotation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    KeyRotated => crate::types::event_type::CryptoEvent::KeyRotated,
    fn payload(&self) -> EventData {
        EventData::new()
            .change("kid", self.old_kid.to_string(), self.new_kid.to_string())
            .field("algorithm", self.algorithm.to_string())
    }
}

/// A signing key was permanently revoked and removed from JWKS.
///
/// Tokens signed with this key do not verify any more. Any cached JWKS that
/// still lists the key should be refreshed.
#[derive(Debug)]
pub struct KeyRevoked {
    /// The key that was revoked.
    pub(crate) kid: KeyId,
    /// When the revocation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    KeyRevoked => crate::types::event_type::CryptoEvent::KeyRevoked,
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

    /// A tenant rotates from `key-2024-01` to `key-2024-07`. The payload
    /// records the change from the old kid to the new one and the algorithm
    /// `RS256`.
    #[test]
    fn rotation_payload_records_both_sides_of_the_kid() {
        let event = KeyRotated {
            old_kid: kid("key-2024-01"),
            new_kid: kid("key-2024-07"),
            algorithm: SigningAlgorithm::Rs256,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        let Some(FieldValue::Change(change)) = payload.value("kid") else {
            panic!("expected a kid change");
        };
        assert_eq!(change.from(), Some("key-2024-01"));
        assert_eq!(change.to(), Some("key-2024-07"));
        assert_eq!(payload.get("algorithm"), Some("RS256"));
    }

    /// A new key's event carries exactly two fields, the kid and the
    /// algorithm. No key material ends up in the audit log.
    #[test]
    fn key_created_payload_is_limited_to_the_kid_and_algorithm() {
        let created = KeyCreated {
            kid: kid("key-2024-01"),
            algorithm: SigningAlgorithm::EdDsa,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = created.payload();
        let keys: Vec<&str> = payload.fields().iter().map(|(k, _)| k.as_str()).collect();

        assert_eq!(keys, ["kid", "algorithm"]);
    }
}
