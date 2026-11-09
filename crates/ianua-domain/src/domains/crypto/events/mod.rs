//! Crypto domain events.

/// Events about a tenant's assertion keys: made, rotated by age and
/// retired after the overlap.
pub mod assertion_keys;
/// Events about a tenant's signing keys: creation, rotation and revocation.
pub mod keys;
/// Events about moving a tenant's signing keys to another algorithm.
pub mod migration;

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::domains::crypto::events::assertion_keys::*;
    use crate::domains::crypto::events::keys::*;
    use crate::domains::crypto::events::migration::*;
    use crate::domains::crypto::signing_key::SigningAlgorithm;
    use crate::shared::events::event::DomainEventCore;
    use crate::types::{KeyId, Text};

    fn kid(value: &str) -> KeyId {
        KeyId::new(value).expect("a short ASCII kid is valid")
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// Every crypto event.
    // The completeness check requires every event struct in this inventory's body.
    #[allow(clippy::too_many_lines)]
    fn every_event() -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(KeyCreated {
                kid: kid("key-1"),
                algorithm: SigningAlgorithm::Rs256,
                occurred_at: now(),
            }),
            Box::new(KeyRotated {
                old_kid: kid("key-1"),
                new_kid: kid("key-2"),
                algorithm: SigningAlgorithm::Rs256,
                occurred_at: now(),
            }),
            Box::new(KeyRevoked {
                kid: kid("key-1"),
                occurred_at: now(),
            }),
            Box::new(AlgorithmMigrationPlanned {
                source_algorithm: SigningAlgorithm::Rs256,
                target_algorithm: SigningAlgorithm::Es256,
                source_key_id: kid("key-1"),
                occurred_at: now(),
            }),
            Box::new(AlgorithmMigrationStarted {
                target_key_id: kid("key-2"),
                target_algorithm: SigningAlgorithm::Es256,
                occurred_at: now(),
            }),
            Box::new(AlgorithmMigrationPromoted {
                target_key_id: kid("key-2"),
                occurred_at: now(),
            }),
            Box::new(AlgorithmMigrationCompleted {
                target_algorithm: SigningAlgorithm::Es256,
                source_key_id: kid("key-1"),
                occurred_at: now(),
            }),
            Box::new(AlgorithmMigrationRolledBack {
                source_algorithm: SigningAlgorithm::Rs256,
                reason: Text::new("reason", "the new key would not verify").unwrap(),
                occurred_at: now(),
            }),
            Box::new(AlgorithmMigrationCancelled {
                target_algorithm: SigningAlgorithm::Es256,
                occurred_at: now(),
            }),
            Box::new(AssertionKeyCreated {
                kid: kid("a1"),
                occurred_at: now(),
            }),
            Box::new(AssertionKeyRotated {
                old_kid: kid("a1"),
                new_kid: kid("a2"),
                occurred_at: now(),
            }),
            Box::new(AssertionKeyRetired {
                kid: kid("a1"),
                occurred_at: now(),
            }),
        ]
    }

    /// Every crypto event has a payload, so each audit entry names the key
    /// or algorithm it is about.
    #[test]
    fn every_event_carries_a_payload() {
        for event in every_event() {
            let name = event.event_type().as_str().to_owned();
            assert!(!event.payload().is_empty(), "{name} has an empty payload");
        }
    }

    /// No two crypto events share an event type. Two under one name would be
    /// filed as the same thing.
    #[test]
    fn every_event_names_itself_exactly_once() {
        let mut seen = std::collections::HashSet::new();

        for event in every_event() {
            let name = event.event_type().as_str().to_owned();
            assert!(seen.insert(name.clone()), "{name} listed twice");
        }
    }
}
