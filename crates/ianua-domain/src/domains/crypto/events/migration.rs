//! Events about moving a tenant's signing keys to another algorithm.

use time::OffsetDateTime;

use crate::domains::crypto::signing_key::SigningAlgorithm;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::{KeyId, Text};

/// An algorithm migration was planned.
///
/// Records the source and target algorithms. No keys exist for the target
/// at this point.
#[derive(Debug)]
pub(crate) struct AlgorithmMigrationPlanned {
    /// The algorithm being migrated away from.
    pub(crate) source_algorithm: SigningAlgorithm,
    /// The algorithm being migrated to.
    pub(crate) target_algorithm: SigningAlgorithm,
    /// The current active key being replaced.
    pub(crate) source_key_id: KeyId,
    /// When the migration was planned.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AlgorithmMigrationPlanned => crate::types::event_type::CryptoEvent::MigrationPlanned,
    fn payload(&self) -> EventData {
        EventData::new()
            .change(
                "algorithm",
                self.source_algorithm.to_string(),
                self.target_algorithm.to_string(),
            )
            .field("source_key_id", self.source_key_id.to_string())
    }
}

/// An algorithm migration started. The new key exists and sits in the JWKS
/// next to the old key, so both verify while the migration runs.
#[derive(Debug)]
pub(crate) struct AlgorithmMigrationStarted {
    /// The newly created key with the target algorithm.
    pub(crate) target_key_id: KeyId,
    /// The signing scheme the new key introduces alongside the old key.
    pub(crate) target_algorithm: SigningAlgorithm,
    /// When the migration started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AlgorithmMigrationStarted => crate::types::event_type::CryptoEvent::MigrationStarted,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("target_key_id", self.target_key_id.to_string())
            .field("target_algorithm", self.target_algorithm.to_string())
    }
}

/// The target key was promoted to primary signer.
///
/// New tokens are signed with the target algorithm. The old key stays in
/// the JWKS so its tokens still verify during the grace period.
#[derive(Debug)]
pub(crate) struct AlgorithmMigrationPromoted {
    /// The key that is now the primary signer.
    pub(crate) target_key_id: KeyId,
    /// When the promotion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AlgorithmMigrationPromoted => crate::types::event_type::CryptoEvent::MigrationPromoted,
    fn payload(&self) -> EventData {
        EventData::new().field("target_key_id", self.target_key_id.to_string())
    }
}

/// An algorithm migration completed successfully.
///
/// The old key is revoked and gone from the JWKS. The tenant signs only
/// with the target algorithm.
#[derive(Debug)]
pub(crate) struct AlgorithmMigrationCompleted {
    /// The algorithm the tenant is now using.
    pub(crate) target_algorithm: SigningAlgorithm,
    /// The old key that was revoked.
    pub(crate) source_key_id: KeyId,
    /// When the migration completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AlgorithmMigrationCompleted => crate::types::event_type::CryptoEvent::MigrationCompleted,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("target_algorithm", self.target_algorithm.to_string())
            .field("source_key_id", self.source_key_id.to_string())
    }
}

/// An algorithm migration was rolled back.
///
/// The source key signs again. The app layer revokes any target key made
/// during the migration.
#[derive(Debug)]
pub(crate) struct AlgorithmMigrationRolledBack {
    /// The algorithm restored as active.
    pub(crate) source_algorithm: SigningAlgorithm,
    /// Why the migration was rolled back.
    pub(crate) reason: Text,
    /// When the rollback occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AlgorithmMigrationRolledBack => crate::types::event_type::CryptoEvent::MigrationRolledBack,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("source_algorithm", self.source_algorithm.to_string())
            .field("reason", self.reason.to_string())
    }
}

/// A planned migration was cancelled before starting.
///
/// No keys were made for it.
#[derive(Debug)]
pub(crate) struct AlgorithmMigrationCancelled {
    /// The algorithm that was planned as the target.
    pub(crate) target_algorithm: SigningAlgorithm,
    /// When the cancellation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AlgorithmMigrationCancelled => crate::types::event_type::CryptoEvent::MigrationCancelled,
    fn payload(&self) -> EventData {
        EventData::new().field("target_algorithm", self.target_algorithm.to_string())
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

    /// A tenant plans a move from RS256 to ES256 away from `key-2024-01`. The
    /// payload records the algorithm change and the source key.
    #[test]
    fn planned_migration_payload_records_the_algorithm_transition() {
        let event = AlgorithmMigrationPlanned {
            source_algorithm: SigningAlgorithm::Rs256,
            target_algorithm: SigningAlgorithm::Es256,
            source_key_id: kid("key-2024-01"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        let Some(FieldValue::Change(change)) = payload.value("algorithm") else {
            panic!("expected an algorithm change");
        };
        assert_eq!(change.from(), Some("RS256"));
        assert_eq!(change.to(), Some("ES256"));
        assert_eq!(payload.get("source_key_id"), Some("key-2024-01"));
    }

    /// A migration is rolled back for "verification failures on the target
    /// key". The payload carries that reason as the same plain text.
    #[test]
    fn rollback_payload_renders_the_reason_as_plain_text() {
        let event = AlgorithmMigrationRolledBack {
            source_algorithm: SigningAlgorithm::Rs256,
            reason: Text::new("reason", "verification failures on the target key")
                .expect("valid free text"),
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(
            event.payload().get("reason"),
            Some("verification failures on the target key")
        );
    }
}
