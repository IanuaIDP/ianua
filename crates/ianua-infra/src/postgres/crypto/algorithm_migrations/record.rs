//! An algorithm migration as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::crypto::algorithm_migration::{
    AlgorithmMigration, AlgorithmMigrationRow, MigrationState,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::KeyId;
use time::OffsetDateTime;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const MIGRATION: Stored = Stored("algorithm migration");

/// A migration as it is read. The store's checked queries fill it.
pub(super) struct MigrationRecord {
    pub(super) source_algorithm: String,
    pub(super) target_algorithm: String,
    pub(super) source_kid: String,
    pub(super) status: String,
    pub(super) target_kid: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl MigrationRecord {
    /// The migration the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the migration
    /// keeps.
    pub(super) fn into_migration(self) -> Result<AlgorithmMigration<ResolvedTenant>, DomainError> {
        let target = self
            .target_kid
            .map(|kid| MIGRATION.value("target key", KeyId::new(kid)))
            .transpose()?;
        AlgorithmMigration::reconstitute(AlgorithmMigrationRow {
            source_algorithm: MIGRATION.choice(&self.source_algorithm)?,
            target_algorithm: MIGRATION.choice(&self.target_algorithm)?,
            source_key_id: MIGRATION.value("source key", KeyId::new(self.source_kid))?,
            state: MigrationState::from_stored(MIGRATION.choice(&self.status)?, target)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A migration's columns, as they are written.
pub(super) struct MigrationColumns<'a> {
    pub(super) source_algorithm: &'static str,
    pub(super) target_algorithm: &'static str,
    pub(super) source_kid: &'a str,
    pub(super) status: &'static str,
    pub(super) target_kid: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> MigrationColumns<'a> {
    /// The columns `migration` is written to.
    pub(super) fn of(migration: &'a AlgorithmMigration<ResolvedTenant>) -> Self {
        Self {
            source_algorithm: migration.source_algorithm().word(),
            target_algorithm: migration.target_algorithm().word(),
            source_kid: migration.source_key_id().as_str(),
            status: migration.status().word(),
            target_kid: migration.target_key_id().map(KeyId::as_str),
            created_at: migration.created_at(),
            updated_at: migration.updated_at(),
        }
    }
}
