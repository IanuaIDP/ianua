//! Steps the key-changing crypto use cases share: generating a fresh signing
//! or assertion key, and loading and saving the key set and the migration a
//! change works on.

use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
use ianua_domain::domains::crypto::assertion_key::{AssertionKey, NewAssertionKey};
use ianua_domain::domains::crypto::signing_key::{
    NewSigningKey, SigningAlgorithm, SigningKey, SigningKeySet,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Expiry, KeyId};

use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{KeyGenerator, MigrationStore, SigningKeyStore};
use crate::tenancy::ScopedTenant;

/// A freshly generated, non-expiring signing key for `algorithm` under a new
/// time-ordered key id.
///
/// # Errors
///
/// Returns `AppError::Internal` if key generation fails.
pub(crate) async fn generated_signing_key(
    generator: &dyn KeyGenerator,
    algorithm: SigningAlgorithm,
) -> Result<SigningKey, AppError> {
    let generated = generator.generate(algorithm).await.or_internal()?;
    let kid = KeyId::new(uuid::Uuid::now_v7().to_string()).or_internal()?;
    Ok(SigningKey::create(NewSigningKey {
        kid,
        algorithm,
        public_key: generated.public_key,
        private_key: generated.private_key,
        expires_at: Expiry::Never,
    }))
}

/// A freshly generated assertion key under a new time-ordered key id,
/// signing with the one algorithm assertion keys use.
///
/// # Errors
///
/// Returns `AppError::Internal` if key generation fails.
pub(crate) async fn generated_assertion_key(
    generator: &dyn KeyGenerator,
) -> Result<AssertionKey, AppError> {
    let generated = generator
        .generate(AssertionKey::ALGORITHM)
        .await
        .or_internal()?;
    let kid = KeyId::new(uuid::Uuid::now_v7().to_string()).or_internal()?;
    Ok(AssertionKey::create(NewAssertionKey {
        kid,
        public_key: generated.public_key,
        private_key: generated.private_key,
    }))
}

/// The key set an active migration operates on, which must still exist.
///
/// # Errors
///
/// Returns `AppError::Internal` if the key set is gone or cannot be loaded.
pub(super) async fn migrating_key_set(
    store: &dyn SigningKeyStore,
    tenant: &ScopedTenant,
) -> Result<SigningKeySet<ResolvedTenant>, AppError> {
    store
        .find(tenant)
        .await
        .or_internal()?
        .ok_or_else(|| AppError::internal_msg("the migrating key set disappeared"))
}

/// Persists the migration.
///
/// # Errors
///
/// Returns `AppError::Conflict` when another migration of the tenant is
/// under way, or `AppError::Internal` on storage failure.
pub(super) async fn save_migration(
    store: &dyn MigrationStore,
    tenant: &ScopedTenant,
    migration: &AlgorithmMigration<ResolvedTenant>,
) -> Result<(), AppError> {
    store
        .save(tenant, migration)
        .await
        .map_err(AppError::from_domain)
}

/// Persists the key set.
///
/// # Errors
///
/// Returns `AppError::Internal` on storage failure.
pub(super) async fn save_key_set(
    store: &dyn SigningKeyStore,
    tenant: &ScopedTenant,
    key_set: &SigningKeySet<ResolvedTenant>,
) -> Result<(), AppError> {
    store.save(tenant, key_set).await.or_internal()
}
