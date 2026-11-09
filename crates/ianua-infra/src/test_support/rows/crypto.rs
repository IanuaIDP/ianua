//! Rows of the crypto context.

use ianua_domain::domains::crypto::algorithm_migration::{AlgorithmMigrationRow, MigrationState};
use ianua_domain::domains::crypto::key_status::KeyState;
use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKeyRow};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Expiry, KeyId, PublicKeyPem};

use crate::test_support::rows::at;

/// The public half every test key publishes.
const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n";

/// The private key every test key under `kid` holds, as a key service
/// would never see it: the PEM itself.
#[must_use]
pub fn private_pem(kid: &str) -> String {
    format!("-----BEGIN PRIVATE KEY-----\n{kid}\n-----END PRIVATE KEY-----\n")
}

/// An active ES256 key under `kid`, made at the fixed moment, that never
/// expires.
///
/// # Panics
///
/// When `kid` is not a valid key id, which is a mistake in the test.
#[must_use]
pub fn signing_key_row(kid: &str) -> SigningKeyRow {
    SigningKeyRow {
        kid: KeyId::new(kid).expect("a valid key id"),
        algorithm: SigningAlgorithm::Es256,
        public_key: PublicKeyPem::new(PUBLIC_PEM).expect("a valid public key"),
        private_key: Secret::new(private_pem(kid)),
        state: KeyState::Active,
        created_at: at(0),
        expires_at: Expiry::Never,
    }
}

/// The key under `kid`, rotated out `seconds` after the fixed moment.
#[must_use]
pub fn rotated_key_row(kid: &str, seconds: i64) -> SigningKeyRow {
    SigningKeyRow {
        state: KeyState::Rotated { at: at(seconds) },
        ..signing_key_row(kid)
    }
}

/// A migration from ES256 to EdDSA, moving away from the key `source`,
/// standing as `state` says.
///
/// # Panics
///
/// When `source` is not a valid key id, which is a mistake in the test.
#[must_use]
pub fn migration_row(source: &str, state: MigrationState) -> AlgorithmMigrationRow {
    AlgorithmMigrationRow {
        source_algorithm: SigningAlgorithm::Es256,
        target_algorithm: SigningAlgorithm::EdDsa,
        source_key_id: KeyId::new(source).expect("a valid key id"),
        state,
        created_at: at(0),
        updated_at: at(1),
    }
}
