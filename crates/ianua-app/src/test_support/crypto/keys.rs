//! Signing keys and migrations as a test sets them up: Acme signs with
//! `key-old` (RS256) and moves to ES256 onto `key-new`.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
use ianua_domain::domains::crypto::signing_key::{
    NewSigningKey, SigningAlgorithm, SigningKey, SigningKeySet,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::test_support::authority::anyone_holding;
use ianua_domain::types::{Expiry, KeyId, PublicKeyPem};

/// A signing key that never expires, under `kid`, signing with `algorithm`.
///
/// # Panics
///
/// If `kid` is not a valid key id. Tests pass literals that are.
#[must_use]
pub fn test_signing_key(kid: &str, algorithm: SigningAlgorithm) -> SigningKey {
    SigningKey::create(NewSigningKey {
        kid: KeyId::new(kid).expect("a valid key id"),
        algorithm,
        public_key: PublicKeyPem::new(
            "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
        )
        .expect("a PEM public key"),
        private_key: Secret::new(format!("private-{kid}")),
        expires_at: Expiry::Never,
    })
}

/// Someone a test does not name who may change signing keys, for setting
/// up keys and migrations the test is not about.
#[must_use]
pub fn key_keeper() -> &'static TenantAuthority {
    anyone_holding(&[SystemPermission::Crypto(CryptoAction::Update)])
}

/// Acme's keys before it migrates: `key-old`, signing with RS256.
#[must_use]
pub fn premigration_keys() -> SigningKeySet<ResolvedTenant> {
    SigningKeySet::new(test_signing_key("key-old", SigningAlgorithm::Rs256))
}

/// A migration from `key-old` to ES256, planned.
///
/// # Panics
///
/// Never: the keeper may change keys and the algorithms differ.
#[must_use]
pub fn planned_migration() -> AlgorithmMigration<ResolvedTenant> {
    let source = test_signing_key("key-old", SigningAlgorithm::Rs256);
    AlgorithmMigration::plan(&source, SigningAlgorithm::Es256, key_keeper())
        .expect("a move from RS256 to ES256 may be planned")
}

/// The planned migration started onto `key-new` (ES256), which is published
/// beside `key-old`; `key-old` still signs.
///
/// # Panics
///
/// Never: the keeper may change keys and `key-new` uses the target
/// algorithm.
#[must_use]
pub fn started_migration() -> (
    SigningKeySet<ResolvedTenant>,
    AlgorithmMigration<ResolvedTenant>,
) {
    let new_key = test_signing_key("key-new", SigningAlgorithm::Es256);
    let mut migration = planned_migration();
    migration
        .start(&new_key, key_keeper())
        .expect("a planned migration starts");
    let mut keys = premigration_keys();
    keys.add_key(new_key, key_keeper())
        .expect("the new key joins the set");
    (keys, migration)
}

/// The started migration promoted: `key-new` signs and `key-old` is rotated
/// out.
///
/// # Panics
///
/// Never: a started migration promotes, and `key-new` still signs.
#[must_use]
pub fn promoted_migration() -> (
    SigningKeySet<ResolvedTenant>,
    AlgorithmMigration<ResolvedTenant>,
) {
    let (mut keys, mut migration) = started_migration();
    migration
        .promote(key_keeper())
        .expect("a started migration promotes");
    keys.rotate_out(
        &KeyId::new("key-old").expect("a valid key id"),
        key_keeper(),
    )
    .expect("the old key is rotated out");
    (keys, migration)
}
