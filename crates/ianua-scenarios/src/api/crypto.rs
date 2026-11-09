//! A tenant's signing keys: reading them, rotating in a new one, and
//! revoking an old one.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::crypto::{
    KeyRotated, Migration, PlanMigration, PublishedKeys, RollBack, RotateKey, SigningKeys,
};

/// `GET …/.well-known/jwks.json`: the keys the tenant publishes, which
/// anyone may read.
#[must_use]
pub fn published(tenant: &TenantPath) -> Request<PublishedKeys> {
    Request::of(Call::get(tenant.at("/.well-known/jwks.json")))
}

/// `GET …/crypto/keys`: every signing key of the tenant.
#[must_use]
pub fn keys(tenant: &TenantPath) -> Request<SigningKeys> {
    Request::of(Call::get(tenant.at("/crypto/keys")))
}

/// `POST …/crypto/keys/rotate`: makes a new active key; the old one stays
/// published as rotated through its grace period.
#[must_use]
pub fn rotate(tenant: &TenantPath, rotation: &RotateKey) -> Request<KeyRotated> {
    Request::of(Call::post(tenant.at("/crypto/keys/rotate")).json(rotation))
}

/// `POST …/crypto/keys/{kid}/revoke`: revokes a key for good; it leaves
/// the published key set at once.
#[must_use]
pub fn revoke(tenant: &TenantPath, kid: &str) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/crypto/keys/{kid}/revoke"))))
}

/// `GET …/crypto/migration`: the move between algorithms under way.
#[must_use]
pub fn migration(tenant: &TenantPath) -> Request<Migration> {
    Request::of(Call::get(tenant.at("/crypto/migration")))
}

/// `POST …/crypto/migration/plan`: plans a move to another algorithm; no
/// key is made yet.
#[must_use]
pub fn plan_migration(tenant: &TenantPath, plan: &PlanMigration) -> Request<()> {
    Request::of(Call::post(tenant.at("/crypto/migration/plan")).json(plan))
}

/// `POST …/crypto/migration/start`: makes the new key, signing beside the
/// old one.
#[must_use]
pub fn start_migration(tenant: &TenantPath) -> Request<KeyRotated> {
    Request::of(Call::post(tenant.at("/crypto/migration/start")))
}

/// `POST …/crypto/migration/promote`: the new key becomes the only signer.
#[must_use]
pub fn promote_migration(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::post(tenant.at("/crypto/migration/promote")))
}

/// `POST …/crypto/migration/complete`: the old key is revoked.
#[must_use]
pub fn complete_migration(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::post(tenant.at("/crypto/migration/complete")))
}

/// `POST …/crypto/migration/rollback`: gives up a started move, revoking
/// its new key.
#[must_use]
pub fn roll_back_migration(tenant: &TenantPath, reason: &RollBack) -> Request<()> {
    Request::of(Call::post(tenant.at("/crypto/migration/rollback")).json(reason))
}

/// `POST …/crypto/migration/cancel`: drops a move not started yet.
#[must_use]
pub fn cancel_migration(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::post(tenant.at("/crypto/migration/cancel")))
}
