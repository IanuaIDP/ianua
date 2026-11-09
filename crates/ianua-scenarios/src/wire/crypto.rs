//! A tenant's signing keys, as its administrators manage them: rotating
//! in a new key and revoking an old one.

use serde::{Deserialize, Serialize};

/// `POST …/crypto/keys/rotate`: the algorithm of the new key.
#[derive(Debug, Clone, Serialize)]
pub struct RotateKey {
    /// `RS256`, `ES256` or `EdDSA`.
    pub algorithm: String,
}

/// The key a rotation made.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyRotated {
    /// The new key's id.
    pub key_id: String,
}

/// `GET …/crypto/keys`: every signing key of the tenant, whatever its
/// status.
#[derive(Debug, Clone, Deserialize)]
pub struct SigningKeys {
    /// Active, rotated and revoked records returned by the administration API.
    pub keys: Vec<SigningKey>,
}

/// `GET …/.well-known/jwks.json`: the keys the tenant publishes for its
/// tokens to be checked with, read only for their ids.
#[derive(Debug, Clone, Deserialize)]
pub struct PublishedKeys {
    /// The keys published.
    pub keys: Vec<PublishedKey>,
}

/// One published key, by the id tokens name it with.
#[derive(Debug, Clone, Deserialize)]
pub struct PublishedKey {
    /// Its id.
    pub kid: String,
}

/// One signing key, without its private half.
#[derive(Debug, Clone, Deserialize)]
pub struct SigningKey {
    /// The id tokens' headers name it by.
    pub kid: String,
    /// `Active`, `Rotated` or `Revoked`.
    pub status: String,
}

/// `POST …/crypto/migration/plan`: the algorithm the tenant's tokens are
/// to be signed with.
#[derive(Debug, Clone, Serialize)]
pub struct PlanMigration {
    /// `RS256`, `ES256` or `EdDSA`.
    pub target_algorithm: String,
}

/// `POST …/crypto/migration/rollback`: why the move is given up.
#[derive(Debug, Clone, Serialize)]
pub struct RollBack {
    /// Kept on the record.
    pub reason: String,
}

/// `GET …/crypto/migration`: the move from one signing algorithm to
/// another under way.
#[derive(Debug, Clone, Deserialize)]
pub struct Migration {
    /// The algorithm moved from, such as `RS256`.
    pub source_algorithm: String,
    /// The algorithm moved to, such as `ES256`.
    pub target_algorithm: String,
    /// The key moved from.
    pub source_key_id: String,
    /// The key moved to, once the move started.
    #[serde(default)]
    pub target_key_id: Option<String>,
    /// `Planned`, `InProgress`, `Validating`, `Completed`, `RolledBack` or
    /// `Cancelled`.
    pub status: String,
}
