//! Crypto bodies: a tenant's signing keys, the public JWKS document, and an
//! algorithm migration.

use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
use ianua_domain::domains::crypto::jwk::JwkComponents;
use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::domains::crypto::migration_status::MigrationStatus;
use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKey, SigningKeySet};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{KeyId, Text};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ApiError;

/// Request body for rotating the active signing key.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RotateKeyBody {
    /// The algorithm of the new key: `RS256`, `ES256` or `EdDSA`.
    #[schema(schema_with = crate::dto::schemas::signing_algorithm)]
    pub algorithm: SigningAlgorithm,
}

/// Request body for planning an algorithm migration.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PlanMigrationBody {
    /// The algorithm to move to: `RS256`, `ES256` or `EdDSA`.
    #[schema(schema_with = crate::dto::schemas::signing_algorithm)]
    pub target_algorithm: SigningAlgorithm,
}

/// Request body for rolling back an algorithm migration.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RollbackMigrationBody {
    /// Why the migration is rolled back, recorded on the audit event.
    pub reason: String,
}

impl RollbackMigrationBody {
    /// The reason, checked.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the reason is empty or too long.
    pub(crate) fn reason(self) -> Result<Text, ApiError> {
        Text::new("reason", self.reason).map_err(ApiError::validation)
    }
}

/// One signing key, without its private half.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SigningKeyResponse {
    /// The key id, as JWT headers and the JWKS document name it.
    pub kid: String,
    /// `RS256`, `ES256` or `EdDSA`.
    #[schema(schema_with = crate::dto::schemas::signing_algorithm)]
    pub algorithm: SigningAlgorithm,
    /// `Active`, `Rotated` or `Revoked`.
    #[schema(schema_with = crate::dto::schemas::key_status)]
    pub status: KeyStatus,
    /// When the key was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the key stops being valid, if it does.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

impl From<&SigningKey> for SigningKeyResponse {
    fn from(key: &SigningKey) -> Self {
        Self {
            kid: key.kid().as_str().to_owned(),
            algorithm: key.algorithm(),
            status: key.status(),
            created_at: key.created_at(),
            expires_at: key.expires_at().instant(),
        }
    }
}

/// A tenant's signing keys.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct KeySetResponse {
    /// Every key, whatever its status.
    pub keys: Vec<SigningKeyResponse>,
}

impl From<SigningKeySet<ResolvedTenant>> for KeySetResponse {
    fn from(set: SigningKeySet<ResolvedTenant>) -> Self {
        Self {
            keys: set.keys().iter().map(SigningKeyResponse::from).collect(),
        }
    }
}

/// The key a rotation or a migration's start made.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct NewKeyResponse {
    /// The new key's id.
    #[schema(value_type = String, format = Uuid)]
    pub key_id: KeyId,
}

/// A tenant's algorithm migration.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MigrationResponse {
    /// The algorithm the tenant signs with before the migration.
    #[schema(schema_with = crate::dto::schemas::signing_algorithm)]
    pub source_algorithm: SigningAlgorithm,
    /// The algorithm it moves to.
    #[schema(schema_with = crate::dto::schemas::signing_algorithm)]
    pub target_algorithm: SigningAlgorithm,
    /// The key it moves away from.
    pub source_key_id: String,
    /// The key it moves to, once the migration started.
    pub target_key_id: Option<String>,
    /// Where the migration stands.
    #[schema(schema_with = crate::dto::schemas::migration_status)]
    pub status: MigrationStatus,
    /// When it was planned.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last moved.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<AlgorithmMigration<ResolvedTenant>> for MigrationResponse {
    fn from(migration: AlgorithmMigration<ResolvedTenant>) -> Self {
        Self {
            source_algorithm: migration.source_algorithm(),
            target_algorithm: migration.target_algorithm(),
            source_key_id: migration.source_key_id().as_str().to_owned(),
            target_key_id: migration.target_key_id().map(|k| k.as_str().to_owned()),
            status: migration.status(),
            created_at: migration.created_at(),
            updated_at: migration.updated_at(),
        }
    }
}

/// One public key in the JWKS document.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct JwkEntry {
    /// Key type: `RSA`, `EC` or `OKP`.
    pub kty: String,
    /// Key use: always `sig`.
    #[serde(rename = "use")]
    pub use_: String,
    /// Key id.
    pub kid: String,
    /// Algorithm: `RS256`, `ES256` or `EdDSA`.
    pub alg: String,
    /// RSA modulus (base64url, RSA keys only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA exponent (base64url, RSA keys only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// Curve name (EC and EdDSA keys only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC x coordinate or EdDSA public key (base64url).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC y coordinate (base64url, EC keys only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

impl From<JwkComponents> for JwkEntry {
    fn from(components: JwkComponents) -> Self {
        let signing = |kty: &str, kid: String, alg: &str| Self {
            kty: kty.to_owned(),
            use_: "sig".to_owned(),
            kid,
            alg: alg.to_owned(),
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        match components {
            JwkComponents::Rsa { kid, n, e } => Self {
                n: Some(n),
                e: Some(e),
                ..signing("RSA", kid, "RS256")
            },
            JwkComponents::Ec { kid, crv, x, y } => Self {
                crv: Some(crv),
                x: Some(x),
                y: Some(y),
                ..signing("EC", kid, "ES256")
            },
            JwkComponents::Okp { kid, crv, x } => Self {
                crv: Some(crv),
                x: Some(x),
                ..signing("OKP", kid, "EdDSA")
            },
        }
    }
}

/// The JWKS document: a tenant's public signing keys.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct JwksResponse {
    /// The keys a relying party verifies the tenant's tokens with.
    pub keys: Vec<JwkEntry>,
}

impl From<Vec<JwkComponents>> for JwksResponse {
    fn from(components: Vec<JwkComponents>) -> Self {
        Self {
            keys: components.into_iter().map(JwkEntry::from).collect(),
        }
    }
}
