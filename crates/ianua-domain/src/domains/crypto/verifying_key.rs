//! The public half of a tenant's signing key: what a verifier holds.
//!
//! The gateway checks the tokens a tenant signed and serves the tenant's
//! JWKS, and needs nothing more than this. It never holds the private half:
//! its database role cannot read it, so a gateway that is broken into cannot
//! sign anything in a tenant's name.

use time::OffsetDateTime;

use crate::domains::crypto::key_status::KeyState;
use crate::domains::crypto::signing_key::{SigningAlgorithm, SigningKey};
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{Expiry, KeyId, Lifetime, PublicKeyPem};

/// The public half of one signing key, with where the key stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    kid: KeyId,
    algorithm: SigningAlgorithm,
    public_key: PublicKeyPem,
    state: KeyState,
    expires_at: Expiry,
}

/// Persisted state of a [`VerifyingKey`]: a signing key's row without its
/// private key.
pub struct VerifyingKeyRow {
    /// The `kid` value in JWT headers and the JWKS.
    pub kid: KeyId,
    /// The signing algorithm, RS256, ES256 or EdDSA.
    pub algorithm: SigningAlgorithm,
    /// The PEM-encoded public key.
    pub public_key: PublicKeyPem,
    /// Where the key stands. See [`KeyState::from_stored`].
    pub state: KeyState,
    /// When the key was created.
    pub created_at: OffsetDateTime,
    /// When it stops signing, or that it never does.
    pub expires_at: Expiry,
}

impl VerifyingKey {
    /// Rebuilds the public half of a signing key from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the key was
    ///   rotated before it was created.
    pub fn reconstitute(row: VerifyingKeyRow) -> Result<Self, DomainError> {
        RowCheck::of("verifying key")
            .in_order_if(
                row.created_at,
                row.state.rotated_at(),
                "rotated before it was created",
            )
            .finish()?;
        Ok(Self {
            kid: row.kid,
            algorithm: row.algorithm,
            public_key: row.public_key,
            state: row.state,
            expires_at: row.expires_at,
        })
    }

    /// The public half of `key`, where it stands as the key does.
    #[must_use]
    pub fn of(key: &SigningKey) -> Self {
        Self {
            kid: key.kid().clone(),
            algorithm: key.algorithm(),
            public_key: key.public_key().clone(),
            state: key.state(),
            expires_at: key.expires_at(),
        }
    }

    /// The `kid` value used in JWT headers and the JWKS.
    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    /// The signing algorithm, RS256, ES256 or EdDSA. A verifier holds a
    /// token to it and never to the algorithm the token's header names.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The PEM-encoded public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKeyPem {
        &self.public_key
    }

    /// Whether a verifier may still accept tokens this key signed, so the
    /// JWKS publishes it at `now`, as [`KeyState::is_published`] judges.
    #[must_use]
    pub fn is_in_jwks(&self, grace: Lifetime, now: OffsetDateTime) -> bool {
        self.state.is_published(self.expires_at, grace, now)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::crypto::key_status::PriorRotation;
    use crate::shared::model::row_check::refused_as_corrupt;

    fn row(state: KeyState, created_at: OffsetDateTime) -> VerifyingKeyRow {
        VerifyingKeyRow {
            kid: KeyId::new("key-1").unwrap(),
            algorithm: SigningAlgorithm::Es256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            state,
            created_at,
            expires_at: Expiry::Never,
        }
    }

    fn grace() -> Lifetime {
        Lifetime::seconds(3600).unwrap()
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// The tenant's active key is published, so the gateway accepts what it
    /// signs.
    #[test]
    fn an_active_key_is_published() {
        let key = VerifyingKey::reconstitute(row(KeyState::Active, now())).unwrap();

        assert!(key.is_in_jwks(grace(), now()));
    }

    /// A key rotated out ten minutes ago stays published for its hour of
    /// grace, and is gone once the hour is over.
    #[test]
    fn a_rotated_key_is_published_through_its_grace_only() {
        let rotated = now() - Duration::minutes(10);
        let key = VerifyingKey::reconstitute(row(
            KeyState::Rotated { at: rotated },
            rotated - Duration::days(1),
        ))
        .unwrap();

        assert!(key.is_in_jwks(grace(), now()));
        assert!(!key.is_in_jwks(grace(), now() + Duration::hours(1)));
    }

    /// A revoked key read from storage is excluded from the published JWKS.
    #[test]
    fn a_revoked_key_is_never_published() {
        let key = VerifyingKey::reconstitute(row(
            KeyState::Revoked {
                before: PriorRotation::NotRotated,
            },
            now(),
        ))
        .unwrap();

        assert!(!key.is_in_jwks(grace(), now()));
    }

    /// A stored key rotated a day before its creation is refused as corrupt.
    #[test]
    fn a_key_rotated_before_it_was_made_is_refused() {
        let made = now();

        let rebuilt = VerifyingKey::reconstitute(row(
            KeyState::Rotated {
                at: made - Duration::days(1),
            },
            made,
        ));

        assert!(refused_as_corrupt(&rebuilt));
    }
}
