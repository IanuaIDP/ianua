//! The tenant's published assertion keys: the public halves an upstream
//! checks `X-Ianua-Assertion` with.
//!
//! The use case behind `/.well-known/ianua-assertion-keys.json`. It is a
//! key set of its own, apart from the tenant's JWKS, so a relying party
//! that trusts the tenant's tokens never takes an assertion for one. Any
//! upstream may fetch it, so it asks for no caller, only the tenant the
//! request's address resolved to.

use std::sync::Arc;

use ianua_domain::domains::crypto::jwk::JwkComponents;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::Lifetime;

use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{AssertionKeyStore, PublicKeyDecoder};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// The ports [`GetPublishedUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPublishedPorts {
    /// Loads the tenant's assertion keys, their public halves only.
    pub keys: Arc<dyn AssertionKeyStore>,
    /// Decodes PEM public keys into JWK components.
    pub decoder: Arc<dyn PublicKeyDecoder>,
}

/// Lists the tenant's published assertion keys as JWK components.
pub struct GetPublishedUseCase {
    ports: GetPublishedPorts,
    overlap: Lifetime,
}

impl GetPublishedUseCase {
    /// A use case reading through `ports`, publishing a key for `overlap`
    /// after it was rotated out: the overlap the rotation schedule keeps.
    #[must_use]
    pub fn new(ports: GetPublishedPorts, overlap: Lifetime) -> Self {
        Self { ports, overlap }
    }
}

impl Query for GetPublishedUseCase {
    type Caller = ScopedTenant;
    type Input = ();
    type Output = Result<Vec<JwkComponents>, AppError>;

    /// The assertion keys an upstream may accept now, as JWK components.
    ///
    /// A key whose PEM does not decode is left out, so one broken key does
    /// not take the whole set down.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant has no assertion keys.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, tenant: &ScopedTenant, (): ()) -> Result<Vec<JwkComponents>, AppError> {
        let Some(keys) = self.ports.keys.find(tenant).await.or_internal()? else {
            return Err(AppError::NotFound(message!(
                "crypto-the-tenant-has-no-assertion-keys",
                "the tenant has no assertion keys"
            )));
        };
        let components = keys
            .published(self.overlap, clock::now())
            .into_iter()
            .filter_map(|key| {
                self.ports
                    .decoder
                    .decode(key.public_key(), key.kid(), key.algorithm())
                    .ok()
            })
            .collect();
        Ok(components)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::assertion_key::{
        AssertionKey, AssertionKeySet, NewAssertionKey,
    };
    use ianua_domain::domains::crypto::rotation::KeyRotationSchedule;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{KeyId, PublicKeyPem};
    use time::Duration;

    use super::*;
    use crate::test_support::crypto::FakeAssertionKeyStore;
    use crate::test_support::{block_on, test_ctx};

    fn key(kid: &str) -> AssertionKey {
        AssertionKey::create(NewAssertionKey {
            kid: KeyId::new(kid).unwrap(),
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
        })
    }

    fn published(store: FakeAssertionKeyStore) -> Result<Vec<String>, AppError> {
        let use_case = GetPublishedUseCase::new(
            GetPublishedPorts {
                keys: Arc::new(store),
                ..GetPublishedPorts::fakes()
            },
            KeyRotationSchedule::FOR_ASSERTION_KEYS.overlap(),
        );
        let jwks = block_on(use_case.execute(&test_ctx().tenant(), ()))?;
        Ok(jwks.iter().map(|jwk| jwk.kid().to_owned()).collect())
    }

    /// An upstream fetches Acme's assertion keys. It gets the signing key
    /// and the one rotated out an hour ago, which may still have signed an
    /// assertion in flight.
    #[test]
    fn the_signing_key_and_one_within_its_overlap_are_published() {
        let now = clock::now();
        let mut set = {
            let _frozen = clock::freeze(now - Duration::days(31));
            AssertionKeySet::new(key("old"))
        };
        {
            let _frozen = clock::freeze(now - Duration::HOUR);
            set.rotate_by_age(
                &KeyRotationSchedule::FOR_ASSERTION_KEYS,
                key("new"),
                now - Duration::HOUR,
            )
            .unwrap();
        }

        let kids = published(FakeAssertionKeyStore::holding(&set)).unwrap();

        assert_eq!(kids, ["old", "new"]);
    }

    /// A tenant with no assertion keys yet answers not found.
    #[test]
    fn a_tenant_without_assertion_keys_is_not_found() {
        let found = published(FakeAssertionKeyStore::empty());

        assert!(matches!(found, Err(AppError::NotFound(_))));
    }
}
