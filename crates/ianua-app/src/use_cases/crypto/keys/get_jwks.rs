//! Get JWKS: the tenant's public signing keys as JWK components.
//!
//! The use case behind `/.well-known/jwks.json`. Any relying party may fetch
//! a tenant's public keys, so it asks for no caller, only the tenant the
//! request's host resolved to.

use std::sync::Arc;

use ianua_domain::domains::crypto::jwk::JwkComponents;
use ianua_domain::shared::clock;
use ianua_domain::types::Lifetime;

use crate::error::AppError;
use crate::ports::crypto::{PublicKeyDecoder, SigningKeyStore};
use crate::services::lookup::existing_key_set;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// The ports [`GetJwksUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetJwksPorts {
    /// Loads the tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Decodes PEM public keys into JWK components.
    pub decoder: Arc<dyn PublicKeyDecoder>,
}

/// Lists the tenant's published signing keys as JWK components.
pub struct GetJwksUseCase {
    ports: GetJwksPorts,
    grace: Lifetime,
}

impl GetJwksUseCase {
    /// A use case reading through `ports`, publishing a key for `grace`
    /// after it stops signing, so tokens it signed just before have time to
    /// run out.
    #[must_use]
    pub fn new(ports: GetJwksPorts, grace: Lifetime) -> Self {
        Self { ports, grace }
    }
}

impl Query for GetJwksUseCase {
    type Caller = ScopedTenant;
    type Input = ();
    type Output = Result<Vec<JwkComponents>, AppError>;

    /// The keys the tenant's JWKS publishes now, as JWK components.
    ///
    /// A key whose PEM does not decode is left out, so one broken key does
    /// not take the whole endpoint down.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant has no key set.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, tenant: &ScopedTenant, (): ()) -> Result<Vec<JwkComponents>, AppError> {
        let key_set = existing_key_set(self.ports.key_store.as_ref(), tenant).await?;
        let components = key_set
            .jwks_keys(self.grace, clock::now())
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
    use ianua_domain::domains::crypto::signing_key::{
        NewSigningKey, SigningAlgorithm, SigningKey, SigningKeySet,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Expiry, KeyId, PublicKeyPem};
    use time::Duration;

    use super::*;
    use crate::test_support::crypto::{FakeSigningKeyStore, key_keeper, test_signing_key};
    use crate::test_support::{block_on, test_ctx};

    struct FailingDecoder;

    impl PublicKeyDecoder for FailingDecoder {
        fn decode(
            &self,
            _pem: &PublicKeyPem,
            _kid: &KeyId,
            _algorithm: SigningAlgorithm,
        ) -> Result<JwkComponents, DomainError> {
            Err(DomainError::infra_msg("bad PEM"))
        }
    }

    fn grace() -> Lifetime {
        Lifetime::seconds(3600).unwrap()
    }

    fn use_case_over(set: SigningKeySet<ResolvedTenant>) -> GetJwksUseCase {
        GetJwksUseCase::new(
            GetJwksPorts {
                key_store: Arc::new(FakeSigningKeyStore::holding(set)),
                ..GetJwksPorts::fakes()
            },
            grace(),
        )
    }

    fn published(use_case: &GetJwksUseCase) -> Vec<String> {
        block_on(use_case.execute(&test_ctx().tenant(), ()))
            .unwrap()
            .iter()
            .map(|jwk| jwk.kid().to_owned())
            .collect()
    }

    fn key_expiring(kid: &str, at: time::OffsetDateTime) -> SigningKey {
        SigningKey::create(NewSigningKey {
            kid: KeyId::new(kid).unwrap(),
            algorithm: SigningAlgorithm::Rs256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            private_key: Secret::new("private"),
            expires_at: Expiry::At(at),
        })
    }

    /// A relying party fetches Acme's JWKS. It gets the signing key as an
    /// RSA JWK under its own kid.
    #[test]
    fn the_signing_key_is_published() {
        let use_case = use_case_over(SigningKeySet::new(test_signing_key(
            "key-1",
            SigningAlgorithm::Rs256,
        )));

        let jwks = block_on(use_case.execute(&test_ctx().tenant(), ())).unwrap();

        assert_eq!(jwks.len(), 1);
        assert_eq!(jwks[0].kid(), "key-1");
        assert_eq!(jwks[0].kty(), "RSA");
    }

    /// One of Acme's keys has a PEM that does not decode. It is left out
    /// rather than failing the whole JWKS.
    #[test]
    fn a_key_that_does_not_decode_is_left_out() {
        let use_case = GetJwksUseCase::new(
            GetJwksPorts {
                key_store: Arc::new(FakeSigningKeyStore::holding(SigningKeySet::new(
                    test_signing_key("bad-key", SigningAlgorithm::Rs256),
                ))),
                decoder: Arc::new(FailingDecoder),
            },
            grace(),
        );

        assert!(published(&use_case).is_empty());
    }

    /// A tenant that never had signing keys has no JWKS.
    #[test]
    fn a_tenant_without_keys_is_not_found() {
        let use_case = GetJwksUseCase::new(GetJwksPorts::fakes(), grace());

        let result = block_on(use_case.execute(&test_ctx().tenant(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann revoked Acme's old key after rotating. Only the new key is
    /// published.
    #[test]
    fn a_revoked_key_is_not_published() {
        let mut set = SigningKeySet::new(test_signing_key("key-1", SigningAlgorithm::Rs256));
        set.rotate_to(
            test_signing_key("key-2", SigningAlgorithm::Rs256),
            key_keeper(),
        )
        .unwrap();
        set.revoke_key(&KeyId::new("key-1").unwrap(), key_keeper())
            .unwrap();

        assert_eq!(published(&use_case_over(set)), ["key-2"]);
    }

    /// Acme's key expired two hours ago and nothing rotated it. With an
    /// hour's grace it is no longer published, so tokens it signed stop
    /// verifying instead of verifying forever.
    #[test]
    fn a_key_past_its_expiry_and_grace_is_not_published() {
        let expired = key_expiring("old", clock::now() - Duration::hours(2));
        let set = SigningKeySet::from_keys(vec![
            expired,
            test_signing_key("current", SigningAlgorithm::Rs256),
        ])
        .unwrap();

        assert_eq!(published(&use_case_over(set)), ["current"]);
    }

    /// Acme's key expired ten minutes ago. It is still published through its
    /// grace, so tokens it signed just before keep verifying.
    #[test]
    fn a_key_just_past_its_expiry_is_published_through_its_grace() {
        let expired = key_expiring("old", clock::now() - Duration::minutes(10));
        let set = SigningKeySet::from_keys(vec![
            expired,
            test_signing_key("current", SigningAlgorithm::Rs256),
        ])
        .unwrap();

        assert_eq!(published(&use_case_over(set)), ["old", "current"]);
    }
}
