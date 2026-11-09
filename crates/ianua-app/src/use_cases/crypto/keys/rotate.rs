//! Rotate key: generate a new signing key and rotate the old one out. The old
//! key stays in the JWKS for its grace period, so tokens it signed still
//! verify.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::crypto::control::CryptoControlCheck;
use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKey, SigningKeySet};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::KeyId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{KeyGenerator, SigningKeyStore};
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::{generated_signing_key, save_key_set};

/// The ports [`RotateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotatePorts {
    /// Loads and saves the tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Generates the new key.
    pub key_generator: Arc<dyn KeyGenerator>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Rotates the tenant's signing key onto a freshly generated one.
pub struct RotateUseCase {
    ports: RotatePorts,
}

impl RotateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RotatePorts) -> Self {
        Self { ports }
    }
}

impl Command for RotateUseCase {
    type Caller = CallerContext;
    type Input = SigningAlgorithm;
    type Output = Result<KeyId, AppError>;

    /// Generates a key signing with `algorithm` and makes it the tenant's
    /// signer, recording `crypto.key_rotated`. Every key that signed until
    /// now is rotated out and stays published for its grace period.
    ///
    /// A tenant without a key set gets one holding only the new key, and
    /// `crypto.key_created` is recorded instead.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change signing keys.
    ///   Nothing is generated then.
    /// - `AppError::Internal` on key generation, persistence or audit
    ///   failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        algorithm: SigningAlgorithm,
    ) -> Result<KeyId, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        CryptoControlCheck::ensure_may_change_keys(&authority).map_err(AppError::from_domain)?;
        let new_key = generated_signing_key(self.ports.key_generator.as_ref(), algorithm).await?;
        let new_kid = new_key.kid().clone();
        let tenant = caller.tenant();
        let existing = self.ports.key_store.find(&tenant).await.or_internal()?;

        let mut key_set = rotated_onto(existing, new_key, &authority)?;
        save_key_set(self.ports.key_store.as_ref(), &tenant, &key_set).await?;
        auditor
            .dispatch_by(&caller.actor(), key_set.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(new_kid)
    }
}

/// The key set with `new_key` as its signer: the existing set rotated onto
/// it, or a fresh set holding only it.
fn rotated_onto(
    existing: Option<SigningKeySet<ResolvedTenant>>,
    new_key: SigningKey,
    by: &TenantAuthority,
) -> Result<SigningKeySet<ResolvedTenant>, AppError> {
    let Some(mut key_set) = existing else {
        return Ok(SigningKeySet::new(new_key));
    };
    key_set
        .rotate_to(new_key, by)
        .map_err(AppError::from_domain)?;
    Ok(key_set)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
    use ianua_domain::domains::crypto::key_status::KeyStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::Lifetime;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{FakeKeyGenerator, FakeSigningKeyStore, test_signing_key};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: RotateUseCase,
        store: Arc<FakeSigningKeyStore>,
        generator: Arc<FakeKeyGenerator>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn fixture_with(store: FakeSigningKeyStore, authorities: FakeTenantAuthorities) -> Fixture {
        let store = Arc::new(store);
        let generator = Arc::new(FakeKeyGenerator::new());
        let use_case = RotateUseCase::new(RotatePorts {
            key_store: store.clone(),
            key_generator: generator.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            store,
            generator,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn fixture(store: FakeSigningKeyStore) -> Fixture {
        fixture_with(store, FakeTenantAuthorities::holding_everything())
    }

    fn one_key() -> FakeSigningKeyStore {
        FakeSigningKeyStore::holding(SigningKeySet::new(test_signing_key(
            "key-old",
            SigningAlgorithm::Rs256,
        )))
    }

    fn rotate(f: &Fixture) -> Result<KeyId, AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            SigningAlgorithm::Rs256,
        ))
    }

    fn held(f: &Fixture) -> SigningKeySet<ResolvedTenant> {
        f.store.set_of(test_ctx().tenant_id()).unwrap()
    }

    /// Ann rotates Acme's signing key. The new key signs from now on, the
    /// old one is rotated out, and the rotation is recorded.
    #[test]
    fn rotating_makes_the_new_key_the_signer() {
        let f = fixture(one_key());

        let new_kid = rotate(&f).unwrap();

        let set = held(&f);
        assert_eq!(set.keys().len(), 2);
        assert_eq!(set.active_key(clock::now()).unwrap().kid(), &new_kid);
        let old = set
            .keys()
            .iter()
            .find(|k| k.kid().as_str() == "key-old")
            .unwrap();
        assert_eq!(old.status(), KeyStatus::Rotated);
        assert_eq!(f.audit.records.lock().unwrap()[0], "crypto.key_rotated");
    }

    /// Acme has no signing keys yet. Ann's rotation creates the first one,
    /// recorded as created rather than rotated.
    #[test]
    fn a_first_key_is_recorded_as_created() {
        let f = fixture(FakeSigningKeyStore::empty());

        rotate(&f).unwrap();

        assert_eq!(held(&f).keys().len(), 1);
        assert_eq!(f.audit.records.lock().unwrap()[0], "crypto.key_created");
    }

    /// After Ann rotates, tokens the old key signed still verify: both keys
    /// are published until the old one's grace is over.
    #[test]
    fn the_rotated_key_stays_published() {
        let f = fixture(one_key());

        rotate(&f).unwrap();

        let grace = Lifetime::seconds(3600).unwrap();
        assert_eq!(held(&f).jwks_keys(grace, clock::now()).len(), 2);
    }

    /// Ann rotates twice. Every key is kept, the two older ones rotated out,
    /// and one signs.
    #[test]
    fn rotating_twice_keeps_every_key() {
        let f = fixture(one_key());

        rotate(&f).unwrap();
        rotate(&f).unwrap();

        let set = held(&f);
        let rotated = set
            .keys()
            .iter()
            .filter(|k| k.status() == KeyStatus::Rotated)
            .count();
        assert_eq!(set.keys().len(), 3);
        assert_eq!(rotated, 2);
        assert!(set.active_key(clock::now()).is_some());
    }

    /// A key viewer cannot rotate the signer; no key is generated, the set
    /// still holds one key and no rotation is recorded.
    #[test]
    fn a_caller_who_may_only_view_keys_is_refused() {
        let f = fixture_with(
            one_key(),
            FakeTenantAuthorities::holding(&[SystemPermission::Crypto(CryptoAction::View)]),
        );

        let result = rotate(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.generator.generated(), 0);
        assert_eq!(held(&f).keys().len(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Without crypto rights, creating the tenant's first signing key is
    /// forbidden and no key set is stored.
    #[test]
    fn a_caller_holding_nothing_cannot_create_the_first_key() {
        let f = fixture_with(
            FakeSigningKeyStore::empty(),
            FakeTenantAuthorities::holding(&[]),
        );

        let result = rotate(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.store.set_of(test_ctx().tenant_id()).is_none());
    }

    /// A signed-out session cannot rotate the tenant's signing key.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            one_key(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = rotate(&f);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
