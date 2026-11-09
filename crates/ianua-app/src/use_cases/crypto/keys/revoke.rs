//! Revoke key: take a signing key out of the JWKS for good. Tokens it signed
//! no longer verify.

use std::sync::Arc;

use ianua_domain::domains::crypto::control::CryptoControlCheck;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::KeyId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::SigningKeyStore;
use crate::services::lookup::existing_key_set;
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::save_key_set;

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Loads and saves the tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Revokes one of the tenant's signing keys.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeUseCase {
    type Caller = CallerContext;
    type Input = KeyId;
    type Output = Result<(), AppError>;

    /// Revokes the key `kid` names and records `crypto.key_revoked`. Relying
    /// parties stop accepting tokens it signed.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without signing-key rights.
    /// - `AppError::NotFound` for a missing key set or `kid`; `Conflict` for the only current signer.
    /// - `AppError::Domain` for an already revoked key; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        kid: KeyId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        CryptoControlCheck::ensure_may_change_keys(&authority).map_err(AppError::from_domain)?;
        let key_store = self.ports.key_store.as_ref();
        let tenant = caller.tenant();
        let mut key_set = existing_key_set(key_store, &tenant).await?;
        key_set
            .revoke_key(&kid, &authority)
            .map_err(AppError::from_domain)?;
        save_key_set(key_store, &tenant, &key_set).await?;

        auditor
            .dispatch_by(&caller.actor(), key_set.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
    use ianua_domain::domains::crypto::key_status::KeyStatus;
    use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKeySet};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::Lifetime;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{FakeSigningKeyStore, key_keeper, test_signing_key};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: RevokeUseCase,
        store: Arc<FakeSigningKeyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn fixture_with(store: FakeSigningKeyStore, authorities: FakeTenantAuthorities) -> Fixture {
        let store = Arc::new(store);
        let use_case = RevokeUseCase::new(RevokePorts {
            key_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            store,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn fixture(store: FakeSigningKeyStore) -> Fixture {
        fixture_with(store, FakeTenantAuthorities::holding_everything())
    }

    fn kid(value: &str) -> KeyId {
        KeyId::new(value).unwrap()
    }

    /// `key-old`, rotated out, beside `key-new`, which signs.
    fn rotated_set() -> SigningKeySet<ResolvedTenant> {
        let mut set = SigningKeySet::new(test_signing_key("key-old", SigningAlgorithm::Rs256));
        set.rotate_to(
            test_signing_key("key-new", SigningAlgorithm::Rs256),
            key_keeper(),
        )
        .unwrap();
        set
    }

    fn single_key() -> FakeSigningKeyStore {
        FakeSigningKeyStore::holding(SigningKeySet::new(test_signing_key(
            "key-1",
            SigningAlgorithm::Rs256,
        )))
    }

    fn revoke(f: &Fixture, value: &str) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), kid(value)),
        )
    }

    fn status_of(f: &Fixture, value: &str) -> KeyStatus {
        let set = f.store.set_of(test_ctx().tenant_id()).unwrap();
        set.keys()
            .iter()
            .find(|k| k.kid().as_str() == value)
            .unwrap()
            .status()
    }

    /// Ann revokes Acme's rotated-out key. It leaves the JWKS at once and
    /// the revocation is recorded.
    #[test]
    fn a_rotated_key_is_revoked_and_unpublished() {
        let f = fixture(FakeSigningKeyStore::holding(rotated_set()));

        revoke(&f, "key-old").unwrap();

        let set = f.store.set_of(test_ctx().tenant_id()).unwrap();
        let grace = Lifetime::seconds(3600).unwrap();
        let published: Vec<&str> = set
            .jwks_keys(grace, clock::now())
            .iter()
            .map(|k| k.kid().as_str())
            .collect();
        assert_eq!(status_of(&f, "key-old"), KeyStatus::Revoked);
        assert_eq!(published, ["key-new"]);
        assert_eq!(f.audit.records.lock().unwrap()[0], "crypto.key_revoked");
    }

    /// Ann names a key Acme never had. It is not found.
    #[test]
    fn an_unknown_key_is_not_found() {
        let f = fixture(single_key());

        let result = revoke(&f, "nonexistent");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Acme has no signing keys at all. Revoking one is not found.
    #[test]
    fn a_tenant_without_keys_is_not_found() {
        let f = fixture(FakeSigningKeyStore::empty());

        let result = revoke(&f, "any");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann tries to revoke the only key Acme signs with. It is refused, so
    /// the tenant is never left with nothing to sign with.
    #[test]
    fn the_only_signer_cannot_be_revoked() {
        let f = fixture(single_key());

        let result = revoke(&f, "key-1");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(status_of(&f, "key-1"), KeyStatus::Active);
    }

    /// Ann revokes a key that is already revoked. The domain refuses the
    /// move and nothing is recorded.
    #[test]
    fn a_revoked_key_cannot_be_revoked_again() {
        let mut set = rotated_set();
        set.revoke_key(&kid("key-old"), key_keeper()).unwrap();
        let f = fixture(FakeSigningKeyStore::holding(set));

        let result = revoke(&f, "key-old");

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A key viewer cannot revoke a rotated key; its status remains rotated
    /// and no revocation is recorded.
    #[test]
    fn a_caller_who_may_only_view_keys_is_refused() {
        let f = fixture_with(
            FakeSigningKeyStore::holding(rotated_set()),
            FakeTenantAuthorities::holding(&[SystemPermission::Crypto(CryptoAction::View)]),
        );

        let result = revoke(&f, "key-old");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&f, "key-old"), KeyStatus::Rotated);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot revoke a rotated signing key.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            FakeSigningKeyStore::holding(rotated_set()),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = revoke(&f, "key-old");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
