//! Get key set: the tenant's signing keys, for an admin to look over.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
use ianua_domain::domains::crypto::signing_key::SigningKeySet;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::crypto::SigningKeyStore;
use crate::services::lookup::existing_key_set;
use crate::use_case::Query;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads the tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the tenant's signing key set.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<SigningKeySet<ResolvedTenant>, AppError>;

    /// The caller's tenant's signing key set, once they may view its keys.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view signing keys.
    /// - `AppError::NotFound` when the tenant has no key set.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        (): (),
    ) -> Result<SigningKeySet<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Crypto(CryptoAction::View))
            .map_err(AppError::from_domain)?;
        existing_key_set(self.ports.key_store.as_ref(), &caller.tenant()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{FakeSigningKeyStore, test_signing_key};
    use crate::test_support::{block_on, test_ctx};

    fn use_case_with(authorities: FakeTenantAuthorities) -> GetUseCase {
        GetUseCase::new(GetPorts {
            key_store: Arc::new(FakeSigningKeyStore::holding(SigningKeySet::new(
                test_signing_key("key-1", SigningAlgorithm::Rs256),
            ))),
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// Ann may view Acme's signing keys. She gets its key set.
    #[test]
    fn a_viewer_gets_the_key_set() {
        let use_case = use_case_with(FakeTenantAuthorities::holding(&[SystemPermission::Crypto(
            CryptoAction::View,
        )]));

        let set = block_on(use_case.execute(&test_ctx(), ())).unwrap();

        assert_eq!(set.keys().len(), 1);
    }

    /// A tenant that never had signing keys has no key set to show.
    #[test]
    fn a_tenant_without_keys_is_not_found() {
        let use_case = GetUseCase::new(GetPorts::fakes());

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading the tenant's signing key set requires the crypto view right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let use_case = use_case_with(FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's signing key set.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
