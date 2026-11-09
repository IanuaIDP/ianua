//! Reading one of the tenant's API keys.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ApiKeyAction, SystemPermission};
use ianua_domain::domains::oauth::clients::api_key::ApiKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::ApiKeyId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::oauth::ApiKeyStore;
use crate::use_case::Query;
use crate::use_cases::oauth::lookup::existing_api_key;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Where keys are kept.
    pub key_store: Arc<dyn ApiKeyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one API key.
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
    type Input = ApiKeyId;
    type Output = Result<ApiKey<ResolvedTenant>, AppError>;

    /// The key `id` of `caller`'s tenant.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view API keys.
    /// - `AppError::NotFound` when the tenant has no such key.
    /// - `AppError::Internal` when the key cannot be read.
    async fn execute(
        &self,
        caller: &CallerContext,
        id: ApiKeyId,
    ) -> Result<ApiKey<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::ApiKeys(ApiKeyAction::View))
            .map_err(AppError::from_domain)?;
        existing_api_key(self.ports.key_store.as_ref(), &caller.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeApiKeyStore, stored_api_key};
    use crate::test_support::{block_on, test_ctx};

    fn get_as(
        authorities: FakeTenantAuthorities,
        id: Option<ApiKeyId>,
    ) -> Result<ApiKey<ResolvedTenant>, AppError> {
        let key = stored_api_key("CI", test_ctx().actor());
        let id = id.unwrap_or(*key.id());
        let use_case = GetUseCase::new(GetPorts {
            key_store: Arc::new(FakeApiKeyStore::holding(&test_ctx().tenant(), key)),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), id))
    }

    /// Ann opens the CI key and reads it.
    #[test]
    fn a_kept_key_is_read() {
        let key = get_as(FakeTenantAuthorities::holding_everything(), None).unwrap();

        assert_eq!(key.name().as_str(), "CI");
    }

    /// Ann opens a key the tenant does not have, or no longer has since it
    /// was revoked. She is told it is not found.
    #[test]
    fn an_unknown_key_is_not_found() {
        let result = get_as(
            FakeTenantAuthorities::holding_everything(),
            Some(ApiKeyId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without API-key view permission is forbidden from reading
    /// the CI key.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = get_as(FakeTenantAuthorities::holding(&[]), None);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives unauthenticated when reading the CI key.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = get_as(FakeTenantAuthorities::refusing(Refusal::SignedOut), None);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
