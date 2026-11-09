//! Reading one of the tenant's OAuth clients.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ApiKeyAction, SystemPermission};
use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::OAuthClientId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::oauth::OAuthClientStore;
use crate::use_case::Query;
use crate::use_cases::oauth::lookup::existing_client;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one OAuth client.
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
    type Input = OAuthClientId;
    type Output = Result<OAuthClient<ResolvedTenant>, AppError>;

    /// The client `id` of `caller`'s tenant.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view API keys and
    ///   clients.
    /// - `AppError::NotFound` when the tenant has no such client.
    /// - `AppError::Internal` when the client cannot be read.
    async fn execute(
        &self,
        caller: &CallerContext,
        id: OAuthClientId,
    ) -> Result<OAuthClient<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::ApiKeys(ApiKeyAction::View))
            .map_err(AppError::from_domain)?;
        existing_client(self.ports.client_store.as_ref(), &caller.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeOAuthClientStore, stored_client};
    use crate::test_support::{block_on, test_ctx};

    fn portal() -> OAuthClient<ResolvedTenant> {
        stored_client("Portal", &[GrantType::AuthorizationCode])
    }

    fn get_as(
        authorities: FakeTenantAuthorities,
        client: OAuthClient<ResolvedTenant>,
        id: OAuthClientId,
    ) -> Result<OAuthClient<ResolvedTenant>, AppError> {
        let use_case = GetUseCase::new(GetPorts {
            client_store: Arc::new(FakeOAuthClientStore::holding(&test_ctx().tenant(), client)),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), id))
    }

    /// Ann opens the portal client and reads it.
    #[test]
    fn a_kept_client_is_read() {
        let client = portal();
        let id = *client.id();

        let read = get_as(FakeTenantAuthorities::holding_everything(), client, id).unwrap();

        assert_eq!(read.name().as_str(), "Portal");
    }

    /// Ann opens a client the tenant does not have. She is told it is not
    /// found.
    #[test]
    fn an_unknown_client_is_not_found() {
        let result = get_as(
            FakeTenantAuthorities::holding_everything(),
            portal(),
            OAuthClientId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without view permission is forbidden from reading the
    /// portal client.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let client = portal();
        let id = *client.id();

        let result = get_as(FakeTenantAuthorities::holding(&[]), client, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives unauthenticated when reading the portal client.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let client = portal();
        let id = *client.id();

        let result = get_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            client,
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
