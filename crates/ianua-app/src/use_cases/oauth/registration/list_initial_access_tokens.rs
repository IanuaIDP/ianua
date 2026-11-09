//! Listing the initial access tokens the tenant issued, revoked ones too,
//! with the uses each has left. The tokens themselves are never shown
//! again.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ApiKeyAction, SystemPermission};
use ianua_domain::domains::oauth::clients::registration::InitialAccessToken;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::InitialAccessTokenStore;
use crate::use_case::Query;

/// The ports [`ListInitialAccessTokensUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListInitialAccessTokensPorts {
    /// Where initial access tokens are kept.
    pub token_store: Arc<dyn InitialAccessTokenStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's initial access tokens.
pub struct ListInitialAccessTokensUseCase {
    ports: ListInitialAccessTokensPorts,
}

impl ListInitialAccessTokensUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListInitialAccessTokensPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListInitialAccessTokensUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<InitialAccessToken<ResolvedTenant>>, AppError>;

    /// Every initial access token of `caller`'s tenant, newest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view API keys and
    ///   clients.
    /// - `AppError::Internal` when the tokens cannot be read.
    async fn execute(
        &self,
        caller: &CallerContext,
        (): (),
    ) -> Result<Vec<InitialAccessToken<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::ApiKeys(ApiKeyAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .token_store
            .list_all(&caller.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::registration::NewInitialAccessToken;
    use ianua_domain::domains::oauth::control::OAuthControl;
    use ianua_domain::types::{InitialAccessTokenId, Label, Lifetime};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeInitialAccessTokenStore, hash_of};
    use crate::test_support::{block_on, test_ctx};

    /// A store holding one token Ann issued for MCP clients.
    fn holding_one() -> Arc<FakeInitialAccessTokenStore> {
        let store = Arc::new(FakeInitialAccessTokenStore::empty());
        let authority =
            block_on(FakeTenantAuthorities::holding_everything().authority(&test_ctx())).unwrap();
        let token = InitialAccessToken::issue(
            NewInitialAccessToken {
                id: InitialAccessTokenId::new(),
                name: Label::new("name", "MCP clients").unwrap(),
                token_hash: hash_of("iat"),
                uses: 5,
                lifetime: Lifetime::seconds(3600).unwrap(),
            },
            &OAuthControl::new(&authority),
        )
        .unwrap();
        block_on(store.save(&test_ctx().tenant(), &token)).unwrap();
        store
    }

    /// What listing answers for a caller `authorities` describe.
    fn list(
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<InitialAccessToken<ResolvedTenant>>, AppError> {
        let use_case = ListInitialAccessTokensUseCase::new(ListInitialAccessTokensPorts {
            token_store: holding_one(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann lists the tenant's tokens. She sees the one issued, with its
    /// uses left.
    #[test]
    fn the_tokens_are_listed() {
        let listed = list(FakeTenantAuthorities::holding(&[
            SystemPermission::ApiKeys(ApiKeyAction::View),
        ]))
        .unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].uses_left(), 5);
    }

    /// A caller without the API-key view right cannot list initial access tokens.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list initial access tokens.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
