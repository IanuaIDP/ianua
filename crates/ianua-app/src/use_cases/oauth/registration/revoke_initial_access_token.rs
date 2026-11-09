//! Revoking an initial access token, as when it leaked: no app registers
//! with it after. Clients that registered with it stay; they can be found
//! by the token they were admitted with.

use std::sync::Arc;

use ianua_domain::domains::oauth::control::{OAuthControl, OAuthRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::InitialAccessTokenId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::InitialAccessTokenStore;
use crate::use_case::Command;
use crate::use_cases::oauth::lookup::existing_initial_access_token;

/// The ports [`RevokeInitialAccessTokenUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeInitialAccessTokenPorts {
    /// Where initial access tokens are kept.
    pub token_store: Arc<dyn InitialAccessTokenStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Withdraws the credential so it cannot authorize further client registrations.
pub struct RevokeInitialAccessTokenUseCase {
    ports: RevokeInitialAccessTokenPorts,
}

impl RevokeInitialAccessTokenUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeInitialAccessTokenPorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeInitialAccessTokenUseCase {
    type Caller = CallerContext;
    type Input = InitialAccessTokenId;
    type Output = Result<(), AppError>;

    /// Revokes the token `id` of `caller`'s tenant for good and records
    /// `oauth.initial_access_token_revoked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not revoke clients.
    /// - `AppError::NotFound` when the tenant has no such token.
    /// - `AppError::Domain` when it was revoked already.
    /// - `AppError::Internal` when the token cannot be read, saved or
    ///   audited.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        id: InitialAccessTokenId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = OAuthControl::new(&authority);
        control
            .ensure_may(OAuthRight::Revoke)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.token_store.as_ref();
        let mut token = existing_initial_access_token(store, &tenant, &id).await?;
        token.revoke(&control).map_err(AppError::from_domain)?;
        store.save(&tenant, &token).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), token.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::registration::{
        InitialAccessToken, NewInitialAccessToken,
    };
    use ianua_domain::types::{Label, Lifetime};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeInitialAccessTokenStore, hash_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A store holding one live token, and its id.
    fn holding_one() -> (Arc<FakeInitialAccessTokenStore>, InitialAccessTokenId) {
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
        (store, *token.id())
    }

    /// What revoking `id` in `store`, as `authorities` allow, answers.
    fn revoke(
        store: &Arc<FakeInitialAccessTokenStore>,
        authorities: FakeTenantAuthorities,
        id: InitialAccessTokenId,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<(), AppError> {
        let use_case = RevokeInitialAccessTokenUseCase::new(RevokeInitialAccessTokenPorts {
            token_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id))
    }

    /// Whether the token `id` in `store` is revoked.
    fn is_revoked(store: &FakeInitialAccessTokenStore, id: &InitialAccessTokenId) -> bool {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .revocation()
            .is_revoked()
    }

    /// The token leaked, so Ann revokes it. It is revoked and recorded.
    #[test]
    fn a_token_is_revoked_and_recorded() {
        let (store, id) = holding_one();
        let audit = Arc::new(FakeEventDispatcher::new());

        revoke(
            &store,
            FakeTenantAuthorities::holding_everything(),
            id,
            &audit,
        )
        .unwrap();

        assert!(is_revoked(&store, &id));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["oauth.initial_access_token_revoked"]
        );
    }

    /// A caller without client-revocation rights cannot revoke an initial
    /// access token. It remains unrevoked and no event is recorded.
    #[test]
    fn a_caller_without_the_revoke_right_is_refused() {
        let (store, id) = holding_one();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = revoke(&store, FakeTenantAuthorities::holding(&[]), id, &audit);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!is_revoked(&store, &id));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a token the tenant does not have. It is not found.
    #[test]
    fn an_unknown_token_is_not_found() {
        let (store, _) = holding_one();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = revoke(
            &store,
            FakeTenantAuthorities::holding_everything(),
            InitialAccessTokenId::new(),
            &audit,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot revoke an initial access token.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = holding_one();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = revoke(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            id,
            &audit,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
