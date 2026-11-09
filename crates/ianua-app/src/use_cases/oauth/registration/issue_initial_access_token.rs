//! Issuing an initial access token, with which apps may register
//! themselves as clients: a set number of times, until it expires. The raw
//! token is shown once.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::registration::{
    InitialAccessToken, NewInitialAccessToken,
};
use ianua_domain::domains::oauth::control::OAuthControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{InitialAccessTokenId, Label, Lifetime};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::{CodeHasher, InitialAccessTokenStore};
use crate::use_case::Command;

/// The registration allowance, label and lifetime for a new bootstrap credential.
pub struct IssueInitialAccessTokenRequest {
    /// What it is for, such as `"MCP clients"`.
    pub name: Label,
    /// How many apps may register with it, from 1 to 1000.
    pub uses: u32,
    /// How long it works, at most thirty days.
    pub lifetime: Lifetime,
}

/// A token just issued.
pub struct IssuedInitialAccessToken {
    /// The stored credential identifier used to revoke further registrations.
    pub id: InitialAccessTokenId,
    /// The raw token, shown once and never stored.
    pub token: Secret,
    /// When it stops working.
    pub expires_at: OffsetDateTime,
}

/// The ports [`IssueInitialAccessTokenUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct IssueInitialAccessTokenPorts {
    /// Where initial access tokens are kept.
    pub token_store: Arc<dyn InitialAccessTokenStore>,
    /// Makes the raw token and its hash.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Creates a bounded credential that permits dynamic client registration.
pub struct IssueInitialAccessTokenUseCase {
    ports: IssueInitialAccessTokenPorts,
}

impl IssueInitialAccessTokenUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: IssueInitialAccessTokenPorts) -> Self {
        Self { ports }
    }
}

impl Command for IssueInitialAccessTokenUseCase {
    type Caller = CallerContext;
    type Input = IssueInitialAccessTokenRequest;
    type Output = Result<IssuedInitialAccessToken, AppError>;

    /// Issues the token `req` describes in `caller`'s tenant and records
    /// `oauth.initial_access_token_issued`. The raw token comes back once.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not create clients.
    /// - `AppError::Domain` when it allows no use or more than a thousand,
    ///   or lives longer than thirty days.
    /// - `AppError::Internal` when the token cannot be made, saved or
    ///   audited.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: IssueInitialAccessTokenRequest,
    ) -> Result<IssuedInitialAccessToken, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let (raw, token_hash) = self.ports.code_hasher.generate_code().await.or_internal()?;
        let new = NewInitialAccessToken {
            id: InitialAccessTokenId::new(),
            name: req.name,
            token_hash,
            uses: req.uses,
            lifetime: req.lifetime,
        };
        let mut token = InitialAccessToken::issue(new, &OAuthControl::new(&authority))
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        self.ports
            .token_store
            .save(&tenant, &token)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), token.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(IssuedInitialAccessToken {
            id: *token.id(),
            token: raw,
            expires_at: token.expires_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeInitialAccessTokenStore, hash_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A token for ten MCP clients, for a week.
    fn for_mcp(uses: u32) -> IssueInitialAccessTokenRequest {
        IssueInitialAccessTokenRequest {
            name: Label::new("name", "MCP clients").unwrap(),
            uses,
            lifetime: Lifetime::seconds(7 * 86_400).unwrap(),
        }
    }

    /// What issuing `req`, as `authorities` allow, answers, with the store
    /// and the records.
    fn issue(
        authorities: FakeTenantAuthorities,
        req: IssueInitialAccessTokenRequest,
    ) -> (
        Result<IssuedInitialAccessToken, AppError>,
        Arc<FakeInitialAccessTokenStore>,
        Arc<FakeEventDispatcher>,
    ) {
        let store = Arc::new(FakeInitialAccessTokenStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = IssueInitialAccessTokenUseCase::new(IssueInitialAccessTokenPorts {
            token_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
            ..IssueInitialAccessTokenPorts::fakes()
        });
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), req));
        (result, store, audit)
    }

    /// Ann issues a token for ten MCP clients. She is shown it once; only
    /// its hash is kept, and the issue is recorded.
    #[test]
    fn a_token_is_issued_and_kept_hashed() {
        let (result, store, audit) =
            issue(FakeTenantAuthorities::holding_everything(), for_mcp(10));

        let issued = result.unwrap();
        let kept =
            block_on(store.find_by_hash(&test_ctx().tenant(), &hash_of(issued.token.expose())))
                .unwrap()
                .unwrap();
        assert_eq!(kept.uses_left(), 10);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["oauth.initial_access_token_issued"]
        );
    }

    /// A token allowing a million registrations is refused. No token is stored.
    #[test]
    fn too_many_uses_are_refused() {
        let (result, store, _) = issue(
            FakeTenantAuthorities::holding_everything(),
            for_mcp(1_000_000),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// A caller without client-creation rights cannot issue an initial access
    /// token. No token is stored.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let (result, store, _) = issue(FakeTenantAuthorities::holding(&[]), for_mcp(10));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// A signed-out session cannot issue an initial access token.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (result, _, _) = issue(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            for_mcp(10),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
