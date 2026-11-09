//! Turning a presented access token into the grant behind it.
//!
//! This is what makes an endpoint an OAuth-protected resource. Without it a
//! resource can only ask whether the bearer is signed in at all, which any
//! session or tenant API key answers: a different principal, carrying none
//! of the scopes the person gave this client.

use std::sync::Arc;

use ianua_domain::domains::oauth::grants::access_token::{AccessToken, TokenSubject};
use ianua_domain::domains::oauth::grants::token_binding::SenderBinding;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Issuer, OAuthClientId, Scope};

use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::oauth::OAuthClientStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::oauth::presented::{PresentedTokenPorts, presented_access_token};
use crate::use_cases::oauth::sender::{
    DpopHeader, SenderEvidence, SenderProofPorts, proven_holder,
};
use crate::use_cases::oauth::token::client_auth::Asking;

/// An access token as a resource receives it.
pub struct PresentedAccessToken {
    /// The raw token.
    pub token: Secret,
    /// What the request carried to prove its holder, for a bound token.
    pub sender: SenderEvidence,
    /// The tenant's issuer, which a JWT access token must carry.
    pub issuer: Issuer,
}

/// The grant a presented access token stands for.
pub struct ResolvedGrant {
    /// Whom it acts for: a person, or the client itself.
    pub subject: TokenSubject,
    /// The client it was issued to.
    pub client_id: OAuthClientId,
    /// The scopes it carries.
    pub scopes: Vec<Scope>,
    /// What it had to be presented with, which this request proved.
    pub binding: SenderBinding,
}

impl ResolvedGrant {
    /// Whether the grant covers `scope`.
    #[must_use]
    pub fn grants(&self, scope: &Scope) -> bool {
        self.scopes.contains(scope)
    }
}

/// The ports [`ResolveAccessTokenUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResolveAccessTokenPorts {
    /// Finds the token's record.
    pub presented: PresentedTokenPorts,
    /// Where clients are kept, to see the token's client is still active.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Where accounts are kept, to see the person may still sign in.
    pub user_store: Arc<dyn UserStore>,
    /// Checks what the request proves about its holder, for a bound token.
    pub sender: SenderProofPorts,
}

/// Resolves a presented access token.
pub struct ResolveAccessTokenUseCase {
    ports: ResolveAccessTokenPorts,
}

impl ResolveAccessTokenUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ResolveAccessTokenPorts) -> Self {
        Self { ports }
    }

    /// The kept token `presented` names, while it works with the proof the
    /// request made.
    async fn live_token(
        &self,
        tenant: &ScopedTenant,
        presented: &PresentedAccessToken,
    ) -> Result<AccessToken<ResolvedTenant>, AppError> {
        let asking = Asking {
            tenant,
            issuer: &presented.issuer,
        };
        let token = presented_access_token(&self.ports.presented, asking, &presented.token)
            .await?
            .ok_or(AppError::Unauthenticated)?;
        let proof = match presented.sender.dpop {
            DpopHeader::ProvenAtOpen => token.binding().proof_spent_at_opening(),
            DpopHeader::NotSent | DpopHeader::Sent(_) => {
                proven_holder(
                    &self.ports.sender,
                    tenant,
                    &presented.sender,
                    &presented.token,
                )
                .await?
            }
        };
        token
            .ensure_usable_with(&proof, clock::now())
            .map_err(|_| AppError::Unauthenticated)?;
        Ok(token)
    }

    /// Refuses a token whose client was revoked, or whose person may no
    /// longer sign in, since it was issued. Either ends the grant at once,
    /// not when the token would have run out.
    async fn ensure_grant_still_stands(
        &self,
        tenant: &ScopedTenant,
        token: &AccessToken<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let client_active = self
            .ports
            .client_store
            .find_by_id(tenant, token.client_id())
            .await
            .or_internal()?
            .is_some_and(|client| client.is_active());
        if !client_active || !self.person_may_sign_in(tenant, token).await? {
            return Err(AppError::Unauthenticated);
        }
        Ok(())
    }

    /// Whether the person `token` acts for may still sign in; a token for a
    /// machine acts for nobody.
    async fn person_may_sign_in(
        &self,
        tenant: &ScopedTenant,
        token: &AccessToken<ResolvedTenant>,
    ) -> Result<bool, AppError> {
        let TokenSubject::Person(person) = token.subject() else {
            return Ok(true);
        };
        let account = self
            .ports
            .user_store
            .find_by_id(tenant, &person)
            .await
            .or_internal()?;
        Ok(account.is_some_and(|user| user.can_authenticate()))
    }
}

impl Query for ResolveAccessTokenUseCase {
    type Caller = ScopedTenant;
    type Input = PresentedAccessToken;
    type Output = Result<ResolvedGrant, AppError>;

    /// The grant `presented` stands for in `tenant`.
    ///
    /// Deny by default: an unknown, expired or revoked token, one presented
    /// without the key or certificate it is bound to, and one whose client
    /// was revoked or whose person may no longer sign in, all look the same
    /// to the caller, and all fail.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the token, or the grant behind it,
    ///   no longer stands.
    /// - `AppError::Internal` when hashing or a lookup fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        presented: PresentedAccessToken,
    ) -> Result<ResolvedGrant, AppError> {
        let token = self.live_token(tenant, &presented).await?;
        self.ensure_grant_still_stands(tenant, &token).await?;
        Ok(ResolvedGrant {
            subject: token.subject(),
            client_id: *token.client_id(),
            scopes: token.scopes().to_vec(),
            binding: token.binding().clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
    use ianua_domain::domains::oauth::grants::access_token::AccessTokenRow;
    use ianua_domain::domains::oauth::grants::token_binding::{JwkThumbprint, SenderBinding};
    use ianua_domain::types::TokenId;
    use time::Duration;

    use super::*;
    use crate::ports::oauth::SignedDpopProof;
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::oauth::{
        FakeAccessTokenStore, FakeDpopVerifier, TEST_ACCESS_TOKEN, TEST_DPOP_URL, TokenEndpoint,
        access_row, client_with, dpop_sent, no_proof, stored_client, test_issuer,
    };
    use crate::test_support::{block_on, test_ctx};

    /// The reader app's token for Ann, kept, beside the reader and Ann.
    struct Fixture {
        endpoint: TokenEndpoint,
    }

    impl Fixture {
        /// The reader's token for Ann, as `edit` leaves its row.
        fn with_token(edit: impl FnOnce(&mut AccessTokenRow)) -> Self {
            let reader = stored_client("Reader", &[GrantType::AuthorizationCode]);
            let mut endpoint = TokenEndpoint::serving(reader);
            let mut row = access_row(&endpoint.client, TokenSubject::Person(endpoint.ann));
            edit(&mut row);
            let token = AccessToken::reconstitute(row).unwrap();
            endpoint.tokens = Arc::new(FakeAccessTokenStore::holding(&test_ctx().tenant(), token));
            Self { endpoint }
        }

        /// The reader's live token for Ann.
        fn live() -> Self {
            Self::with_token(|_| {})
        }

        /// What presenting the token with `sender`, checked through
        /// `checks`, resolves to, with `users` as the accounts.
        fn resolve_with(
            &self,
            (sender, checks): (SenderEvidence, SenderProofPorts),
            users: Arc<FakeUserStore>,
        ) -> Result<ResolvedGrant, AppError> {
            let use_case = ResolveAccessTokenUseCase::new(ResolveAccessTokenPorts {
                presented: self.endpoint.presented(),
                client_store: self.endpoint.clients.clone(),
                user_store: users,
                sender: checks,
            });
            let presented = PresentedAccessToken {
                token: Secret::new(TEST_ACCESS_TOKEN),
                sender,
                issuer: test_issuer(),
            };
            block_on(use_case.execute(&test_ctx().tenant(), presented))
        }

        /// What presenting the token, proving nothing, resolves to.
        fn resolve(&self) -> Result<ResolvedGrant, AppError> {
            self.resolve_with(proving_nothing(), self.endpoint.users.clone())
        }
    }

    /// A request carrying no `DPoP` header.
    fn proving_nothing() -> (SenderEvidence, SenderProofPorts) {
        (no_proof(), SenderProofPorts::fakes())
    }

    /// A request carrying a fresh `DPoP` proof made with the key `key`.
    fn proving(key: &JwkThumbprint) -> (SenderEvidence, SenderProofPorts) {
        let signed = SignedDpopProof {
            thumbprint: key.clone(),
            jti: TokenId::new("proof-1").unwrap(),
            method: "POST".to_owned(),
            url: TEST_DPOP_URL.to_owned(),
            issued_at: clock::now(),
        };
        let checks = SenderProofPorts {
            dpop_verifier: Arc::new(FakeDpopVerifier::accepting(signed)),
            ..SenderProofPorts::fakes()
        };
        (dpop_sent(), checks)
    }

    /// The thumbprint of the key Ann's reader app holds.
    fn anns_key() -> JwkThumbprint {
        JwkThumbprint::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I").unwrap()
    }

    /// The reader app presents a live token. It resolves to Ann's grant,
    /// which covers the scopes she gave and nothing else.
    #[test]
    fn a_live_token_resolves_to_its_grant() {
        let fixture = Fixture::live();

        let grant = fixture.resolve().unwrap();

        assert_eq!(grant.subject, TokenSubject::Person(fixture.endpoint.ann));
        assert!(grant.grants(&Scope::new("read").unwrap()));
        assert!(!grant.grants(&Scope::new("admin").unwrap()));
    }

    /// An access token absent from storage resolves as unauthenticated.
    #[test]
    fn an_unknown_token_is_refused() {
        let mut fixture = Fixture::live();
        fixture.endpoint.tokens = Arc::new(FakeAccessTokenStore::empty());

        assert!(matches!(fixture.resolve(), Err(AppError::Unauthenticated)));
    }

    /// An access token that expired an hour ago resolves as unauthenticated.
    #[test]
    fn an_expired_token_is_refused() {
        let fixture = Fixture::with_token(|row| {
            row.created_at = clock::now() - Duration::hours(2);
            row.expires_at = clock::now() - Duration::hours(1);
        });

        assert!(matches!(fixture.resolve(), Err(AppError::Unauthenticated)));
    }

    /// Revoking a stored access token makes its next resolution unauthenticated.
    #[test]
    fn a_revoked_token_is_refused() {
        let fixture = Fixture::live();
        fixture.endpoint.tokens.revoke_all();

        assert!(matches!(fixture.resolve(), Err(AppError::Unauthenticated)));
    }

    /// A DPoP-bound access token without a proof resolves as unauthenticated.
    #[test]
    fn a_bound_token_without_its_key_is_refused() {
        let fixture = Fixture::with_token(|row| row.binding = SenderBinding::DpopKey(anns_key()));

        assert!(matches!(fixture.resolve(), Err(AppError::Unauthenticated)));
    }

    /// Ann's reader app presents its bound token with a fresh proof made
    /// with its key. The token resolves.
    #[test]
    fn a_bound_token_with_its_key_resolves() {
        let fixture = Fixture::with_token(|row| row.binding = SenderBinding::DpopKey(anns_key()));

        let result = fixture.resolve_with(proving(&anns_key()), fixture.endpoint.users.clone());

        assert!(result.is_ok());
    }

    /// Ann's WebSocket opened with a proof of her key, spent then. The check
    /// of the open connection resolves the token still bound to that key.
    #[test]
    fn a_bound_token_resolves_on_a_connection_proven_when_it_opened() {
        let fixture = Fixture::with_token(|row| row.binding = SenderBinding::DpopKey(anns_key()));
        let spent = SenderEvidence {
            dpop: DpopHeader::ProvenAtOpen,
            ..no_proof()
        };

        let result = fixture.resolve_with(
            (spent, SenderProofPorts::fakes()),
            fixture.endpoint.users.clone(),
        );

        assert!(result.is_ok());
    }

    /// A verified proof made with another key cannot resolve Ann's DPoP-bound
    /// access token and returns unauthenticated.
    #[test]
    fn a_bound_token_with_another_key_is_refused() {
        let fixture = Fixture::with_token(|row| row.binding = SenderBinding::DpopKey(anns_key()));
        let mallorys = JwkThumbprint::new("m".repeat(43)).unwrap();

        let result = fixture.resolve_with(proving(&mallorys), fixture.endpoint.users.clone());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Revoking the reader client makes its existing access token resolve
    /// as unauthenticated.
    #[test]
    fn a_token_of_a_revoked_client_is_refused() {
        let fixture = Fixture::live();
        let reader_id = *fixture.endpoint.client.id();
        let revoked: OAuthClient<ResolvedTenant> =
            client_with("Reader", &[GrantType::AuthorizationCode], |row| {
                row.id = reader_id;
                row.status = OAuthClientStatus::Revoked;
            });
        block_on(
            fixture
                .endpoint
                .clients
                .save(&test_ctx().tenant(), &revoked),
        )
        .unwrap();

        assert!(matches!(fixture.resolve(), Err(AppError::Unauthenticated)));
    }

    /// A token for Ann resolves as unauthenticated when her stored account
    /// is deactivated.
    #[test]
    fn a_token_of_a_deactivated_person_is_refused() {
        let fixture = Fixture::live();
        let users = Arc::new(FakeUserStore::empty());
        users.add(stored_user(
            fixture.endpoint.ann,
            "ann@acme.example",
            UserStatus::Deactivated,
        ));

        let result = fixture.resolve_with(proving_nothing(), users);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
