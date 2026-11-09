//! The `userinfo` endpoint (OIDC Core 5.3): an app sends the access token
//! it was handed and learns about the person it acts for what the token's
//! scopes let out, as the ID token does.

use std::sync::Arc;

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::oauth::grants::access_token::{AccessToken, TokenSubject};
use ianua_domain::domains::oauth::grants::userinfo::{UserInfoClaims, UserInfoParams};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::RoleStore;
use crate::ports::identity::UserStore;
use crate::ports::oauth::OAuthClientStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::oauth::flows::PresentedAccessToken;
use crate::use_cases::oauth::presented::{PresentedTokenPorts, presented_access_token};
use crate::use_cases::oauth::sender::{SenderProofPorts, proven_holder};
use crate::use_cases::oauth::token::client_auth::Asking;
use crate::use_cases::oauth::token::issuing::role_names;

/// The ports [`UserInfoUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UserInfoPorts {
    /// Finds the token's record.
    pub presented: PresentedTokenPorts,
    /// Where clients are kept, to see the token's client is still active.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Where the account the token acts for is kept.
    pub users: Arc<dyn UserStore>,
    /// Where roles are kept, for the `roles` claim.
    pub roles: Arc<dyn RoleStore>,
    /// Checks what the request proves about its holder, for a bound token.
    pub sender: SenderProofPorts,
}

/// Answers `userinfo`.
pub struct UserInfoUseCase {
    ports: UserInfoPorts,
}

impl UserInfoUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: UserInfoPorts) -> Self {
        Self { ports }
    }

    /// The kept token `presented` names, while its client is active.
    async fn standing_token(
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
        let client_active = self
            .ports
            .client_store
            .find_by_id(tenant, token.client_id())
            .await
            .or_internal()?
            .is_some_and(|client| client.is_active());
        if !client_active {
            return Err(AppError::Unauthenticated);
        }
        Ok(token)
    }

    /// The account `token` acts for, while it may sign in.
    async fn described_account(
        &self,
        tenant: &ScopedTenant,
        token: &AccessToken<ResolvedTenant>,
    ) -> Result<User<ResolvedTenant>, AppError> {
        let TokenSubject::Person(person) = token.subject() else {
            return Err(AppError::Forbidden(message!(
                "oauth-a-token-for-a-machine-acts",
                "a token for a machine acts for no person to describe"
            )));
        };
        self.ports
            .users
            .find_by_id(tenant, &person)
            .await
            .or_internal()?
            .filter(User::can_authenticate)
            .ok_or(AppError::Unauthenticated)
    }
}

impl Query for UserInfoUseCase {
    type Caller = ScopedTenant;
    type Input = PresentedAccessToken;
    type Output = Result<UserInfoClaims, AppError>;

    /// The claims about the person `presented` acts for in `tenant`: `sub`
    /// always, the rest as its scopes let out.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the token is unknown, expired,
    ///   revoked, presented without what it is bound to or with a `DPoP`
    ///   proof that does not check out, its client was revoked, or its
    ///   person may no longer sign in: the API answers `invalid_token`.
    /// - `AppError::Forbidden` when the token acts for a machine or lacks
    ///   `openid`: the API answers `insufficient_scope`.
    /// - `AppError::Internal` when a lookup fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        presented: PresentedAccessToken,
    ) -> Result<UserInfoClaims, AppError> {
        let token = self.standing_token(tenant, &presented).await?;
        let proof = proven_holder(
            &self.ports.sender,
            tenant,
            &presented.sender,
            &presented.token,
        )
        .await?;
        let account = self.described_account(tenant, &token).await?;
        let roles = role_names(self.ports.roles.as_ref(), tenant, account.id()).await?;
        UserInfoClaims::build(&UserInfoParams {
            token: &token,
            proof: &proof,
            account: &account,
            roles: &roles,
            now: clock::now(),
        })
        .map_err(refused_claims)
    }
}

/// The error a refused `userinfo` answer gives: a token that does not work
/// is unauthenticated, one that works but may not see this is forbidden.
fn refused_claims(refusal: DomainError) -> AppError {
    match refusal {
        DomainError::Unauthorized(_) => AppError::Unauthenticated,
        other => AppError::from_domain(other),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::grants::access_token::AccessTokenRow;
    use ianua_domain::domains::oauth::grants::token_binding::{JwkThumbprint, SenderBinding};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::Scope;

    use super::*;
    use crate::test_support::oauth::{
        FakeAccessTokenStore, TEST_ACCESS_TOKEN, TokenEndpoint, access_row, dpop_sent, no_proof,
        stored_client, test_issuer,
    };
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::oauth::sender::SenderEvidence;

    /// The portal's token, as `edit` leaves its row, presented to
    /// `userinfo` with no `DPoP` header.
    fn userinfo(
        subject: impl FnOnce(&TokenEndpoint) -> TokenSubject,
        edit: impl FnOnce(&mut AccessTokenRow),
    ) -> (TokenEndpoint, Result<UserInfoClaims, AppError>) {
        userinfo_sent(subject, edit, no_proof())
    }

    /// The portal's token, as `edit` leaves its row, presented to
    /// `userinfo` with `sender`, whose proof never checks out.
    fn userinfo_sent(
        subject: impl FnOnce(&TokenEndpoint) -> TokenSubject,
        edit: impl FnOnce(&mut AccessTokenRow),
        sender: SenderEvidence,
    ) -> (TokenEndpoint, Result<UserInfoClaims, AppError>) {
        let portal = stored_client("Portal", &[GrantType::AuthorizationCode]);
        let mut endpoint = TokenEndpoint::serving(portal);
        let mut row = access_row(&endpoint.client, subject(&endpoint));
        edit(&mut row);
        let token = AccessToken::reconstitute(row).unwrap();
        endpoint.tokens = Arc::new(FakeAccessTokenStore::holding(&test_ctx().tenant(), token));
        let use_case = UserInfoUseCase::new(UserInfoPorts {
            presented: endpoint.presented(),
            client_store: endpoint.clients.clone(),
            users: endpoint.users.clone(),
            ..UserInfoPorts::fakes()
        });
        let presented = PresentedAccessToken {
            token: Secret::new(TEST_ACCESS_TOKEN),
            sender,
            issuer: test_issuer(),
        };
        let answer = block_on(use_case.execute(&test_ctx().tenant(), presented));
        (endpoint, answer)
    }

    /// Ann's portal token, as issued.
    fn anns(endpoint: &TokenEndpoint) -> TokenSubject {
        TokenSubject::Person(endpoint.ann)
    }

    /// The portal asks about Ann with her `openid` token. It learns who she
    /// is, and no address, since the token carries no `email` scope.
    #[test]
    fn userinfo_names_the_person_and_only_what_the_scopes_let_out() {
        let (endpoint, answer) = userinfo(anns, |_| {});

        let claims = answer.unwrap();
        assert_eq!(claims.sub(), endpoint.ann);
        assert!(claims.scoped().email().is_none());
    }

    /// The portal's token carries `email` too. It learns Ann's address.
    #[test]
    fn the_email_scope_lets_out_the_address() {
        let (_, answer) = userinfo(anns, |row| row.scopes.push(Scope::new("email").unwrap()));

        assert!(answer.unwrap().scoped().email().is_some());
    }

    /// Userinfo refuses a person's token whose scopes omit openid.
    #[test]
    fn a_token_without_openid_is_forbidden() {
        let (_, answer) = userinfo(anns, |row| row.scopes = vec![Scope::new("read").unwrap()]);

        assert!(matches!(answer, Err(AppError::Forbidden(_))));
    }

    /// Userinfo refuses a client token because it has no person to describe.
    #[test]
    fn a_machine_token_is_forbidden() {
        let (_, answer) = userinfo(|_| TokenSubject::Client, |_| {});

        assert!(matches!(answer, Err(AppError::Forbidden(_))));
    }

    /// Userinfo returns unauthenticated for a token that expired an hour ago.
    #[test]
    fn an_expired_token_is_refused() {
        let (_, answer) = userinfo(anns, |row| {
            row.created_at = clock::now() - time::Duration::hours(2);
            row.expires_at = clock::now() - time::Duration::hours(1);
        });

        assert!(matches!(answer, Err(AppError::Unauthenticated)));
    }

    /// A token bound to the `DPoP` key of `fill` repeated.
    fn bound_to(fill: char) -> impl FnOnce(&mut AccessTokenRow) {
        let key = JwkThumbprint::new(fill.to_string().repeat(43)).unwrap();
        move |row| row.binding = SenderBinding::DpopKey(key)
    }

    /// A DPoP-bound token presented without a proof is unauthenticated at userinfo.
    #[test]
    fn a_bound_token_without_a_proof_is_refused() {
        let (_, answer) = userinfo(anns, bound_to('a'));

        assert!(matches!(answer, Err(AppError::Unauthenticated)));
    }

    /// A DPoP-bound token whose accompanying proof fails verification is
    /// unauthenticated at userinfo.
    #[test]
    fn a_proof_that_does_not_verify_is_refused() {
        let (_, answer) = userinfo_sent(anns, bound_to('a'), dpop_sent());

        assert!(matches!(answer, Err(AppError::Unauthenticated)));
    }
}
