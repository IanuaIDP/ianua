//! The claims the `userinfo` endpoint answers with (OIDC Core 5.3).
//!
//! An app sends the access token it was handed and learns about the person
//! it acts for what the token's scopes let out, as the ID token does:
//! `sub` always, the rest by scope. A token for a machine acts for nobody,
//! and one without `openid` was never for OpenID Connect, so neither gets
//! an answer.

use time::OffsetDateTime;

use crate::domains::identity::account::user::User;
use crate::domains::oauth::grants::access_token::{AccessToken, TokenSubject};
use crate::domains::oauth::grants::id_token::asks_for_id_token;
use crate::domains::oauth::grants::scoped_claims::ScopedClaims;
use crate::domains::oauth::grants::token_binding::PresentedProof;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{Label, UserId};

/// What `userinfo` answers with.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct UserInfoClaims {
    sub: UserId,
    #[cfg_attr(feature = "serde", serde(flatten))]
    scoped: ScopedClaims,
}

/// What the `userinfo` claims are built from.
pub struct UserInfoParams<'a, T: TenantScope> {
    /// The access token the app presented.
    pub token: &'a AccessToken<T>,
    /// What the request proved about its holder, for a bound token.
    pub proof: &'a PresentedProof,
    /// The account the token acts for, as it is now.
    pub account: &'a User<T>,
    /// The names of the roles the person holds, for the `roles` claim.
    pub roles: &'a [Label],
    /// The time now.
    pub now: OffsetDateTime,
}

impl UserInfoClaims {
    /// The claims for the person `params.token` acts for.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when the token is revoked or expired,
    ///   or lacks the proof it is bound to.
    /// - [`DomainError::Forbidden`] when the token acts for no person, does
    ///   not carry `openid`, or `params.account` is not the person it acts
    ///   for.
    pub fn build<T: TenantScope>(params: &UserInfoParams<'_, T>) -> Result<Self, DomainError> {
        let token = params.token;
        token.ensure_usable_with(params.proof, params.now)?;
        let TokenSubject::Person(person) = token.subject() else {
            return Err(DomainError::forbidden(message!(
                "oauth-a-token-for-a-machine-acts",
                "a token for a machine acts for no person to describe"
            )));
        };
        if !asks_for_id_token(token.scopes()) {
            return Err(DomainError::forbidden(message!(
                "oauth-userinfo-answers-only-a-token-with",
                "userinfo answers only a token with the openid scope"
            )));
        }
        if person != *params.account.id() {
            return Err(DomainError::forbidden(message!(
                "oauth-the-account-is-not-the-one",
                "the account is not the one the token acts for"
            )));
        }
        Ok(Self {
            sub: person,
            scoped: ScopedClaims::for_scopes(token.scopes(), params.account, params.roles),
        })
    }

    /// The subject, `sub`: the person's id, as in their ID token.
    #[must_use]
    pub fn sub(&self) -> UserId {
        self.sub
    }

    /// What the token's scopes let out about the person.
    #[must_use]
    pub fn scoped(&self) -> &ScopedClaims {
        &self.scoped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::domains::oauth::clients::client::{GrantType, NewOAuthClient, OAuthClient};
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::domains::oauth::grants::access_token::{IssueAccessTokenParams, TokenIssue};
    use crate::domains::oauth::grants::token_binding::{JwkThumbprint, SenderBinding};
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::{label, user};
    use crate::types::{ClientId, Email, Lifetime, OAuthClientId, RedirectUri, Scope, TokenHash};

    /// Ann, who proved her address.
    fn ann() -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), "ann@acme.com");
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// A token acting for `account`, carrying `scopes`, bound as `binding`.
    fn token_for(
        account: &User<ResolvedTenant>,
        scopes: &[&str],
        binding: SenderBinding,
    ) -> AccessToken<ResolvedTenant> {
        AccessToken::issue(IssueAccessTokenParams {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            client_id: OAuthClientId::new(),
            user_id: *account.id(),
            scopes: scopes
                .iter()
                .map(|name| Scope::new(*name).unwrap())
                .collect(),
            lifetime: Lifetime::seconds(3600).unwrap(),
            binding,
        })
    }

    /// The claims for `account` from `token`, proving nothing.
    fn claims(
        token: &AccessToken<ResolvedTenant>,
        account: &User<ResolvedTenant>,
    ) -> Result<UserInfoClaims, DomainError> {
        UserInfoClaims::build(&UserInfoParams {
            token,
            proof: &PresentedProof::nothing(),
            account,
            roles: &[label("Editor")],
            now: crate::shared::clock::now(),
        })
    }

    /// An app holding Ann's token for `openid` and `email` learns who she
    /// is and her proven address, and nothing about her name or roles.
    #[test]
    fn userinfo_answers_by_the_tokens_scopes() {
        let ann = ann();
        let token = token_for(&ann, &["openid", "email"], SenderBinding::Bearer);

        let claims = claims(&token, &ann).unwrap();

        assert_eq!(claims.sub(), *ann.id());
        assert_eq!(
            claims.scoped().email().map(Email::as_str),
            Some("ann@acme.com")
        );
        assert_eq!(claims.scoped().email_verified(), Some(true));
        assert_eq!(claims.scoped().name(), None);
        assert_eq!(claims.scoped().roles(), None);
    }

    /// Ann's email-scoped token cannot obtain user information without the
    /// `openid` scope. Building the claims is forbidden.
    #[test]
    fn a_token_without_openid_gets_no_answer() {
        let ann = ann();
        let token = token_for(&ann, &["email"], SenderBinding::Bearer);

        assert!(matches!(
            claims(&token, &ann),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Revoking Ann's token makes a later user-information request
    /// unauthorized.
    #[test]
    fn a_revoked_token_gets_no_answer() {
        let ann = ann();
        let mut token = token_for(&ann, &["openid"], SenderBinding::Bearer);
        token.revoke();

        assert!(matches!(
            claims(&token, &ann),
            Err(DomainError::Unauthorized(_))
        ));
    }

    /// A DPoP-bound token cannot obtain user information without proof of
    /// its key. Building the claims is unauthorized.
    #[test]
    fn a_bound_token_without_its_proof_gets_no_answer() {
        let ann = ann();
        let key = JwkThumbprint::new("a".repeat(43)).unwrap();
        let token = token_for(&ann, &["openid"], SenderBinding::DpopKey(key));

        assert!(matches!(
            claims(&token, &ann),
            Err(DomainError::Unauthorized(_))
        ));
    }

    /// Supplying a different account from the person named by the token
    /// makes building user-information claims forbidden.
    #[test]
    fn the_account_must_be_the_tokens_person() {
        let token = token_for(&ann(), &["openid", "email"], SenderBinding::Bearer);

        assert!(matches!(
            claims(&token, &ann()),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A machine's client-credentials token cannot obtain user information,
    /// even with the `openid` scope. Building the claims is forbidden.
    #[test]
    fn a_machine_token_gets_no_answer() {
        let machine = OAuthClient::<ResolvedTenant>::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("robot").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored("s".to_owned())),
                name: label("Robot"),
                redirect_uris: vec![RedirectUri::new("https://robot.example/cb").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::ClientCredentials],
                scopes: vec![Scope::new("openid").unwrap()],
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap();
        let token = AccessToken::<ResolvedTenant>::for_client(
            TokenIssue {
                token_hash: TokenHash::from_stored("m".to_owned()),
                lifetime: Lifetime::seconds(300).unwrap(),
                binding: SenderBinding::Bearer,
            },
            &machine,
            vec![Scope::new("openid").unwrap()],
        )
        .unwrap();

        assert!(matches!(
            claims(&token, &ann()),
            Err(DomainError::Forbidden(_))
        ));
    }
}
