//! Token exchange at the token endpoint (RFC 8693): a service swaps a
//! token it was handed for a narrower one meant for another client of the
//! tenant, naming itself, or an actor, as acting for the token's subject.
//!
//! Nothing is widened: the new token carries the subject token's scopes or
//! fewer, and only a confidential client the admins allowed to exchange
//! may ask.

use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
use ianua_domain::domains::oauth::clients::lifetimes::TokenTerms;
use ianua_domain::domains::oauth::grants::access_token::{AccessToken, TokenIssue, TokenSubject};
use ianua_domain::domains::oauth::grants::jwt_access_token::SignInFacts;
use ianua_domain::domains::oauth::grants::token_exchange::{
    ExchangeActor, ExchangeRequest, ExchangeScopes, TokenExchange,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, ClientId, Issuer, Lifetime};

use crate::auditor::RequestAuditor;
use crate::error::OrInternal;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::presented::{PresentedTokenPorts, presented_access_token};
use crate::use_cases::oauth::sender::SenderEvidence;
use crate::use_cases::oauth::token::client_auth::{
    Asking, ClientAuthPorts, ClientProof, authenticated_client,
};
use crate::use_cases::oauth::token::issuing::{
    HandedToken, Issued, IssuedTokens, IssuingPorts, Minting, TokenType, ensure_may_use,
    fresh_access_value, kept_access, proven_binding, terms_for,
};
use crate::use_cases::oauth::token::refusal::{OAuthErrorCode, TokenError};

/// The actor token an exchange carries, if any.
pub enum ActorSent {
    /// None: the new token acts for the subject alone.
    NotSent,
    /// This raw access token, naming who acts.
    Sent(Secret),
}

/// What a service presents to exchange a token.
pub struct ExchangeGrant {
    /// How the client proves itself.
    pub client: ClientProof,
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// What the request carried to prove its holder.
    pub sender: SenderEvidence,
    /// The raw access token it exchanges (`subject_token`).
    pub subject_token: Secret,
    /// Who acts (`actor_token`).
    pub actor_token: ActorSent,
    /// The client the new token is for (`audience`).
    pub audience: ClientId,
    /// The scopes the new token carries.
    pub scopes: ExchangeScopes,
}

/// The ports [`ExchangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExchangePorts {
    /// How the client proves itself.
    pub client_auth: ClientAuthPorts,
    /// How the new token is made and kept.
    pub issuing: IssuingPorts,
    /// Finds the subject and actor tokens' records.
    pub presented: PresentedTokenPorts,
}

/// Exchanges a token for a narrower one for another client's audience.
pub struct ExchangeUseCase {
    platform: TokenTerms,
    ports: ExchangePorts,
}

/// The tokens an exchange brings, found.
struct Brought {
    subject: AccessToken<ResolvedTenant>,
    actor: Option<AccessToken<ResolvedTenant>>,
    audience: OAuthClient<ResolvedTenant>,
}

impl ExchangeUseCase {
    /// A use case issuing tokens on the platform's `platform` terms, unless
    /// a client has its own, working through `ports`.
    #[must_use]
    pub fn new(platform: TokenTerms, ports: ExchangePorts) -> Self {
        Self { platform, ports }
    }

    /// The record of the access token `raw`, or `missing` when there is
    /// none.
    async fn found_token(
        &self,
        asking: Asking<'_>,
        raw: &Secret,
        missing: TokenError,
    ) -> Result<AccessToken<ResolvedTenant>, TokenError> {
        presented_access_token(&self.ports.presented, asking, raw)
            .await?
            .ok_or(missing)
    }

    /// The subject token, actor token and audience `grant` names.
    async fn brought(
        &self,
        asking: Asking<'_>,
        grant: &ExchangeGrant,
    ) -> Result<Brought, TokenError> {
        let subject = self
            .found_token(asking, &grant.subject_token, refused_subject())
            .await?;
        let actor = match &grant.actor_token {
            ActorSent::NotSent => None,
            ActorSent::Sent(raw) => Some(self.found_token(asking, raw, refused_actor()).await?),
        };
        let audience = self
            .ports
            .client_auth
            .client_store
            .find_by_client_id_value(asking.tenant, &grant.audience)
            .await
            .or_internal()?
            .ok_or_else(|| {
                TokenError::refused(
                    OAuthErrorCode::InvalidTarget,
                    "the audience is not a client of this tenant",
                )
            })?;
        Ok(Brought {
            subject,
            actor,
            audience,
        })
    }

    /// The new token `exchange` allows, bound as `grant` proved, with its
    /// raw value.
    async fn issued(
        &self,
        minting: Minting<'_>,
        audience: &OAuthClient<ResolvedTenant>,
        exchange: &TokenExchange,
        grant: &ExchangeGrant,
    ) -> Result<(AccessToken<ResolvedTenant>, Secret), TokenError> {
        let issuing = &self.ports.issuing;
        let (binding, _) =
            proven_binding(issuing, minting.tenant, minting.client, &grant.sender).await?;
        let (value, token_hash) = fresh_access_value(issuing, minting.client).await?;
        let issue = TokenIssue {
            token_hash,
            lifetime: terms_for(minting.client, self.platform).access(),
            binding,
        };
        let token = AccessToken::exchanged(issue, exchange);
        let handed = Issued {
            token: &token,
            value,
            audience,
            sign_in: SignInFacts::NotStated,
        };
        let raw = kept_access(issuing, minting, handed).await?;
        Ok((token, raw))
    }
}

impl Command for ExchangeUseCase {
    type Caller = ScopedTenant;
    type Input = ExchangeGrant;
    type Output = Result<IssuedTokens, TokenError>;

    /// Exchanges the subject token `grant` presents in `tenant` for a new
    /// access token meant for the audience it names. Records
    /// `oauth.access_token_issued` and `oauth.token_exchanged`, with the
    /// subject as actor: the person, or the client a machine token acts as.
    ///
    /// # Errors
    ///
    /// - `invalid_client` for failed authentication; `unauthorized_client` for a public client or one barred from exchange.
    /// - `invalid_grant` for an unusable/foreign subject token; `invalid_request` for an unusable actor token.
    /// - `invalid_target` for an audience not naming an active client; `invalid_scope` for rights beyond the subject token.
    /// - `TokenError::Failed` on lookup, signing, save or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        grant: ExchangeGrant,
    ) -> Result<IssuedTokens, TokenError> {
        let asking = Asking {
            tenant,
            issuer: &grant.issuer,
        };
        let client = authenticated_client(&self.ports.client_auth, asking, &grant.client).await?;
        ensure_may_use(&client, GrantType::TokenExchange)?;
        let brought = self.brought(asking, &grant).await?;
        let exchange = decided(&client, &brought, grant.scopes.clone())?;
        let minting = Minting {
            tenant,
            issuer: &grant.issuer,
            client: &client,
        };
        let (mut token, access_token) = self
            .issued(minting, &brought.audience, &exchange, &grant)
            .await?;
        auditor
            .dispatch_by(&subject_actor(&brought.subject), token.take_events(tenant))
            .await
            .or_internal()?;
        let expires_in = terms_for(&client, self.platform).access();
        Ok(exchanged_tokens(&token, access_token, expires_in))
    }
}

/// The exchange `client` may make with what `brought` holds, for `scopes`.
///
/// # Errors
///
/// The refusal [`TokenExchange::decide`] gives: `unauthorized_client`,
/// `invalid_grant`, `invalid_target` or `invalid_scope`.
fn decided(
    client: &OAuthClient<ResolvedTenant>,
    brought: &Brought,
    scopes: ExchangeScopes,
) -> Result<TokenExchange, TokenError> {
    let request = ExchangeRequest {
        client,
        subject_token: &brought.subject,
        actor: brought
            .actor
            .as_ref()
            .map_or(ExchangeActor::NotNamed, ExchangeActor::Token),
        audience: &brought.audience,
        now: clock::now(),
    };
    Ok(TokenExchange::decide(&request, scopes)?)
}

/// What the exchange hands the client: `token` as `access_token`, good for
/// `expires_in`, with no refresh or ID token.
fn exchanged_tokens(
    token: &AccessToken<ResolvedTenant>,
    access_token: Secret,
    expires_in: Lifetime,
) -> IssuedTokens {
    IssuedTokens {
        token_type: TokenType::of(token.binding()),
        access_token,
        expires_in,
        scopes: token.scopes().to_vec(),
        refresh_token: HandedToken::NotIssued,
        id_token: HandedToken::NotIssued,
    }
}

/// Who the exchanged token acts for, as the record's actor.
fn subject_actor(subject: &AccessToken<ResolvedTenant>) -> ActorRef {
    match subject.subject() {
        TokenSubject::Person(person) => ActorRef::User(person),
        TokenSubject::Client => ActorRef::OAuthClient(*subject.client_id()),
    }
}

/// The refusal for a subject token nothing is behind.
fn refused_subject() -> TokenError {
    TokenError::refused(
        OAuthErrorCode::InvalidGrant,
        "the subject token is not one this tenant issued",
    )
}

/// The refusal for an actor token nothing is behind.
fn refused_actor() -> TokenError {
    TokenError::refused(
        OAuthErrorCode::InvalidRequest,
        "the actor token is not one this tenant issued",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::oauth::grants::access_token::AccessAudience;
    use ianua_domain::types::Scope;

    use super::*;
    use crate::ports::oauth::OAuthClientStore as _;
    use crate::test_support::oauth::{
        FakeAccessTokenStore, TEST_ACCESS_TOKEN, TokenEndpoint, access_token, basic_proof,
        no_proof, refused_with, stored_client, test_issuer, test_terms,
    };
    use crate::test_support::{block_on, test_auditor, test_ctx};

    /// The orders service, which may exchange, holding Ann's token, beside
    /// the billing API it calls.
    struct Fixture {
        endpoint: TokenEndpoint,
        billing: OAuthClient<ResolvedTenant>,
    }

    impl Fixture {
        /// The orders service holding Ann's token, beside billing.
        fn new() -> Self {
            let orders = stored_client("Orders", &[GrantType::TokenExchange]);
            let mut endpoint = TokenEndpoint::serving(orders);
            let billing = stored_client("Billing API", &[GrantType::ClientCredentials]);
            block_on(endpoint.clients.save(&test_ctx().tenant(), &billing)).unwrap();
            let held = access_token(&endpoint.client, TokenSubject::Person(endpoint.ann));
            endpoint.tokens = Arc::new(FakeAccessTokenStore::holding(&test_ctx().tenant(), held));
            Self { endpoint, billing }
        }

        /// The orders service exchanging Ann's token for billing, with
        /// its scopes.
        fn grant(&self) -> ExchangeGrant {
            ExchangeGrant {
                client: basic_proof(&self.endpoint.client),
                issuer: test_issuer(),
                sender: no_proof(),
                subject_token: Secret::new(TEST_ACCESS_TOKEN.to_owned()),
                actor_token: ActorSent::NotSent,
                audience: self.billing.client_id_value().clone(),
                scopes: ExchangeScopes::AsSubject,
            }
        }

        /// What exchanging as `grant` says answers.
        fn exchange(&self, grant: ExchangeGrant) -> Result<IssuedTokens, TokenError> {
            let use_case = ExchangeUseCase::new(
                test_terms(),
                ExchangePorts {
                    client_auth: self.endpoint.client_auth(),
                    issuing: self.endpoint.issuing(),
                    presented: self.endpoint.presented(),
                },
            );
            let auditor = test_auditor(self.endpoint.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, grant))
        }

        /// The token kept last: the exchanged one.
        fn exchanged(&self) -> AccessToken<ResolvedTenant> {
            self.endpoint.tokens.all().pop().unwrap()
        }
    }

    /// The orders service exchanges Ann's token for one meant for the
    /// billing API. The new token acts for Ann, is meant for billing, and
    /// the exchange is recorded with Ann as actor.
    #[test]
    fn a_token_is_exchanged_for_another_audience() {
        let fixture = Fixture::new();

        fixture.exchange(fixture.grant()).unwrap();

        let token = fixture.exchanged();
        assert_eq!(token.subject(), TokenSubject::Person(fixture.endpoint.ann));
        assert_eq!(
            token.audience(),
            AccessAudience::Client(*fixture.billing.id())
        );
        assert_eq!(
            fixture.endpoint.recorded(),
            ["oauth.access_token_issued", "oauth.token_exchanged"]
        );
    }

    /// The orders service asks for `read` alone. The new token carries
    /// only that.
    #[test]
    fn an_exchange_may_narrow_the_scopes() {
        let fixture = Fixture::new();

        let tokens = fixture
            .exchange(ExchangeGrant {
                scopes: ExchangeScopes::Narrowed(vec![Scope::new("read").unwrap()]),
                ..fixture.grant()
            })
            .unwrap();

        assert_eq!(tokens.scopes, [Scope::new("read").unwrap()]);
    }

    /// Exchanging a token for `write` when it grants only `openid` and `read`
    /// returns invalid scope. Only the original token remains stored.
    #[test]
    fn an_exchange_cannot_widen_the_scopes() {
        let fixture = Fixture::new();

        let result = fixture.exchange(ExchangeGrant {
            scopes: ExchangeScopes::Narrowed(vec![Scope::new("write").unwrap()]),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidScope));
        assert_eq!(fixture.endpoint.tokens.count(), 1);
    }

    /// An unknown subject token receives invalid grant during exchange.
    #[test]
    fn an_unknown_subject_token_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.exchange(ExchangeGrant {
            subject_token: Secret::new("never-issued"),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
    }

    /// A revoked subject token receives invalid grant during exchange.
    #[test]
    fn a_revoked_subject_token_is_refused() {
        let fixture = Fixture::new();
        fixture.endpoint.tokens.revoke_all();

        let result = fixture.exchange(fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
    }

    /// An exchange naming an unknown audience client receives invalid target.
    #[test]
    fn an_unknown_audience_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.exchange(ExchangeGrant {
            audience: ClientId::new("client_unknown").unwrap(),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidTarget));
    }

    /// A client registered only for client credentials is unauthorized to
    /// exchange tokens.
    #[test]
    fn a_client_without_exchange_is_unauthorized() {
        let fixture = Fixture::new();

        let result = fixture.exchange(ExchangeGrant {
            client: basic_proof(&fixture.billing),
            ..fixture.grant()
        });

        assert_eq!(
            refused_with(&result),
            Some(OAuthErrorCode::UnauthorizedClient)
        );
    }

    /// An exchange-capable client presenting another client's subject token
    /// receives invalid grant.
    #[test]
    fn a_token_handed_to_another_client_is_refused() {
        let fixture = Fixture::new();
        let other = stored_client("Reports", &[GrantType::TokenExchange]);
        block_on(fixture.endpoint.clients.save(&test_ctx().tenant(), &other)).unwrap();

        let result = fixture.exchange(ExchangeGrant {
            client: basic_proof(&other),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
    }
}
