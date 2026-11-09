//! Token exchange (RFC 8693): a client swapping a token it was handed for a
//! new one, meant for another client of the tenant.
//!
//! The orders service holds Ann's token and must call the billing API for
//! her. It exchanges her token for one whose audience is the billing API,
//! with no more scopes than hers and itself named as the actor (`act`), so
//! the billing API knows who acts for whom. Nothing is widened: Mallory's
//! service, holding a token with `orders:read`, cannot come back with
//! `billing:write`.

use time::OffsetDateTime;

use crate::domains::oauth::clients::client::{GrantType, OAuthClient};
use crate::domains::oauth::grants::access_token::{
    AccessAudience, AccessToken, ActingParty, TokenSubject,
};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::{EventLabel, OAuthClientId, Scope};

/// Who acts, when a client exchanges a token on someone's behalf.
#[derive(Debug)]
pub enum ExchangeActor<'a, T: TenantScope> {
    /// No actor token: the new token acts for the subject alone, as an
    /// impersonation (RFC 8693 1.1).
    NotNamed,
    /// The party this token names acts for the subject, a delegation.
    Token(&'a AccessToken<T>),
}

/// The scopes an exchange asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeScopes {
    /// The subject token's own.
    AsSubject,
    /// Fewer: only these.
    Narrowed(Vec<Scope>),
}

/// What a client brings to the token endpoint to exchange a token.
#[derive(Debug)]
pub struct ExchangeRequest<'a, T: TenantScope> {
    /// The client asking, proved at the token endpoint.
    pub client: &'a OAuthClient<T>,
    /// The token it exchanges (`subject_token`).
    pub subject_token: &'a AccessToken<T>,
    /// Who acts (`actor_token`).
    pub actor: ExchangeActor<'a, T>,
    /// The client the new token is for (`audience`).
    pub audience: &'a OAuthClient<T>,
    /// The time now.
    pub now: OffsetDateTime,
}

/// Why an exchange was refused, as the error the token endpoint answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeRefusal {
    /// The client is revoked, public, or may not exchange tokens
    /// (`unauthorized_client`).
    #[error("this client may not exchange tokens")]
    UnauthorizedClient,
    /// The subject token does not work, or was not handed to this client
    /// (`invalid_grant`).
    #[error("the subject token cannot be exchanged by this client")]
    InvalidSubjectToken,
    /// The actor token does not work (`invalid_request`).
    #[error("the actor token does not work")]
    InvalidActorToken,
    /// The audience is not an active client of the tenant
    /// (`invalid_target`).
    #[error("the audience is not a client the token can be exchanged for")]
    InvalidTarget,
    /// It asked for a scope the subject token does not carry
    /// (`invalid_scope`).
    #[error("an exchange cannot ask for more than the subject token carries")]
    InvalidScope,
}

impl From<ExchangeRefusal> for DomainError {
    fn from(refusal: ExchangeRefusal) -> Self {
        match refusal {
            ExchangeRefusal::UnauthorizedClient | ExchangeRefusal::InvalidSubjectToken => {
                Self::forbidden(refusal.to_string())
            }
            ExchangeRefusal::InvalidActorToken
            | ExchangeRefusal::InvalidTarget
            | ExchangeRefusal::InvalidScope => Self::invalid(refusal.to_string()),
        }
    }
}

/// An exchange the domain allowed: what the new token carries.
///
/// Only [`TokenExchange::decide`] makes one, and
/// [`AccessToken::exchanged`] issues the token from it.
#[derive(Debug, Clone)]
pub struct TokenExchange {
    client_id: OAuthClientId,
    client_label: EventLabel,
    subject: TokenSubject,
    scopes: Vec<Scope>,
    audience: OAuthClientId,
    audience_label: EventLabel,
    delegation: Vec<ActingParty>,
}

impl TokenExchange {
    /// Decides `request` with `scopes` asked.
    ///
    /// The client must be active, confidential and allowed token exchange.
    /// The subject token must work now and have been handed to it, as its
    /// own or with it as the audience. An actor token must work now. The
    /// audience must be an active client. The scopes are the subject
    /// token's, or fewer. The new token's delegation is the actor, then the
    /// subject token's own actors.
    ///
    /// # Errors
    ///
    /// - The cases [`ExchangeRefusal`] names.
    pub fn decide<T: TenantScope>(
        request: &ExchangeRequest<'_, T>,
        scopes: ExchangeScopes,
    ) -> Result<Self, ExchangeRefusal> {
        let ExchangeRequest {
            client,
            subject_token: subject,
            actor,
            audience,
            now,
        } = request;
        ensure_may_exchange(client)?;
        if !subject.is_usable_at(*now) || !subject.reaches(client.id()) {
            return Err(ExchangeRefusal::InvalidSubjectToken);
        }
        if !audience.is_active() {
            return Err(ExchangeRefusal::InvalidTarget);
        }
        Ok(Self {
            client_id: *client.id(),
            client_label: EventLabel::of(client.name().as_str()),
            subject: subject.subject(),
            scopes: kept_scopes(subject, scopes)?,
            audience: *audience.id(),
            audience_label: EventLabel::of(audience.name().as_str()),
            delegation: delegation(subject, actor, *now)?,
        })
    }

    /// The client that asked, which holds the new token.
    #[must_use]
    pub fn client_id(&self) -> &OAuthClientId {
        &self.client_id
    }

    /// Whom the new token acts for: the subject token's subject.
    #[must_use]
    pub fn subject(&self) -> TokenSubject {
        self.subject
    }

    /// The scopes it carries.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// The client it is meant for.
    #[must_use]
    pub fn audience(&self) -> AccessAudience {
        AccessAudience::Client(self.audience)
    }

    /// Who acts for the subject, outermost first.
    #[must_use]
    pub fn delegation(&self) -> &[ActingParty] {
        &self.delegation
    }

    /// The client's label, for the audit trail.
    pub(crate) fn client_label(&self) -> &EventLabel {
        &self.client_label
    }

    /// The audience's id and label, for the audit trail.
    pub(crate) fn audience_named(&self) -> (OAuthClientId, &EventLabel) {
        (self.audience, &self.audience_label)
    }
}

/// Refuses a client that may not exchange tokens.
fn ensure_may_exchange<T: TenantScope>(client: &OAuthClient<T>) -> Result<(), ExchangeRefusal> {
    let may = client.is_active()
        && !client.is_public()
        && client.supports_grant_type(GrantType::TokenExchange);
    if may {
        return Ok(());
    }
    Err(ExchangeRefusal::UnauthorizedClient)
}

/// The scopes the new token keeps: the subject token's, or fewer.
fn kept_scopes<T: TenantScope>(
    subject: &AccessToken<T>,
    asked: ExchangeScopes,
) -> Result<Vec<Scope>, ExchangeRefusal> {
    match asked {
        ExchangeScopes::AsSubject => Ok(subject.scopes().to_vec()),
        ExchangeScopes::Narrowed(scopes) if scopes.iter().all(|scope| subject.grants(scope)) => {
            Ok(scopes)
        }
        ExchangeScopes::Narrowed(_) => Err(ExchangeRefusal::InvalidScope),
    }
}

/// The new token's chain of actors: `actor`, then whoever already acted in
/// `subject`.
fn delegation<T: TenantScope>(
    subject: &AccessToken<T>,
    actor: &ExchangeActor<'_, T>,
    now: OffsetDateTime,
) -> Result<Vec<ActingParty>, ExchangeRefusal> {
    let ExchangeActor::Token(actor) = actor else {
        return Ok(subject.delegation().to_vec());
    };
    if !actor.is_usable_at(now) {
        return Err(ExchangeRefusal::InvalidActorToken);
    }
    let party = match actor.subject() {
        TokenSubject::Person(user) => ActingParty::Person(user),
        TokenSubject::Client => ActingParty::Client(*actor.client_id()),
    };
    Ok(std::iter::once(party)
        .chain(subject.delegation().iter().copied())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::oauth::clients::client::NewOAuthClient;
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::domains::oauth::grants::access_token::{IssueAccessTokenParams, TokenIssue};
    use crate::domains::oauth::grants::token_binding::SenderBinding;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;
    use crate::types::{ClientId, Lifetime, RedirectUri, TokenHash, UserId};

    fn scope(name: &str) -> Scope {
        Scope::new(name).unwrap()
    }

    /// A confidential client named `name`, using `grants`.
    fn client(name: &str, grants: Vec<GrantType>) -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new(name).unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored("s".to_owned())),
                name: label(name),
                redirect_uris: vec![RedirectUri::new("https://svc.acme.com/cb").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: grants,
                scopes: vec![scope("orders:read"), scope("billing:read")],
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// The orders service, which may exchange tokens.
    fn orders() -> OAuthClient<ResolvedTenant> {
        client("orders", vec![GrantType::TokenExchange])
    }

    /// The billing API.
    fn billing() -> OAuthClient<ResolvedTenant> {
        client("billing", vec![GrantType::ClientCredentials])
    }

    /// Ann's token, issued to `holder`, for `scopes`.
    fn anns_token(
        holder: &OAuthClient<ResolvedTenant>,
        scopes: &[&str],
    ) -> AccessToken<ResolvedTenant> {
        AccessToken::issue(IssueAccessTokenParams {
            token_hash: TokenHash::from_stored("ann".to_owned()),
            client_id: *holder.id(),
            user_id: UserId::new(),
            scopes: scopes.iter().map(|name| scope(name)).collect(),
            lifetime: Lifetime::seconds(3600).unwrap(),
            binding: SenderBinding::Bearer,
        })
    }

    /// `client` exchanging `subject` for the billing API, with no actor.
    fn exchange(
        client: &OAuthClient<ResolvedTenant>,
        subject: &AccessToken<ResolvedTenant>,
        audience: &OAuthClient<ResolvedTenant>,
        scopes: ExchangeScopes,
    ) -> Result<TokenExchange, ExchangeRefusal> {
        TokenExchange::decide(
            &ExchangeRequest {
                client,
                subject_token: subject,
                actor: ExchangeActor::NotNamed,
                audience,
                now: crate::shared::clock::now(),
            },
            scopes,
        )
    }

    /// The orders service exchanges Ann's token for one for the billing
    /// API, narrowed to `orders:read`. The new token acts for Ann, for the
    /// billing API, and its issue is raised as an exchange.
    #[test]
    fn a_client_exchanges_a_token_it_holds_for_another_audience() {
        let (orders, billing) = (orders(), billing());
        let ann = anns_token(&orders, &["orders:read", "billing:read"]);
        let narrowed = ExchangeScopes::Narrowed(vec![scope("orders:read")]);

        let decided = exchange(&orders, &ann, &billing, narrowed).unwrap();
        let mut token = AccessToken::<ResolvedTenant>::exchanged(
            TokenIssue {
                token_hash: TokenHash::from_stored("exchanged".to_owned()),
                lifetime: Lifetime::seconds(300).unwrap(),
                binding: SenderBinding::Bearer,
            },
            &decided,
        );

        assert_eq!(token.subject(), ann.subject());
        assert_eq!(token.audience(), AccessAudience::Client(*billing.id()));
        assert_eq!(token.scopes(), &[scope("orders:read")]);
        assert_eq!(
            raised_names(&mut token),
            ["oauth.access_token_issued", "oauth.token_exchanged"]
        );
    }

    /// Exchanging a token carrying only `orders:read` for one also carrying
    /// `billing:write` is refused with an invalid-scope result.
    #[test]
    fn an_exchange_cannot_widen_the_scopes() {
        let (orders, billing) = (orders(), billing());
        let ann = anns_token(&orders, &["orders:read"]);
        let wider = ExchangeScopes::Narrowed(vec![scope("orders:read"), scope("billing:write")]);

        let result = exchange(&orders, &ann, &billing, wider);

        assert_eq!(result.unwrap_err(), ExchangeRefusal::InvalidScope);
    }

    /// The orders client cannot exchange a token issued to billing. The
    /// token is refused as an invalid subject token for orders.
    #[test]
    fn a_client_exchanges_only_tokens_handed_to_it() {
        let (orders, billing) = (orders(), billing());
        let elsewhere = anns_token(&billing, &["orders:read"]);

        let result = exchange(&orders, &elsewhere, &billing, ExchangeScopes::AsSubject);

        assert_eq!(result.unwrap_err(), ExchangeRefusal::InvalidSubjectToken);
    }

    /// Exchange rejects a client lacking the exchange grant as unauthorized.
    /// An authorized client presenting a revoked token gets an invalid-subject
    /// refusal.
    #[test]
    fn exchange_needs_the_grant_and_a_working_token() {
        let (orders, billing) = (orders(), billing());
        let mut revoked = anns_token(&orders, &["orders:read"]);
        revoked.revoke();
        let ann = anns_token(&billing, &["orders:read"]);

        let no_grant = exchange(&billing, &ann, &orders, ExchangeScopes::AsSubject);
        let dead = exchange(&orders, &revoked, &billing, ExchangeScopes::AsSubject);

        assert_eq!(no_grant.unwrap_err(), ExchangeRefusal::UnauthorizedClient);
        assert_eq!(dead.unwrap_err(), ExchangeRefusal::InvalidSubjectToken);
    }

    /// The orders service names itself as the actor with its own token. The
    /// new token's delegation names the orders service.
    #[test]
    fn an_actor_token_names_who_acts_for_the_subject() {
        let (orders, billing) = (orders(), billing());
        let ann = anns_token(&orders, &["orders:read"]);
        let itself = AccessToken::<ResolvedTenant>::for_client(
            TokenIssue {
                token_hash: TokenHash::from_stored("svc".to_owned()),
                lifetime: Lifetime::seconds(300).unwrap(),
                binding: SenderBinding::Bearer,
            },
            &client("orders-svc", vec![GrantType::ClientCredentials]),
            Vec::new(),
        )
        .unwrap();

        let decided = TokenExchange::decide(
            &ExchangeRequest {
                client: &orders,
                subject_token: &ann,
                actor: ExchangeActor::Token(&itself),
                audience: &billing,
                now: crate::shared::clock::now(),
            },
            ExchangeScopes::AsSubject,
        )
        .unwrap();

        assert_eq!(
            decided.delegation(),
            &[ActingParty::Client(*itself.client_id())]
        );
    }
}
