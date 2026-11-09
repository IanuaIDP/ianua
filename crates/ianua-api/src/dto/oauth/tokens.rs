//! What the token endpoint hands out (RFC 6749 5.1, RFC 8693 2.2.1), what
//! introspection says of a token (RFC 7662 2.2), and the claims `userinfo`
//! answers with (OIDC Core 5.3).

use ianua_app::use_cases::oauth::token::IntrospectionResult;
use ianua_app::use_cases::oauth::token::issuing::{HandedToken, IssuedTokens, TokenType};
use ianua_assembly::oauth::IssuedGrant;
use ianua_domain::domains::oauth::grants::access_token::{
    ActingParty, Introspection, TokenSubject,
};
use ianua_domain::domains::oauth::grants::token_binding::SenderBinding;
use ianua_domain::domains::oauth::grants::userinfo::UserInfoClaims;
use ianua_domain::types::{Audience, ClientId, Issuer, Label, Scope};
use serde::Serialize;

use crate::extractors::oauth::token::ACCESS_TOKEN_TYPE;

/// The tokens a grant hands out.
#[derive(Serialize, utoipa::ToSchema)]
pub struct TokenResponse {
    /// The access token: opaque, or a signed JWT, as the client chose.
    pub access_token: String,
    /// How it is presented: `Bearer`, or `DPoP` for a token bound to a key.
    pub token_type: &'static str,
    /// The access token's lifetime, in seconds.
    pub expires_in: i64,
    /// The scopes it carries, separated by spaces.
    pub scope: String,
    /// The refresh token, when the grant hands one out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The signed OIDC ID token, when the grant asked for `openid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The kind of token a token exchange issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<&'static str>,
}

impl From<IssuedGrant> for TokenResponse {
    fn from(grant: IssuedGrant) -> Self {
        match grant {
            IssuedGrant::Granted(tokens) => Self::from(tokens),
            IssuedGrant::Exchanged(tokens) => Self {
                issued_token_type: Some(ACCESS_TOKEN_TYPE),
                ..Self::from(tokens)
            },
        }
    }
}

impl From<IssuedTokens> for TokenResponse {
    fn from(tokens: IssuedTokens) -> Self {
        Self {
            access_token: tokens.access_token.expose().to_owned(),
            token_type: match tokens.token_type {
                TokenType::Bearer => "Bearer",
                TokenType::Dpop => "DPoP",
            },
            expires_in: tokens.expires_in.whole_seconds(),
            scope: spaced(&tokens.scopes),
            refresh_token: handed(tokens.refresh_token),
            id_token: handed(tokens.id_token),
            issued_token_type: None,
        }
    }
}

/// The token handed out, if one was.
fn handed(token: HandedToken) -> Option<String> {
    match token {
        HandedToken::NotIssued => None,
        HandedToken::Issued(token) => Some(token.expose().to_owned()),
    }
}

/// `scopes`, separated by spaces.
fn spaced(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(Scope::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

/// What a token is bound to (`cnf`, RFC 7800).
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConfirmationClaim {
    /// The thumbprint of the `DPoP` key it is bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    /// The thumbprint of the TLS certificate it is bound to.
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

/// Who acts for a token's subject (`act`, RFC 8693 4.1): the current actor,
/// with those before it nested inside.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ActorClaim {
    /// The actor: a person's id, or a client's id.
    pub sub: String,
    /// The actor before it, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub act: Option<Box<ActorClaim>>,
}

/// What an access token says about itself. An inactive token says nothing
/// else.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct IntrospectionResponse {
    /// Whether the token works now.
    pub active: bool,
    /// The scopes it carries, separated by spaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The client it was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Whom it acts for: a person's id, or the client's own id for a
    /// machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// The client it is meant for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// The issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// When it expires, in seconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// When it was issued, in seconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// How it is presented: `Bearer` or `DPoP`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<&'static str>,
    /// What it is bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaim>,
    /// Who acts for its subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
}

impl IntrospectionResponse {
    /// What `result` says, the token issued by the tenant `issuer` names.
    #[must_use]
    pub(crate) fn of(result: IntrospectionResult, issuer: &Issuer) -> Self {
        let IntrospectionResult::Active {
            facts,
            holder,
            audience,
        } = result
        else {
            return Self::inactive();
        };
        Self::active(facts, &holder, &audience, issuer)
    }

    /// Maps active domain facts with the public identities resolved by the use case.
    fn active(
        facts: Introspection,
        holder: &ClientId,
        audience: &Audience,
        issuer: &Issuer,
    ) -> Self {
        let Introspection::Active {
            subject,
            scopes,
            issued_at,
            expires_at,
            binding,
            delegation,
            ..
        } = facts
        else {
            return Self::inactive();
        };
        Self {
            active: true,
            scope: Some(spaced(&scopes)),
            sub: Some(match subject {
                TokenSubject::Person(person) => person.to_string(),
                TokenSubject::Client => holder.as_str().to_owned(),
            }),
            client_id: Some(holder.as_str().to_owned()),
            aud: Some(audience.as_str().to_owned()),
            iss: Some(issuer.as_str().to_owned()),
            exp: Some(expires_at.unix_timestamp()),
            iat: Some(issued_at.unix_timestamp()),
            token_type: Some(presentation(&binding)),
            cnf: confirmation(&binding),
            act: actor(&delegation).map(|actor| *actor),
        }
    }

    /// A token that does not work.
    fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            sub: None,
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            token_type: None,
            cnf: None,
            act: None,
        }
    }
}

/// The authorization scheme a token's sender binding requires on the wire.
fn presentation(binding: &SenderBinding) -> &'static str {
    match binding {
        SenderBinding::DpopKey(_) => "DPoP",
        SenderBinding::Bearer | SenderBinding::Certificate(_) => "Bearer",
    }
}

/// What `binding` binds a token to, if anything.
fn confirmation(binding: &SenderBinding) -> Option<ConfirmationClaim> {
    match binding {
        SenderBinding::Bearer => None,
        SenderBinding::DpopKey(key) => Some(ConfirmationClaim {
            jkt: Some(key.as_str().to_owned()),
            x5t_s256: None,
        }),
        SenderBinding::Certificate(certificate) => Some(ConfirmationClaim {
            jkt: None,
            x5t_s256: Some(certificate.as_str().to_owned()),
        }),
    }
}

/// The actors of `parties`, outermost first, nested.
fn actor(parties: &[ActingParty]) -> Option<Box<ActorClaim>> {
    let (current, before) = parties.split_first()?;
    Some(Box::new(ActorClaim {
        sub: match current {
            ActingParty::Person(person) => person.to_string(),
            ActingParty::Client(client) => client.to_string(),
        },
        act: actor(before),
    }))
}

/// The claims `userinfo` answers with: `sub` always, the rest as the
/// token's scopes let out.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UserInfoResponse {
    /// The person's id, as in their ID token.
    pub sub: String,
    /// Their email address, with the `email` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether they proved they hold it, with the `email` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Their name, with the `profile` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Their own locale, with the `profile` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Their own timezone, with the `profile` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// The names of the roles they hold, with the `roles` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

impl From<UserInfoClaims> for UserInfoResponse {
    fn from(claims: UserInfoClaims) -> Self {
        let scoped = claims.scoped();
        Self {
            sub: claims.sub().to_string(),
            email: scoped.email().map(|email| email.as_str().to_owned()),
            email_verified: scoped.email_verified(),
            name: scoped.name().map(|name| name.as_str().to_owned()),
            locale: scoped.locale().map(|locale| locale.as_str().to_owned()),
            zoneinfo: scoped.zoneinfo().map(|zone| zone.as_str().to_owned()),
            roles: scoped
                .roles()
                .map(|roles| roles.iter().map(Label::as_str).map(str::to_owned).collect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{OAuthClientId, UserId};

    use super::*;

    /// A delegation chain reads as nested actors, the current one outermost.
    #[test]
    fn a_delegation_chain_nests_its_actors() {
        let person = UserId::new();
        let client = OAuthClientId::new();

        let Some(outer) = actor(&[ActingParty::Client(client), ActingParty::Person(person)]) else {
            panic!("a chain has an actor");
        };

        assert_eq!(outer.sub, client.to_string());
        assert_eq!(
            outer.act.as_ref().map(|inner| inner.sub.clone()),
            Some(person.to_string())
        );
    }

    /// An inactive token says nothing but that it is inactive.
    #[test]
    fn an_inactive_token_says_nothing_else() {
        let issuer =
            Issuer::new("https://app.ianua.test/api/v1/organizations/a/tenants/b").unwrap();

        let body = serde_json::to_value(IntrospectionResponse::of(
            IntrospectionResult::Inactive,
            &issuer,
        ))
        .unwrap();

        assert_eq!(body, serde_json::json!({"active": false}));
    }
}
