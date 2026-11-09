//! Access tokens as signed JWTs a resource server checks on its own (RFC
//! 9068), for a client that chose that form.
//!
//! The claims come from the token record, never from the caller: a use
//! case cannot widen `scope` or move `aud` before the token is signed. A
//! bound token carries what it is bound to (`cnf`, RFC 9449 6 and RFC 8705
//! 3.1), and an exchanged one who acts for its subject (`act`, RFC 8693
//! 4.1). An adapter signs the claims with the JWT type `at+jwt`.

use time::OffsetDateTime;

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::oauth::clients::client::OAuthClient;
use crate::domains::oauth::clients::settings::AccessTokenFormat;
use crate::domains::oauth::grants::access_token::{
    AccessAudience, AccessToken, ActingParty, TokenSubject,
};
use crate::domains::oauth::grants::authorization_code::AuthorizationCode;
use crate::domains::oauth::grants::id_token::{AuthMethodReference, amr_for};
use crate::domains::oauth::grants::token_binding::SenderBinding;
use crate::domains::routing::stream::tunnel_audience_of;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{Audience, ClientId, Issuer, Scope, TokenId, UserId};

/// How the person behind a token signed in, when it is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInFacts {
    /// Not stated: the token acts for a machine, or was refreshed long
    /// after the sign-in, which is not at hand.
    NotStated,
    /// The sign-in the grant came from.
    Stated {
        /// When the person signed in (`auth_time`).
        auth_time: OffsetDateTime,
        /// The assurance it reached (`acr`).
        assurance: AssuranceLevel,
        /// How they proved who they are (`amr`).
        amr: Vec<AuthMethodReference>,
    },
}

impl SignInFacts {
    /// The sign-in `code` was issued after.
    #[must_use]
    pub fn of_code<T: TenantScope>(code: &AuthorizationCode<T>) -> Self {
        Self::Stated {
            auth_time: code.authenticated_at(),
            assurance: code.assurance_level(),
            amr: amr_for(code.auth_method(), code.second_factor()),
        }
    }
}

/// Whom a JWT access token is about (`sub`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtSubject {
    /// The person it acts for.
    Person(UserId),
    /// The client acting as itself, by its client id.
    Client(ClientId),
}

/// The claims of a JWT access token (RFC 9068 2.2).
///
/// Only [`JwtAccessTokenClaims::build`] makes them.
#[derive(Debug, Clone)]
pub struct JwtAccessTokenClaims {
    iss: Issuer,
    exp: OffsetDateTime,
    aud: Audience,
    sub: JwtSubject,
    client_id: ClientId,
    iat: OffsetDateTime,
    jti: TokenId,
    scope: Vec<Scope>,
    sign_in: SignInFacts,
    binding: SenderBinding,
    delegation: Vec<ActingParty>,
}

/// What JWT access token claims are built from.
pub struct JwtAccessTokenParams<'a, T: TenantScope> {
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// The token just issued.
    pub token: &'a AccessToken<T>,
    /// The client holding it.
    pub client: &'a OAuthClient<T>,
    /// The client it is meant for: the holder, or the one it was exchanged
    /// for.
    pub audience: &'a OAuthClient<T>,
    /// A fresh `jti`.
    pub jti: TokenId,
    /// How the person signed in, for a token acting for one.
    pub sign_in: SignInFacts,
}

impl JwtAccessTokenClaims {
    /// The claims of `params.token`, as a JWT for `params.client`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the client chose opaque tokens.
    /// - [`DomainError::Forbidden`] when the token was not issued to
    ///   `params.client`, `params.audience` is not whom it is meant for, or
    ///   it acts for a machine and sign-in facts are stated.
    pub fn build<T: TenantScope>(params: JwtAccessTokenParams<'_, T>) -> Result<Self, DomainError> {
        let (token, client) = (params.token, params.client);
        if client.settings().token_format != AccessTokenFormat::Jwt {
            return Err(DomainError::conflict(message!(
                "oauth-this-client-takes-opaque-access-tokens",
                "this client takes opaque access tokens"
            )));
        }
        if !token.belongs_to(client.id()) || !is_meant_for(token, params.audience) {
            return Err(DomainError::forbidden(message!(
                "oauth-the-token-was-issued-to-another",
                "the token was issued to another client or for another audience"
            )));
        }
        Ok(Self {
            iss: params.issuer,
            exp: token.expires_at(),
            aud: audience_named(token, params.audience)?,
            sub: subject_of(token, client, &params.sign_in)?,
            client_id: client.client_id_value().clone(),
            iat: token.created_at(),
            jti: params.jti,
            scope: token.scopes().to_vec(),
            sign_in: params.sign_in,
            binding: token.binding().clone(),
            delegation: token.delegation().to_vec(),
        })
    }

    /// The issuer, `iss`.
    #[must_use]
    pub fn iss(&self) -> &Issuer {
        &self.iss
    }

    /// When it expires, `exp`.
    #[must_use]
    pub fn exp(&self) -> OffsetDateTime {
        self.exp
    }

    /// Whom it is meant for, `aud`: a client by its client id, or a stream
    /// route's tunnel.
    #[must_use]
    pub fn aud(&self) -> &Audience {
        &self.aud
    }

    /// Whom it is about, `sub`.
    #[must_use]
    pub fn sub(&self) -> &JwtSubject {
        &self.sub
    }

    /// The client holding it, `client_id`.
    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// When it was issued, `iat`.
    #[must_use]
    pub fn iat(&self) -> OffsetDateTime {
        self.iat
    }

    /// The token identity used to distinguish this issuance from other tokens.
    #[must_use]
    pub fn jti(&self) -> &TokenId {
        &self.jti
    }

    /// The scopes it carries, written space-separated as `scope`.
    #[must_use]
    pub fn scope(&self) -> &[Scope] {
        &self.scope
    }

    /// How the person signed in: `auth_time`, `acr` and `amr` when stated.
    #[must_use]
    pub fn sign_in(&self) -> &SignInFacts {
        &self.sign_in
    }

    /// What it is bound to, written as `cnf` unless it is a bearer token.
    #[must_use]
    pub fn binding(&self) -> &SenderBinding {
        &self.binding
    }

    /// Who acts for its subject, outermost first, written as nested `act`.
    #[must_use]
    pub fn delegation(&self) -> &[ActingParty] {
        &self.delegation
    }
}

/// Whether `audience` is whom `token` is meant for. A tunnel token is
/// signed for its holder, its `aud` naming the tunnel.
fn is_meant_for<T: TenantScope>(token: &AccessToken<T>, audience: &OAuthClient<T>) -> bool {
    match token.audience() {
        AccessAudience::Holder | AccessAudience::StreamRoute(_) => token.belongs_to(audience.id()),
        AccessAudience::Client(meant) => meant == *audience.id(),
    }
}

/// The `aud` of `token`, meant for `audience`: that client's id, or the
/// tunnel audience of the stream route it was asked for.
///
/// # Errors
///
/// - [`DomainError::Validation`] if the audience cannot be spelled, which
///   a client id or a route id never causes.
fn audience_named<T: TenantScope>(
    token: &AccessToken<T>,
    audience: &OAuthClient<T>,
) -> Result<Audience, DomainError> {
    match token.audience() {
        AccessAudience::StreamRoute(route) => tunnel_audience_of(&route),
        AccessAudience::Holder | AccessAudience::Client(_) => {
            Audience::new(audience.client_id_value().as_str()).map_err(DomainError::from)
        }
    }
}

/// The `sub` of `token`, held by `client`; a machine's token states no
/// sign-in.
fn subject_of<T: TenantScope>(
    token: &AccessToken<T>,
    client: &OAuthClient<T>,
    sign_in: &SignInFacts,
) -> Result<JwtSubject, DomainError> {
    match (token.subject(), sign_in) {
        (TokenSubject::Person(person), _) => Ok(JwtSubject::Person(person)),
        (TokenSubject::Client, SignInFacts::NotStated) => {
            Ok(JwtSubject::Client(client.client_id_value().clone()))
        }
        (TokenSubject::Client, SignInFacts::Stated { .. }) => {
            Err(DomainError::forbidden(message!(
                "oauth-a-token-for-a-machine-states",
                "a token for a machine states no sign-in"
            )))
        }
    }
}

#[cfg(feature = "serde")]
mod json {
    //! The JSON a JWT access token's claims are written as.

    use std::collections::BTreeMap;

    use serde::ser::{Serialize, SerializeMap, Serializer};

    use crate::domains::oauth::grants::access_token::ActingParty;
    use crate::domains::oauth::grants::jwt_access_token::{
        JwtAccessTokenClaims, JwtSubject, SignInFacts,
    };
    use crate::domains::oauth::grants::token_binding::SenderBinding;
    use crate::types::Scope;

    impl Serialize for JwtAccessTokenClaims {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(None)?;
            serialize_registered(self, &mut map)?;
            sign_in(&self.sign_in, &mut map)?;
            confirmation(&self.binding, &mut map)?;
            if !self.delegation.is_empty() {
                map.serialize_entry("act", &Actors(&self.delegation))?;
            }
            map.end()
        }
    }

    /// The claims every JWT access token carries.
    fn serialize_registered<M: SerializeMap>(
        claims: &JwtAccessTokenClaims,
        map: &mut M,
    ) -> Result<(), M::Error> {
        let scope: Vec<&str> = claims.scope.iter().map(Scope::as_str).collect();
        map.serialize_entry("iss", claims.iss.as_str())?;
        map.serialize_entry("exp", &claims.exp.unix_timestamp())?;
        map.serialize_entry("aud", claims.aud.as_str())?;
        map.serialize_entry("sub", &subject_text(&claims.sub))?;
        map.serialize_entry("client_id", claims.client_id.as_str())?;
        map.serialize_entry("iat", &claims.iat.unix_timestamp())?;
        map.serialize_entry("jti", claims.jti.as_str())?;
        map.serialize_entry("scope", &scope.join(" "))
    }

    /// `auth_time`, `acr` and `amr`, when the sign-in is stated.
    fn sign_in<M: SerializeMap>(facts: &SignInFacts, map: &mut M) -> Result<(), M::Error> {
        let SignInFacts::Stated {
            auth_time,
            assurance,
            amr,
        } = facts
        else {
            return Ok(());
        };
        map.serialize_entry("auth_time", &auth_time.unix_timestamp())?;
        map.serialize_entry("acr", assurance.acr())?;
        map.serialize_entry("amr", amr)
    }

    /// `cnf`, for a bound token.
    fn confirmation<M: SerializeMap>(binding: &SenderBinding, map: &mut M) -> Result<(), M::Error> {
        let (member, thumbprint) = match binding {
            SenderBinding::Bearer => return Ok(()),
            SenderBinding::DpopKey(key) => ("jkt", key.as_str()),
            SenderBinding::Certificate(certificate) => ("x5t#S256", certificate.as_str()),
        };
        map.serialize_entry("cnf", &BTreeMap::from([(member, thumbprint)]))
    }

    /// The `sub` text of a subject.
    fn subject_text(subject: &JwtSubject) -> String {
        match subject {
            JwtSubject::Person(person) => person.to_string(),
            JwtSubject::Client(client) => client.as_str().to_owned(),
        }
    }

    /// A chain of actors, written as an `act` holding the first one's
    /// `sub` and, nested, the rest.
    struct Actors<'a>(&'a [ActingParty]);

    impl Serialize for Actors<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(None)?;
            let Some((first, rest)) = self.0.split_first() else {
                return map.end();
            };
            let sub = match first {
                ActingParty::Person(person) => person.to_string(),
                ActingParty::Client(client) => client.to_string(),
            };
            map.serialize_entry("sub", &sub)?;
            if !rest.is_empty() {
                map.serialize_entry("act", &Actors(rest))?;
            }
            map.end()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::oauth::clients::client::{GrantType, NewOAuthClient, OAuthClientChange};
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::{ClientSettings, SettingsChange};
    use crate::domains::oauth::control::tests::key_admin;
    use crate::domains::oauth::grants::access_token::{AccessTokenRow, IssueAccessTokenParams};
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::label;
    use crate::types::{Lifetime, OAuthClientId, RedirectUri, TokenHash};

    /// An app whose access tokens take `format`.
    fn app(format: AccessTokenFormat) -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("web_app").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored("s".to_owned())),
                name: label("Web app"),
                redirect_uris: vec![RedirectUri::new("https://app.acme.com/cb").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: Vec::new(),
                settings: ClientSettings {
                    token_format: format,
                    ..ClientSettings::platform_defaults()
                },
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// Ann's token, issued to `client`, bound as `binding` says.
    fn anns_token(
        client: &OAuthClient<ResolvedTenant>,
        binding: SenderBinding,
    ) -> AccessToken<ResolvedTenant> {
        AccessToken::issue(IssueAccessTokenParams {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            client_id: *client.id(),
            user_id: UserId::new(),
            scopes: vec![Scope::new("openid").unwrap(), Scope::new("read").unwrap()],
            lifetime: Lifetime::seconds(300).unwrap(),
            binding,
        })
    }

    /// The claims of `token` held by `client`, for `audience`.
    fn claims(
        token: &AccessToken<ResolvedTenant>,
        client: &OAuthClient<ResolvedTenant>,
        audience: &OAuthClient<ResolvedTenant>,
    ) -> Result<JwtAccessTokenClaims, DomainError> {
        JwtAccessTokenClaims::build(JwtAccessTokenParams {
            issuer: Issuer::new("https://auth.acme.com").unwrap(),
            token,
            client,
            audience,
            jti: TokenId::new("019f0000-0000-7000-8000-0000000000a6").unwrap(),
            sign_in: SignInFacts::NotStated,
        })
    }

    /// Ann's token for the web app, which chose JWTs, carries the token's
    /// own terms: its client, Ann, its scopes and its expiry.
    #[test]
    fn the_claims_come_from_the_token_record() {
        let client = app(AccessTokenFormat::Jwt);
        let token = anns_token(&client, SenderBinding::Bearer);

        let claims = claims(&token, &client, &client).unwrap();

        assert_eq!(claims.client_id().as_str(), "web_app");
        assert_eq!(claims.aud().as_str(), "web_app");
        assert_eq!(
            claims.sub(),
            &JwtSubject::Person(*token.subject().person().unwrap())
        );
        assert_eq!(claims.scope(), token.scopes());
        assert_eq!(claims.exp(), token.expires_at());
    }

    /// Ann's CLI asked for a token for the SSH tunnel. Its `aud` names that
    /// route's tunnel, never the CLI, so no app or API takes it.
    #[test]
    fn a_tunnel_tokens_aud_names_its_route() {
        let client = app(AccessTokenFormat::Jwt);
        let issued = anns_token(&client, SenderBinding::Bearer);
        let route = crate::types::StreamRouteId::new();
        let token = AccessToken::reconstitute(AccessTokenRow {
            token_hash: issued.token_hash().clone(),
            client_id: *client.id(),
            subject: issued.subject(),
            scopes: issued.scopes().to_vec(),
            audience: AccessAudience::StreamRoute(route),
            delegation: Vec::new(),
            binding: SenderBinding::Bearer,
            created_at: issued.created_at(),
            expires_at: issued.expires_at(),
            revocation: crate::types::Revocation::InForce,
        })
        .unwrap();

        let claims = claims(&token, &client, &client).unwrap();

        assert_eq!(
            claims.aud().as_str(),
            format!("urn:ianua:stream-route:{route}")
        );
    }

    /// A client that chose opaque tokens gets no JWT.
    #[test]
    fn an_opaque_client_gets_no_jwt() {
        let client = app(AccessTokenFormat::Opaque);
        let token = anns_token(&client, SenderBinding::Bearer);

        assert!(matches!(
            claims(&token, &client, &client),
            Err(DomainError::Conflict(_))
        ));
    }

    /// Building JWT claims with a different client as the audience is
    /// forbidden when the token is meant for its holder.
    #[test]
    fn the_audience_must_be_whom_the_token_is_meant_for() {
        let client = app(AccessTokenFormat::Jwt);
        let token = anns_token(&client, SenderBinding::Bearer);
        let billing = app(AccessTokenFormat::Jwt);

        assert!(matches!(
            claims(&token, &client, &billing),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// An admin switches the app to JWTs; its tokens can then be written
    /// as JWTs.
    #[test]
    fn switching_to_jwt_lets_tokens_be_written_as_jwts() {
        let mut client = app(AccessTokenFormat::Opaque);
        client
            .update(
                vec![OAuthClientChange::from(SettingsChange::TokenFormat(
                    AccessTokenFormat::Jwt,
                ))],
                &key_admin(),
            )
            .unwrap();
        let token = anns_token(&client, SenderBinding::Bearer);

        assert!(claims(&token, &client, &client).is_ok());
    }

    /// A `DPoP`-bound token's JWT names its key as `cnf.jkt`, carries the
    /// scopes space-separated, and leaves out the sign-in it did not state.
    #[cfg(feature = "serde")]
    #[test]
    fn a_bound_tokens_jwt_names_its_key() {
        let client = app(AccessTokenFormat::Jwt);
        let key = crate::domains::oauth::grants::token_binding::JwkThumbprint::new("a".repeat(43));
        let token = anns_token(&client, SenderBinding::DpopKey(key.unwrap()));

        let json = serde_json::to_value(claims(&token, &client, &client).unwrap()).unwrap();

        assert_eq!(json["cnf"]["jkt"], "a".repeat(43));
        assert_eq!(json["scope"], "openid read");
        assert!(json.get("auth_time").is_none());
        assert!(json.get("act").is_none());
    }
}
