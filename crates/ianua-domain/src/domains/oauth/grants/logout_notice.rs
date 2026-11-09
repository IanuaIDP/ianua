//! Telling apps that a person signed out (OpenID Connect Back-Channel
//! Logout 1.0 and Front-Channel Logout 1.0).
//!
//! Ann signs out of ianua. The apps she signed in to through it still hold
//! her session, and would let anyone at her desk carry on. So each app that
//! asked to hear of it is told: its server gets a signed logout token, or
//! her browser loads a page of the app that ends its own session.
//!
//! A logout token never carries a nonce, so it can never be passed off as
//! an ID token (Back-Channel Logout 2.4).

use time::{Duration, OffsetDateTime};
use url::Url;

use crate::domains::oauth::clients::client::OAuthClient;
use crate::domains::oauth::clients::settings::{ChannelLogout, SessionRequired};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ClientId, HttpsUrl, Issuer, SessionId, TokenId, UserId};

/// How long a logout token is accepted: two minutes, enough to deliver it.
const LOGOUT_TOKEN_LIFETIME: Duration = Duration::minutes(2);

/// Who signed out, as a logout token names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignedOut {
    /// A person, out of one session: `sub` and `sid`.
    Session {
        /// The subject whose one named session has ended.
        person: UserId,
        /// The session that ended.
        session: SessionId,
    },
    /// A person, out of every session at once, as when their account is
    /// locked: `sub` alone.
    Everywhere {
        /// The subject whose sessions must all be ended by the relying party.
        person: UserId,
    },
}

/// The claims of a logout token (Back-Channel Logout 2.4): `iss`, `aud`,
/// `iat`, `exp`, `jti`, the back-channel logout event, `sub`, and `sid` for
/// one session.
///
/// Only [`LogoutTokenClaims::build`] makes them.
#[derive(Debug, Clone)]
pub struct LogoutTokenClaims {
    iss: Issuer,
    aud: ClientId,
    iat: OffsetDateTime,
    exp: OffsetDateTime,
    jti: TokenId,
    signed_out: SignedOut,
}

/// What a logout token is built from.
pub struct LogoutTokenParams<'a, T: TenantScope> {
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// The app being told. Its client id is the audience.
    pub client: &'a OAuthClient<T>,
    /// Who signed out.
    pub signed_out: SignedOut,
    /// A fresh `jti`, by which the app spots a replay.
    pub jti: TokenId,
}

impl LogoutTokenClaims {
    /// The logout token telling `params.client` that `params.signed_out`
    /// signed out, issued now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the client is revoked or takes no
    ///   back-channel logout.
    /// - [`DomainError::Conflict`] when the client wants each session named
    ///   and the person signed out everywhere: the caller sends one token
    ///   per session instead.
    pub fn build<T: TenantScope>(params: LogoutTokenParams<'_, T>) -> Result<Self, DomainError> {
        let client = params.client;
        let ChannelLogout::At { session, .. } = &client.settings().logout.back_channel else {
            return Err(DomainError::conflict(message!(
                "oauth-this-client-takes-no-back-channel",
                "this client takes no back-channel logout"
            )));
        };
        if !client.is_active() {
            return Err(DomainError::conflict(message!(
                "oauth-a-revoked-client-is-told-nothing",
                "a revoked client is told nothing"
            )));
        }
        let unnamed = matches!(params.signed_out, SignedOut::Everywhere { .. });
        if *session == SessionRequired::Required && unnamed {
            return Err(DomainError::conflict(message!(
                "oauth-this-client-wants-each-session-named",
                "this client wants each session named; send one logout token per session"
            )));
        }
        let now = crate::shared::clock::now();
        Ok(Self {
            iss: params.issuer,
            aud: client.client_id_value().clone(),
            iat: now,
            exp: now.saturating_add(LOGOUT_TOKEN_LIFETIME),
            jti: params.jti,
            signed_out: params.signed_out,
        })
    }

    /// The issuer, `iss`.
    #[must_use]
    pub fn iss(&self) -> &Issuer {
        &self.iss
    }

    /// The app told, `aud`.
    #[must_use]
    pub fn aud(&self) -> &ClientId {
        &self.aud
    }

    /// When it was issued, `iat`.
    #[must_use]
    pub fn iat(&self) -> OffsetDateTime {
        self.iat
    }

    /// When it stops being accepted, `exp`.
    #[must_use]
    pub fn exp(&self) -> OffsetDateTime {
        self.exp
    }

    /// The unique issuance identifier used to detect replay of this logout notice.
    #[must_use]
    pub fn jti(&self) -> &TokenId {
        &self.jti
    }

    /// Who signed out: `sub`, and `sid` for one session.
    #[must_use]
    pub fn signed_out(&self) -> SignedOut {
        self.signed_out
    }
}

/// The page a person's browser loads to sign them out of an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontChannelVisit {
    /// None: the app takes no front-channel logout, or is revoked.
    NotRegistered,
    /// This page, with `iss` and `sid` when the app wants the session
    /// named.
    Visit(HttpsUrl),
}

/// The page that signs the person out of `client`, for `session` ending, at
/// `issuer`.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the page with the session named is
///   no longer a URL this server sends a browser to.
pub fn front_channel_visit<T: TenantScope>(
    client: &OAuthClient<T>,
    issuer: &Issuer,
    session: &SessionId,
) -> Result<FrontChannelVisit, DomainError> {
    let front_channel = &client.settings().logout.front_channel;
    let ChannelLogout::At {
        uri,
        session: named,
    } = front_channel
    else {
        return Ok(FrontChannelVisit::NotRegistered);
    };
    if !client.is_active() {
        return Ok(FrontChannelVisit::NotRegistered);
    }
    let page = match named {
        SessionRequired::NotRequired => uri.clone(),
        SessionRequired::Required => with_session(uri, issuer, session)?,
    };
    Ok(FrontChannelVisit::Visit(page))
}

/// `uri` with `iss` and `sid` added to its query.
fn with_session(
    uri: &HttpsUrl,
    issuer: &Issuer,
    session: &SessionId,
) -> Result<HttpsUrl, DomainError> {
    let mut url = Url::parse(uri.as_str()).map_err(|_| {
        DomainError::invalid(message!(
            "oauth-a-front-channel-page-must-be",
            "a front-channel page must be a URL"
        ))
    })?;
    url.query_pairs_mut()
        .append_pair("iss", issuer.as_str())
        .append_pair("sid", &session.to_string());
    Ok(HttpsUrl::new(url.as_str())?)
}

#[cfg(feature = "serde")]
mod json {
    //! The JSON a logout token's claims are written as.

    use std::collections::BTreeMap;

    use serde::ser::{Serialize, SerializeMap, Serializer};

    use crate::domains::oauth::grants::logout_notice::{LogoutTokenClaims, SignedOut};

    /// The event that says a token is a logout token.
    const BACK_CHANNEL_LOGOUT: &str = "http://schemas.openid.net/event/backchannel-logout";

    impl Serialize for LogoutTokenClaims {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let no_members: BTreeMap<&str, &str> = BTreeMap::new();
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("iss", self.iss.as_str())?;
            map.serialize_entry("aud", self.aud.as_str())?;
            map.serialize_entry("iat", &self.iat.unix_timestamp())?;
            map.serialize_entry("exp", &self.exp.unix_timestamp())?;
            map.serialize_entry("jti", self.jti.as_str())?;
            map.serialize_entry(
                "events",
                &BTreeMap::from([(BACK_CHANNEL_LOGOUT, no_members)]),
            )?;
            match self.signed_out {
                SignedOut::Session { person, session } => {
                    map.serialize_entry("sub", &person.to_string())?;
                    map.serialize_entry("sid", &session.to_string())?;
                }
                SignedOut::Everywhere { person } => {
                    map.serialize_entry("sub", &person.to_string())?;
                }
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
    use crate::domains::oauth::clients::settings::{ClientLogout, ClientSettings, SettingsChange};
    use crate::domains::oauth::control::tests::key_admin;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::label;
    use crate::types::{OAuthClientId, RedirectUri, TokenHash};

    /// An app hearing of sign-outs as `logout` says.
    fn app(logout: ClientLogout) -> OAuthClient<ResolvedTenant> {
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
                    logout,
                    ..ClientSettings::platform_defaults()
                },
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// A channel at `address`, wanting the session named or not.
    fn at(address: &str, session: SessionRequired) -> ChannelLogout {
        ChannelLogout::At {
            uri: HttpsUrl::new(address).unwrap(),
            session,
        }
    }

    /// An app told on the back channel, wanting the session named or not.
    fn back_channel(session: SessionRequired) -> OAuthClient<ResolvedTenant> {
        app(ClientLogout {
            back_channel: at("https://app.acme.com/backchannel", session),
            ..ClientLogout::none()
        })
    }

    /// The token telling `client` that Ann signed out as `signed_out` says.
    fn token(
        client: &OAuthClient<ResolvedTenant>,
        signed_out: SignedOut,
    ) -> Result<LogoutTokenClaims, DomainError> {
        LogoutTokenClaims::build(LogoutTokenParams {
            issuer: Issuer::new("https://auth.acme.com").unwrap(),
            client,
            signed_out,
            jti: TokenId::new("019f0000-0000-7000-8000-0000000000a6").unwrap(),
        })
    }

    /// Ann's session, ending.
    fn anns_session() -> SignedOut {
        SignedOut::Session {
            person: UserId::new(),
            session: SessionId::new(),
        }
    }

    /// Ann signs out of one session. The web app's token names it, for the
    /// web app, and is accepted for two minutes.
    #[test]
    fn a_logout_token_names_the_session_for_its_app() {
        let client = back_channel(SessionRequired::Required);
        let ended = anns_session();

        let claims = token(&client, ended).unwrap();

        assert_eq!(claims.aud().as_str(), "web_app");
        assert_eq!(claims.signed_out(), ended);
        assert_eq!(
            claims.exp(),
            claims.iat().saturating_add(LOGOUT_TOKEN_LIFETIME)
        );
    }

    /// An app that takes no back-channel logout gets no token.
    #[test]
    fn an_app_without_a_back_channel_gets_no_token() {
        let result = token(&app(ClientLogout::none()), anns_session());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// The app wants each session named, and Ann's account was locked out
    /// of all of them. One token for all is refused, so each session is
    /// sent its own.
    #[test]
    fn a_session_wanting_app_is_not_told_of_everywhere_at_once() {
        let named = back_channel(SessionRequired::Required);
        let unnamed = back_channel(SessionRequired::NotRequired);
        let everywhere = SignedOut::Everywhere {
            person: UserId::new(),
        };

        assert!(token(&named, everywhere).is_err());
        assert!(token(&unnamed, everywhere).is_ok());
    }

    /// A serialized logout token contains the back-channel event, subject and
    /// session claims, and omits the nonce used by ID tokens.
    #[cfg(feature = "serde")]
    #[test]
    fn a_logout_token_carries_the_event_and_no_nonce() {
        let claims = token(&back_channel(SessionRequired::Required), anns_session()).unwrap();

        let json = serde_json::to_value(&claims).unwrap();

        assert_eq!(
            json["events"]["http://schemas.openid.net/event/backchannel-logout"],
            serde_json::json!({})
        );
        assert!(json.get("nonce").is_none());
        assert!(json.get("sid").is_some());
        assert!(json.get("sub").is_some());
    }

    /// The front-channel page carries `iss` and `sid` when the app wants
    /// the session named, and is the page as registered otherwise.
    #[test]
    fn the_front_channel_page_names_the_session_when_asked() {
        let named = app(ClientLogout {
            front_channel: at("https://app.acme.com/fc", SessionRequired::Required),
            ..ClientLogout::none()
        });
        let issuer = Issuer::new("https://auth.acme.com").unwrap();
        let session = SessionId::new();

        let FrontChannelVisit::Visit(page) =
            front_channel_visit(&named, &issuer, &session).unwrap()
        else {
            panic!("the app registered a front channel");
        };

        assert!(page.as_str().contains(&format!("sid={session}")));
        assert!(page.as_str().contains("iss=https"));
    }

    /// Revoking an app makes its registered front-channel logout page
    /// unavailable for a browser visit.
    #[test]
    fn a_revoked_app_is_not_visited() {
        let mut client = app(ClientLogout {
            front_channel: at("https://app.acme.com/fc", SessionRequired::NotRequired),
            ..ClientLogout::none()
        });
        client.revoke(&key_admin()).unwrap();

        let visit = front_channel_visit(
            &client,
            &Issuer::new("https://auth.acme.com").unwrap(),
            &SessionId::new(),
        )
        .unwrap();

        assert_eq!(visit, FrontChannelVisit::NotRegistered);
    }

    /// An admin registers the app's back channel through an update; a
    /// logout token can then be built for it.
    #[test]
    fn a_back_channel_set_by_an_admin_takes_logout_tokens() {
        let mut client = app(ClientLogout::none());
        let logout = ClientLogout {
            back_channel: at("https://app.acme.com/bc", SessionRequired::Required),
            ..ClientLogout::none()
        };

        client
            .update(
                vec![OAuthClientChange::from(SettingsChange::Logout(logout))],
                &key_admin(),
            )
            .unwrap();

        assert!(token(&client, anns_session()).is_ok());
    }
}
