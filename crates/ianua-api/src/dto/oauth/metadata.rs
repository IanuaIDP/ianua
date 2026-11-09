//! What a client is registered with, read from a body and shown back: how
//! it proves itself, the grant names of the standards, and its settings
//! (token lifetimes, the pages about it, consent, the form of its access
//! tokens, how it hears of sign-outs, and what its tokens are bound to).
//!
//! An admin's client and an app registering itself (RFC 7591) are read
//! with the same rules here; the app decides what each may set.

use ianua_app::use_cases::oauth::clients::credentials::ClientProving;
use ianua_domain::domains::oauth::clients::client::GrantType;
use ianua_domain::domains::oauth::clients::credential::{
    CertificateSubject, ClientJwks, ClientKeys, TokenEndpointAuthMethod,
};
use ianua_domain::domains::oauth::clients::lifetimes::{
    ClientTokenLifetimes, RefreshLifetimes, TokenTerms,
};
use ianua_domain::domains::oauth::clients::settings::{
    AccessTokenFormat, ChannelLogout, ClientLinks, ClientLogout, ClientSettings, ClientUri,
    ConsentPrompt, SessionRequired, SettingsChange,
};
use ianua_domain::domains::oauth::grants::token_binding::SenderConstraint;
use ianua_domain::message;
use ianua_domain::types::{HttpsUrl, Lifetime, RedirectUri};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// How a client proves itself, as a body names it (RFC 7591 2): the
/// method, and the keys or certificate subject it needs.
#[derive(Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct ProvingBody {
    /// `client_secret_basic` (the default), `client_secret_post`,
    /// `private_key_jwt`, `tls_client_auth` or `none` for a public client.
    pub token_endpoint_auth_method: Option<String>,
    /// The client's JWK Set, for `private_key_jwt`.
    #[schema(value_type = Option<Object>)]
    pub jwks: Option<serde_json::Value>,
    /// Where the client publishes its JWK Set, for `private_key_jwt`.
    pub jwks_uri: Option<String>,
    /// The subject its certificate carries, for `tls_client_auth`.
    pub tls_client_auth_subject_dn: Option<String>,
}

impl ProvingBody {
    /// How the client proves itself.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the method is unknown, or the keys
    ///   or subject it needs are missing or malformed.
    pub(crate) fn proving(&self) -> Result<ClientProving, ApiError> {
        let method = self
            .token_endpoint_auth_method
            .as_deref()
            .map_or(Ok(TokenEndpointAuthMethod::ClientSecretBasic), |name| {
                TokenEndpointAuthMethod::parse(name).map_err(ApiError::validation)
            })?;
        match method {
            TokenEndpointAuthMethod::ClientSecretBasic => Ok(ClientProving::SecretInHeader),
            TokenEndpointAuthMethod::ClientSecretPost => Ok(ClientProving::SecretInBody),
            TokenEndpointAuthMethod::PrivateKeyJwt => self.keys().map(ClientProving::SignedJwt),
            TokenEndpointAuthMethod::TlsClientAuth => {
                self.subject().map(ClientProving::Certificate)
            }
            TokenEndpointAuthMethod::None => Ok(ClientProving::Nothing),
        }
    }

    /// The keys a `private_key_jwt` client signs with: listed, or
    /// published at an address, not both.
    fn keys(&self) -> Result<ClientKeys, ApiError> {
        match (&self.jwks, &self.jwks_uri) {
            (Some(jwks), None) => ClientJwks::new(jwks.to_string())
                .map(ClientKeys::Listed)
                .map_err(ApiError::validation),
            (None, Some(uri)) => HttpsUrl::new(uri.as_str())
                .map(ClientKeys::Published)
                .map_err(ApiError::validation),
            (Some(_), Some(_)) => Err(ApiError::validation(message!(
                "api-send-jwks-or-jwks-uri-not",
                "send jwks or jwks_uri, not both"
            ))),
            (None, None) => Err(ApiError::validation(message!(
                "api-private-key-jwt-needs-the-client",
                "private_key_jwt needs the client's jwks or jwks_uri"
            ))),
        }
    }

    /// The subject a `tls_client_auth` client's certificate carries.
    fn subject(&self) -> Result<CertificateSubject, ApiError> {
        let subject = self.tls_client_auth_subject_dn.as_deref().ok_or_else(|| {
            ApiError::validation(message!(
                "api-tls-client-auth-needs-tls-client",
                "tls_client_auth needs tls_client_auth_subject_dn"
            ))
        })?;
        CertificateSubject::new(subject).map_err(ApiError::validation)
    }
}

/// How long a client's tokens last.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum TokenLifetimesBody {
    /// The platform's, as the deployment sets them.
    PlatformDefault,
    /// The client's own, each in seconds.
    Own {
        /// How long an access token lasts, at most a day.
        access_token_seconds: i64,
        /// How long an ID token lasts, at most a day.
        id_token_seconds: i64,
        /// How long a refresh token lasts unless used.
        refresh_idle_seconds: i64,
        /// How long a refresh token family lasts from its first token, at
        /// most ninety days.
        refresh_family_seconds: i64,
    },
}

impl TokenLifetimesBody {
    /// The lifetimes this body names.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when a lifetime is not positive, or
    ///   longer than allowed.
    pub(crate) fn lifetimes(&self) -> Result<ClientTokenLifetimes, ApiError> {
        let Self::Own {
            access_token_seconds,
            id_token_seconds,
            refresh_idle_seconds,
            refresh_family_seconds,
        } = *self
        else {
            return Ok(ClientTokenLifetimes::PlatformDefault);
        };
        let refresh = RefreshLifetimes::new(
            seconds(refresh_idle_seconds)?,
            seconds(refresh_family_seconds)?,
        )
        .map_err(ApiError::validation)?;
        TokenTerms::new(
            seconds(access_token_seconds)?,
            seconds(id_token_seconds)?,
            refresh,
        )
        .map(ClientTokenLifetimes::Own)
        .map_err(ApiError::validation)
    }
}

impl From<ClientTokenLifetimes> for TokenLifetimesBody {
    fn from(lifetimes: ClientTokenLifetimes) -> Self {
        let ClientTokenLifetimes::Own(terms) = lifetimes else {
            return Self::PlatformDefault;
        };
        Self::Own {
            access_token_seconds: terms.access().whole_seconds(),
            id_token_seconds: terms.id_token().whole_seconds(),
            refresh_idle_seconds: terms.refresh().idle().whole_seconds(),
            refresh_family_seconds: terms.refresh().family().whole_seconds(),
        }
    }
}

/// `count` seconds as a lifetime.
fn seconds(count: i64) -> Result<Lifetime, ApiError> {
    Lifetime::seconds(count).map_err(ApiError::validation)
}

/// Whether people are asked to consent to a client.
#[derive(Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentChoice {
    /// They are, the first time it asks for a scope.
    AskPerson,
    /// They are not: the tenant's own app. Only an admin sets it.
    FirstParty,
}

/// The form of a client's access tokens.
#[derive(Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TokenFormatChoice {
    /// A random string, checked by introspection.
    Opaque,
    /// A signed JWT a resource server checks on its own (RFC 9068).
    Jwt,
}

/// What a client's tokens are bound to.
#[derive(Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SenderChoice {
    /// Nothing required: bound to a `DPoP` key when one is proved.
    Bearer,
    /// Always a `DPoP` key.
    Dpop,
    /// Always the client's TLS certificate.
    Certificate,
}

/// A client's settings, as a body sends them. A field left out takes the
/// platform's default on a new client; on a change it is left as it is,
/// except that the three pages, and the two sign-out channels, are each
/// replaced together when any one of them is sent.
#[derive(Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct ClientSettingsBody {
    /// How long its tokens last.
    pub token_lifetimes: Option<TokenLifetimesBody>,
    /// Its logo, shown on the consent page.
    pub logo_uri: Option<String>,
    /// How it treats people's data.
    pub policy_uri: Option<String>,
    /// Its terms of service.
    pub tos_uri: Option<String>,
    /// Whether people are asked to consent.
    pub consent: Option<ConsentChoice>,
    /// The form of its access tokens.
    pub access_token_format: Option<TokenFormatChoice>,
    /// Where a logout token is posted when a person signs out.
    pub backchannel_logout_uri: Option<String>,
    /// Whether the logout token names the session.
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    /// The page loaded in the browser when a person signs out.
    pub frontchannel_logout_uri: Option<String>,
    /// Whether that page is told the issuer and session.
    #[serde(default)]
    pub frontchannel_logout_session_required: bool,
    /// What its tokens are bound to.
    pub sender_constraint: Option<SenderChoice>,
}

impl ClientSettingsBody {
    /// The settings of a new client.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when a lifetime or an address is not
    ///   valid.
    pub(crate) fn settings(&self) -> Result<ClientSettings, ApiError> {
        let defaults = ClientSettings::platform_defaults();
        Ok(ClientSettings {
            lifetimes: self
                .token_lifetimes
                .as_ref()
                .map_or(Ok(defaults.lifetimes), TokenLifetimesBody::lifetimes)?,
            links: self.links()?,
            consent: self.consent.map_or(defaults.consent, ConsentPrompt::from),
            token_format: self
                .access_token_format
                .map_or(defaults.token_format, AccessTokenFormat::from),
            logout: self.logout()?,
            sender_constraint: self
                .sender_constraint
                .map_or(defaults.sender_constraint, SenderConstraint::from),
        })
    }

    /// The changes this body makes to a client's settings.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when a lifetime or an address is not
    ///   valid.
    pub(crate) fn changes(&self) -> Result<Vec<SettingsChange>, ApiError> {
        let lifetimes = self
            .token_lifetimes
            .as_ref()
            .map(|body| body.lifetimes().map(SettingsChange::Lifetimes))
            .transpose()?;
        let links = self
            .sends_links()
            .then(|| self.links().map(SettingsChange::Links))
            .transpose()?;
        let logout = self
            .sends_logout()
            .then(|| self.logout().map(SettingsChange::Logout))
            .transpose()?;
        let consent = self.consent.map(|c| SettingsChange::Consent(c.into()));
        let format = self
            .access_token_format
            .map(|f| SettingsChange::TokenFormat(f.into()));
        let sender = self
            .sender_constraint
            .map(|s| SettingsChange::SenderConstraint(s.into()));
        Ok([lifetimes, links, logout, consent, format, sender]
            .into_iter()
            .flatten()
            .collect())
    }

    /// Whether any of the three pages is sent.
    fn sends_links(&self) -> bool {
        self.logo_uri.is_some() || self.policy_uri.is_some() || self.tos_uri.is_some()
    }

    /// Whether either sign-out channel is sent.
    fn sends_logout(&self) -> bool {
        self.backchannel_logout_uri.is_some() || self.frontchannel_logout_uri.is_some()
    }

    /// The pages about the client.
    fn links(&self) -> Result<ClientLinks, ApiError> {
        Ok(ClientLinks {
            logo: client_uri(self.logo_uri.as_deref())?,
            policy: client_uri(self.policy_uri.as_deref())?,
            terms: client_uri(self.tos_uri.as_deref())?,
        })
    }

    /// How the client hears of sign-outs.
    fn logout(&self) -> Result<ClientLogout, ApiError> {
        let session = |asked: bool| match asked {
            true => SessionRequired::Required,
            false => SessionRequired::NotRequired,
        };
        Ok(ClientLogout {
            back_channel: channel(
                self.backchannel_logout_uri.as_deref(),
                session(self.backchannel_logout_session_required),
            )?,
            front_channel: channel(
                self.frontchannel_logout_uri.as_deref(),
                session(self.frontchannel_logout_session_required),
            )?,
        })
    }
}

/// A page address a body sent, or none.
fn client_uri(raw: Option<&str>) -> Result<ClientUri, ApiError> {
    raw.map_or(Ok(ClientUri::NotGiven), |raw| {
        HttpsUrl::new(raw)
            .map(ClientUri::At)
            .map_err(ApiError::validation)
    })
}

/// A sign-out channel at `raw`, naming the session as `session` says.
fn channel(raw: Option<&str>, session: SessionRequired) -> Result<ChannelLogout, ApiError> {
    let Some(raw) = raw else {
        return Ok(ChannelLogout::NotRegistered);
    };
    Ok(ChannelLogout::At {
        uri: HttpsUrl::new(raw).map_err(ApiError::validation)?,
        session,
    })
}

impl From<ConsentChoice> for ConsentPrompt {
    fn from(choice: ConsentChoice) -> Self {
        match choice {
            ConsentChoice::AskPerson => Self::AskPerson,
            ConsentChoice::FirstParty => Self::FirstParty,
        }
    }
}

impl From<TokenFormatChoice> for AccessTokenFormat {
    fn from(choice: TokenFormatChoice) -> Self {
        match choice {
            TokenFormatChoice::Opaque => Self::Opaque,
            TokenFormatChoice::Jwt => Self::Jwt,
        }
    }
}

impl From<SenderChoice> for SenderConstraint {
    fn from(choice: SenderChoice) -> Self {
        match choice {
            SenderChoice::Bearer => Self::BearerAllowed,
            SenderChoice::Dpop => Self::DpopRequired,
            SenderChoice::Certificate => Self::CertificateRequired,
        }
    }
}

/// A client's settings, as they are shown.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ClientSettingsView {
    /// How long its tokens last.
    pub token_lifetimes: TokenLifetimesBody,
    /// The image URL presented when the client is shown to a person.
    pub logo_uri: Option<String>,
    /// How it treats people's data.
    pub policy_uri: Option<String>,
    /// Its terms of service.
    pub tos_uri: Option<String>,
    /// Whether people are asked to consent.
    pub consent: ConsentChoice,
    /// The form of its access tokens.
    pub access_token_format: TokenFormatChoice,
    /// Where a logout token is posted, if anywhere.
    pub backchannel_logout_uri: Option<String>,
    /// Whether the logout token names the session.
    pub backchannel_logout_session_required: bool,
    /// The page loaded on sign-out, if any.
    pub frontchannel_logout_uri: Option<String>,
    /// Whether that page is told the issuer and session.
    pub frontchannel_logout_session_required: bool,
    /// What its tokens are bound to.
    pub sender_constraint: SenderChoice,
}

impl From<&ClientSettings> for ClientSettingsView {
    fn from(settings: &ClientSettings) -> Self {
        let (back, back_session) = channel_view(&settings.logout.back_channel);
        let (front, front_session) = channel_view(&settings.logout.front_channel);
        Self {
            token_lifetimes: settings.lifetimes.into(),
            logo_uri: uri_view(&settings.links.logo),
            policy_uri: uri_view(&settings.links.policy),
            tos_uri: uri_view(&settings.links.terms),
            consent: match settings.consent {
                ConsentPrompt::AskPerson => ConsentChoice::AskPerson,
                ConsentPrompt::FirstParty => ConsentChoice::FirstParty,
            },
            access_token_format: match settings.token_format {
                AccessTokenFormat::Opaque => TokenFormatChoice::Opaque,
                AccessTokenFormat::Jwt => TokenFormatChoice::Jwt,
            },
            backchannel_logout_uri: back,
            backchannel_logout_session_required: back_session,
            frontchannel_logout_uri: front,
            frontchannel_logout_session_required: front_session,
            sender_constraint: match settings.sender_constraint {
                SenderConstraint::BearerAllowed => SenderChoice::Bearer,
                SenderConstraint::DpopRequired => SenderChoice::Dpop,
                SenderConstraint::CertificateRequired => SenderChoice::Certificate,
            },
        }
    }
}

/// A page address as shown.
pub(crate) fn uri_view(uri: &ClientUri) -> Option<String> {
    match uri {
        ClientUri::NotGiven => None,
        ClientUri::At(url) => Some(url.as_str().to_owned()),
    }
}

/// A sign-out channel as shown: its address, and whether it names the
/// session.
pub(crate) fn channel_view(channel: &ChannelLogout) -> (Option<String>, bool) {
    match channel {
        ChannelLogout::NotRegistered => (None, false),
        ChannelLogout::At { uri, session } => (
            Some(uri.as_str().to_owned()),
            *session == SessionRequired::Required,
        ),
    }
}

/// `uris` as redirect URIs: HTTPS, loopback or a private-use scheme.
///
/// # Errors
///
/// - [`ApiError::validation`] when one is not a redirect URI a client may
///   register.
pub fn redirect_uris(uris: &[String]) -> Result<Vec<RedirectUri>, ApiError> {
    uris.iter()
        .map(|uri| RedirectUri::new(uri.as_str()).map_err(ApiError::validation))
        .collect()
}

/// The name the standards give `grant` (RFC 7591 2, RFC 8628, RFC 8693).
#[must_use]
pub(crate) fn grant_name(grant: GrantType) -> &'static str {
    match grant {
        GrantType::AuthorizationCode => "authorization_code",
        GrantType::ClientCredentials => "client_credentials",
        GrantType::RefreshToken => "refresh_token",
        GrantType::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
        GrantType::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
    }
}

/// The grant the standards name `name`.
///
/// # Errors
///
/// - [`ApiError::validation`] when no grant offered here has that name.
pub(crate) fn grant_named(name: &str) -> Result<GrantType, ApiError> {
    [
        GrantType::AuthorizationCode,
        GrantType::ClientCredentials,
        GrantType::RefreshToken,
        GrantType::DeviceCode,
        GrantType::TokenExchange,
    ]
    .into_iter()
    .find(|grant| grant_name(*grant) == name)
    .ok_or_else(|| {
        ApiError::validation(message!(
            "api-is-not-a-grant-type-offered",
            format!("{name} is not a grant type offered here")
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client naming no method proves itself with a secret in the
    /// header, as RFC 7591 says.
    #[test]
    fn no_method_means_a_secret_in_the_header() {
        let Ok(proving) = ProvingBody::default().proving() else {
            panic!("no method reads");
        };

        assert_eq!(proving, ClientProving::SecretInHeader);
    }

    /// `private_key_jwt` without keys is refused.
    #[test]
    fn a_signing_client_without_keys_is_refused() {
        let body = ProvingBody {
            token_endpoint_auth_method: Some("private_key_jwt".to_owned()),
            ..ProvingBody::default()
        };

        assert!(body.proving().is_err());
    }

    /// Sending only a logo replaces the three pages together; nothing else
    /// changes.
    #[test]
    fn a_logo_alone_changes_the_pages_only() {
        let body = ClientSettingsBody {
            logo_uri: Some("https://acme.example/logo.png".to_owned()),
            ..ClientSettingsBody::default()
        };

        let Ok(changes) = body.changes() else {
            panic!("the change reads");
        };
        assert!(matches!(changes.as_slice(), [SettingsChange::Links(_)]));
    }

    /// Every grant reads back from the name the standards give it.
    #[test]
    fn grant_names_read_back() {
        for grant in [GrantType::DeviceCode, GrantType::TokenExchange] {
            assert_eq!(grant_named(grant_name(grant)).ok(), Some(grant));
        }
    }
}
