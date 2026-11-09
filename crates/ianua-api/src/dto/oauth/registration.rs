//! Apps registering themselves (RFC 7591) and managing their registration
//! (RFC 7592), in the standards' own names, and the initial access tokens a
//! tenant hands out so they may.

use ianua_app::use_cases::oauth::registration::{
    ClientMetadata, IssueInitialAccessTokenRequest, IssuedInitialAccessToken, RegisteredClient,
};
use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient, OAuthClientChange};
use ianua_domain::domains::oauth::clients::credential::{ClientCredential, ClientKeys};
use ianua_domain::domains::oauth::clients::registration::InitialAccessToken;
use ianua_domain::domains::oauth::clients::settings::{ClientSettings, SettingsChange};
use ianua_domain::domains::oauth::grants::token_binding::SenderConstraint;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{InitialAccessTokenId, Issuer, Label, Lifetime, RedirectUri, Scope};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::oauth::clients::{redirect_texts, shown, texts};
use crate::dto::oauth::metadata::{
    ClientSettingsBody, ProvingBody, SenderChoice, channel_view, grant_name, grant_named, uri_view,
};
use crate::error::oauth::RegistrationError;
use crate::error::{ApiError, public_message};

/// What an app registers itself with (RFC 7591 2), in the standard's
/// names. A field left out takes the standard's default.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RegistrationBody {
    /// Where codes may be sent: HTTPS, a loopback address for a native
    /// app, or a private-use scheme.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Where people may be sent back after signing out through the app.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// The name people see on the consent page.
    pub client_name: Option<String>,
    /// The grants it may use; `authorization_code` when left out. An app
    /// registering itself may not use `client_credentials` or token
    /// exchange.
    pub grant_types: Option<Vec<String>>,
    /// What it asks to be handed back; only `code`.
    pub response_types: Option<Vec<String>>,
    /// The scopes it may ask for, separated by spaces.
    pub scope: Option<String>,
    /// How it proves itself at the token endpoint.
    #[serde(flatten)]
    pub proving: ProvingBody,
    /// Its logo, shown on the consent page.
    pub logo_uri: Option<String>,
    /// How it treats people's data.
    pub policy_uri: Option<String>,
    /// Its terms of service.
    pub tos_uri: Option<String>,
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
    /// Whether its access tokens are bound to a `DPoP` key (RFC 9449 5.2).
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    /// Whether its access tokens are bound to its TLS certificate (RFC
    /// 8705 2.4).
    #[serde(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
}

impl RegistrationBody {
    /// What the app registers with.
    ///
    /// # Errors
    ///
    /// - `invalid_redirect_uri` when an address is not one a client may
    ///   register.
    /// - `invalid_client_metadata` when anything else is malformed or not
    ///   offered.
    pub(crate) fn metadata(self) -> Result<ClientMetadata, RegistrationError> {
        self.ensure_code_only()?;
        Ok(ClientMetadata {
            name: self.name()?,
            redirect_uris: addresses(&self.redirect_uris)?,
            post_logout_redirect_uris: addresses(&self.post_logout_redirect_uris)?,
            grant_types: self.grants()?,
            scopes: self.scopes()?,
            proving: self
                .proving
                .proving()
                .map_err(|error| metadata_error(&error))?,
            settings: self
                .settings()
                .settings()
                .map_err(|error| metadata_error(&error))?,
        })
    }

    /// The changes to its registration the app asks for (RFC 7592 2.2):
    /// what the body leaves out is cleared, as a replacement does. Its
    /// grants and how it proves itself stay as registered.
    ///
    /// # Errors
    ///
    /// - The cases [`Self::metadata`] lists.
    pub(crate) fn changes(self) -> Result<Vec<OAuthClientChange>, RegistrationError> {
        self.ensure_code_only()?;
        let settings = self
            .settings()
            .settings()
            .map_err(|error| metadata_error(&error))?;
        Ok(vec![
            OAuthClientChange::Rename(self.name()?),
            OAuthClientChange::RedirectTo(addresses(&self.redirect_uris)?),
            OAuthClientChange::AfterLogoutTo(addresses(&self.post_logout_redirect_uris)?),
            OAuthClientChange::Scopes(self.scopes()?),
            SettingsChange::Links(settings.links).into(),
            SettingsChange::Logout(settings.logout).into(),
            SettingsChange::SenderConstraint(settings.sender_constraint).into(),
        ])
    }

    /// Refuses a request for anything but a code.
    fn ensure_code_only(&self) -> Result<(), RegistrationError> {
        let Some(types) = &self.response_types else {
            return Ok(());
        };
        if types.iter().all(|kind| kind == "code") {
            return Ok(());
        }
        Err(RegistrationError::InvalidMetadata(
            "only the code response type is offered".to_owned(),
        ))
    }

    /// The name people see.
    fn name(&self) -> Result<Label, RegistrationError> {
        let name = self.client_name.as_deref().ok_or_else(|| {
            RegistrationError::InvalidMetadata("client_name is required".to_owned())
        })?;
        Label::new("client_name", name)
            .map_err(|e| RegistrationError::InvalidMetadata(e.to_string()))
    }

    /// The grants it asks for.
    fn grants(&self) -> Result<Vec<GrantType>, RegistrationError> {
        let Some(names) = &self.grant_types else {
            return Ok(vec![GrantType::AuthorizationCode]);
        };
        names
            .iter()
            .map(|name| grant_named(name).map_err(|error| metadata_error(&error)))
            .collect()
    }

    /// The scopes it may ask for.
    fn scopes(&self) -> Result<Vec<Scope>, RegistrationError> {
        self.scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(|scope| {
                Scope::new(scope).map_err(|e| RegistrationError::InvalidMetadata(e.to_string()))
            })
            .collect()
    }

    /// What its tokens are bound to.
    fn sender(&self) -> SenderChoice {
        match (
            self.dpop_bound_access_tokens,
            self.tls_client_certificate_bound_access_tokens,
        ) {
            (_, true) => SenderChoice::Certificate,
            (true, false) => SenderChoice::Dpop,
            (false, false) => SenderChoice::Bearer,
        }
    }

    /// Its settings, as an admin's body would send them: the pages, the
    /// sign-out channels and what its tokens are bound to. Lifetimes,
    /// consent and the token format stay the platform's.
    fn settings(&self) -> ClientSettingsBody {
        ClientSettingsBody {
            logo_uri: self.logo_uri.clone(),
            policy_uri: self.policy_uri.clone(),
            tos_uri: self.tos_uri.clone(),
            backchannel_logout_uri: self.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            frontchannel_logout_uri: self.frontchannel_logout_uri.clone(),
            frontchannel_logout_session_required: self.frontchannel_logout_session_required,
            sender_constraint: Some(self.sender()),
            ..ClientSettingsBody::default()
        }
    }
}

/// `uris` as redirect URIs.
fn addresses(uris: &[String]) -> Result<Vec<RedirectUri>, RegistrationError> {
    uris.iter()
        .map(|uri| {
            RedirectUri::new(uri.as_str())
                .map_err(|e| RegistrationError::InvalidRedirectUri(e.to_string()))
        })
        .collect()
}

/// A body refused as malformed metadata.
fn metadata_error(error: &ApiError) -> RegistrationError {
    RegistrationError::InvalidMetadata(public_message(&error.0))
}

/// A registered client's metadata, in the standards' names (RFC 7591
/// 3.2.1, RFC 7592 3).
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RegisteredClientResponse {
    /// The client id it names itself with.
    pub client_id: String,
    /// Its secret, shown once, at registration only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// When the secret expires: `0`, never.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    /// When it was registered, in seconds since the epoch.
    pub client_id_issued_at: i64,
    /// The token it manages its registration with, shown once, at
    /// registration only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    /// Where it manages its registration.
    pub registration_client_uri: String,
    /// The name people see.
    pub client_name: String,
    /// Where codes may be sent.
    pub redirect_uris: Vec<String>,
    /// Where people may be sent back after signing out.
    pub post_logout_redirect_uris: Vec<String>,
    /// The grants it may use.
    pub grant_types: Vec<&'static str>,
    /// What it may ask to be handed back.
    pub response_types: Vec<&'static str>,
    /// The scopes it may ask for, separated by spaces.
    pub scope: String,
    /// How it proves itself at the token endpoint.
    pub token_endpoint_auth_method: &'static str,
    /// Where it publishes its keys, for `private_key_jwt`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// The registered image URL presented when the client is shown to a person.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    /// How it treats people's data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    /// Its terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    /// Where a logout token is posted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    /// Whether the logout token names the session.
    pub backchannel_logout_session_required: bool,
    /// The page loaded on sign-out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    /// Whether that page is told the issuer and session.
    pub frontchannel_logout_session_required: bool,
    /// Whether its access tokens are bound to a `DPoP` key.
    pub dpop_bound_access_tokens: bool,
    /// Whether its access tokens are bound to its TLS certificate.
    pub tls_client_certificate_bound_access_tokens: bool,
}

impl RegisteredClientResponse {
    /// The metadata of `client`, managed at the registration endpoint of
    /// the tenant `issuer` names.
    #[must_use]
    pub(crate) fn of(client: &OAuthClient<ResolvedTenant>, issuer: &Issuer) -> Self {
        let settings: &ClientSettings = client.settings();
        let (back, back_session) = channel_view(&settings.logout.back_channel);
        let (front, front_session) = channel_view(&settings.logout.front_channel);
        let client_id = client.client_id_value().as_str();
        Self {
            client_id: client_id.to_owned(),
            client_secret: None,
            client_secret_expires_at: None,
            client_id_issued_at: client.created_at().unix_timestamp(),
            registration_access_token: None,
            registration_client_uri: format!("{}/oauth/register/{client_id}", issuer.as_str()),
            client_name: client.name().as_str().to_owned(),
            redirect_uris: redirect_texts(client.redirect_uris()),
            post_logout_redirect_uris: redirect_texts(client.post_logout_redirect_uris()),
            grant_types: grant_names(client.grant_types()),
            response_types: response_types(client.grant_types()),
            scope: texts(client.scopes().iter().map(Scope::as_str)).join(" "),
            token_endpoint_auth_method: client.credential().method().as_str(),
            jwks_uri: published_keys(client.credential()),
            logo_uri: uri_view(&settings.links.logo),
            policy_uri: uri_view(&settings.links.policy),
            tos_uri: uri_view(&settings.links.terms),
            backchannel_logout_uri: back,
            backchannel_logout_session_required: back_session,
            frontchannel_logout_uri: front,
            frontchannel_logout_session_required: front_session,
            dpop_bound_access_tokens: settings.sender_constraint == SenderConstraint::DpopRequired,
            tls_client_certificate_bound_access_tokens: settings.sender_constraint
                == SenderConstraint::CertificateRequired,
        }
    }

    /// The answer to a registration: the metadata, with the secret and the
    /// registration access token shown this once.
    #[must_use]
    pub(crate) fn registered(registered: RegisteredClient, issuer: &Issuer) -> Self {
        let secret = shown(registered.secret);
        Self {
            client_secret_expires_at: secret.as_ref().map(|_| 0),
            client_secret: secret,
            registration_access_token: Some(
                registered.registration_access_token.expose().to_owned(),
            ),
            ..Self::of(&registered.client, issuer)
        }
    }
}

/// The protocol spelling of each allowed grant, preserving registration order.
fn grant_names(grants: &[GrantType]) -> Vec<&'static str> {
    grants.iter().copied().map(grant_name).collect()
}

/// What a client with `grants` may ask to be handed back.
fn response_types(grants: &[GrantType]) -> Vec<&'static str> {
    if grants.contains(&GrantType::AuthorizationCode) {
        return vec!["code"];
    }
    Vec::new()
}

/// Where a `private_key_jwt` client publishes its keys, if it does.
fn published_keys(credential: &ClientCredential) -> Option<String> {
    match credential {
        ClientCredential::PrivateKeyJwt(ClientKeys::Published(url)) => {
            Some(url.as_str().to_owned())
        }
        _ => None,
    }
}

/// Request body for issuing an initial access token.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct IssueInitialAccessTokenBody {
    /// What it is for, such as `MCP clients`.
    pub name: String,
    /// How many apps may register with it, from 1 to 1000.
    #[serde(default = "one_use")]
    pub uses: u32,
    /// How long it works, in seconds, at most thirty days.
    pub expires_in_seconds: i64,
}

/// The uses a token allows when the body names none.
fn one_use() -> u32 {
    1
}

impl TryFrom<IssueInitialAccessTokenBody> for IssueInitialAccessTokenRequest {
    type Error = ApiError;

    fn try_from(body: IssueInitialAccessTokenBody) -> Result<Self, ApiError> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            uses: body.uses,
            lifetime: Lifetime::seconds(body.expires_in_seconds).map_err(ApiError::validation)?,
        })
    }
}

/// An initial access token just issued, shown this once.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct IssuedInitialAccessTokenResponse {
    /// The handle used to manage this registration credential after issuance.
    #[schema(value_type = String, format = Uuid)]
    pub id: InitialAccessTokenId,
    /// The raw token, shown once and never stored. An app sends it as
    /// `Authorization: Bearer` when it registers.
    pub token: String,
    /// When it stops working.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl From<IssuedInitialAccessToken> for IssuedInitialAccessTokenResponse {
    fn from(issued: IssuedInitialAccessToken) -> Self {
        Self {
            id: issued.id,
            token: issued.token.expose().to_owned(),
            expires_at: issued.expires_at,
        }
    }
}

/// An initial access token, without the token itself.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct InitialAccessTokenResponse {
    /// The handle used to identify this registration credential without revealing it.
    #[schema(value_type = String, format = Uuid)]
    pub id: InitialAccessTokenId,
    /// What it is for.
    pub name: String,
    /// How many registrations it still allows.
    pub uses_left: u32,
    /// When it was issued.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it stops working.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// When it was revoked, if it was.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

impl From<InitialAccessToken<ResolvedTenant>> for InitialAccessTokenResponse {
    fn from(token: InitialAccessToken<ResolvedTenant>) -> Self {
        Self {
            id: *token.id(),
            name: token.name().as_str().to_owned(),
            uses_left: token.uses_left(),
            created_at: token.created_at(),
            expires_at: token.expires_at(),
            revoked_at: token.revocation().revoked_at(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest registration: a name and a redirect.
    fn minimal() -> RegistrationBody {
        serde_json::from_value(serde_json::json!({
            "client_name": "MCP tool",
            "redirect_uris": ["http://127.0.0.1:8123/callback"]
        }))
        .unwrap()
    }

    /// A registration naming no grant asks for the code flow, with a
    /// secret in the header, as RFC 7591 says.
    #[test]
    fn a_minimal_registration_takes_the_standards_defaults() {
        let Ok(metadata) = minimal().metadata() else {
            panic!("the registration reads");
        };

        assert_eq!(metadata.grant_types, vec![GrantType::AuthorizationCode]);
        assert_eq!(metadata.redirect_uris.len(), 1);
    }

    /// A malformed registration redirect maps to invalid_redirect_uri.
    #[test]
    fn a_malformed_redirect_is_told_as_such() {
        let body = RegistrationBody {
            redirect_uris: vec!["not a uri".to_owned()],
            ..minimal()
        };

        assert!(matches!(
            body.metadata(),
            Err(RegistrationError::InvalidRedirectUri(_))
        ));
    }

    /// A grant this server does not offer is invalid metadata.
    #[test]
    fn an_unknown_grant_is_invalid_metadata() {
        let body = RegistrationBody {
            grant_types: Some(vec!["implicit".to_owned()]),
            ..minimal()
        };

        assert!(matches!(
            body.metadata(),
            Err(RegistrationError::InvalidMetadata(_))
        ));
    }
}
