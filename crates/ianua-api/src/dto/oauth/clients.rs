//! OAuth client bodies: registering, listing, changing a tenant's clients
//! and rotating their secrets, and the apps a person authorized.

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::oauth::OAuthClientSortField;
use ianua_app::use_cases::oauth::clients::credentials::ShownSecret;
use ianua_app::use_cases::oauth::clients::{
    AuthorizedApp, ClientFilter, CreateRequest, CreateResult, ListRequest, RotateSecretRequest,
    UpdateRequest,
};
use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Label, Lifetime, OAuthClientId, RedirectUri, RotationOverlap, Scope};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::oauth::metadata::{
    ClientSettingsBody, ClientSettingsView, ProvingBody, redirect_uris, uri_view,
};
use crate::error::ApiError;

/// Request body for registering an OAuth client.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateClientBody {
    /// The name people see.
    pub name: String,
    /// Where codes may be sent: HTTPS, a loopback address for a native
    /// app, or a private-use scheme.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Where people may be sent back after signing out through the client.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// The grants the client may use: `AuthorizationCode`,
    /// `ClientCredentials`, `RefreshToken`, `DeviceCode`, `TokenExchange`.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::grant_type_list)]
    pub grant_types: Vec<GrantType>,
    /// The scopes the client may ask for.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub scopes: Vec<Scope>,
    /// How the client proves itself.
    #[serde(flatten)]
    pub proving: ProvingBody,
    /// What it is set up with beyond the above.
    #[serde(default)]
    pub settings: ClientSettingsBody,
}

impl TryFrom<CreateClientBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateClientBody) -> Result<Self, ApiError> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            redirect_uris: redirect_uris(&body.redirect_uris)?,
            post_logout_redirect_uris: redirect_uris(&body.post_logout_redirect_uris)?,
            grant_types: body.grant_types,
            scopes: body.scopes,
            proving: body.proving.proving()?,
            settings: body.settings.settings()?,
        })
    }
}

/// Request body for changing an OAuth client. A field left out keeps its
/// value.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateClientBody {
    /// A new name.
    pub name: Option<String>,
    /// New redirect URIs.
    pub redirect_uris: Option<Vec<String>>,
    /// New addresses to send people back to after signing out.
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// New scopes.
    #[schema(value_type = Option<Vec<String>>)]
    pub scopes: Option<Vec<Scope>>,
    /// Settings to change.
    #[serde(default)]
    pub settings: ClientSettingsBody,
}

impl UpdateClientBody {
    /// The change to `client_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the name is not a valid label, an
    ///   address is not one a client may register, or a setting is not
    ///   valid.
    pub(crate) fn change_of(self, client_id: OAuthClientId) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            client_id,
            name: self
                .name
                .map(|name| Label::new("name", name))
                .transpose()
                .map_err(ApiError::validation)?,
            redirect_uris: self
                .redirect_uris
                .as_deref()
                .map(redirect_uris)
                .transpose()?,
            post_logout_redirect_uris: self
                .post_logout_redirect_uris
                .as_deref()
                .map(redirect_uris)
                .transpose()?,
            scopes: self.scopes,
            settings: self.settings.changes()?,
        })
    }
}

/// Query parameters for filtering an OAuth client listing.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ClientFilterParams {
    /// Filter by lifecycle status (`Active` or `Revoked`). Omit to return
    /// clients of any status.
    #[param(value_type = Option<String>)]
    pub status: Option<OAuthClientStatus>,
}

impl ClientFilterParams {
    /// The listing asked for: these clients, in `sort` order, the page
    /// `pagination` names.
    #[must_use]
    pub(crate) fn listing(
        self,
        sort: SortOrder<OAuthClientSortField>,
        pagination: PageRequest,
    ) -> ListRequest {
        ListRequest {
            filter: ClientFilter {
                status: self.status,
            },
            sort,
            page: pagination,
        }
    }
}

/// An OAuth client, without its secret.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ClientResponse {
    /// The client's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: OAuthClientId,
    /// The OAuth `client_id` the client names itself with.
    pub client_id: String,
    /// The name people see.
    pub name: String,
    /// `Active` or `Revoked`.
    #[schema(schema_with = crate::dto::schemas::o_auth_client_status)]
    pub status: OAuthClientStatus,
    /// Where codes may be sent.
    pub redirect_uris: Vec<String>,
    /// Where people may be sent back after signing out.
    pub post_logout_redirect_uris: Vec<String>,
    /// The grants it may use.
    #[schema(schema_with = crate::dto::schemas::grant_type_list)]
    pub grant_types: Vec<GrantType>,
    /// The scopes it may ask for.
    pub scopes: Vec<String>,
    /// How it proves itself at the token endpoint.
    pub token_endpoint_auth_method: &'static str,
    /// What it is set up with beyond the above.
    pub settings: ClientSettingsView,
    /// When it was registered.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<OAuthClient<ResolvedTenant>> for ClientResponse {
    fn from(client: OAuthClient<ResolvedTenant>) -> Self {
        Self {
            id: *client.id(),
            client_id: client.client_id_value().as_str().to_owned(),
            name: client.name().as_str().to_owned(),
            status: client.status(),
            redirect_uris: redirect_texts(client.redirect_uris()),
            post_logout_redirect_uris: redirect_texts(client.post_logout_redirect_uris()),
            grant_types: client.grant_types().to_vec(),
            scopes: texts(client.scopes().iter().map(Scope::as_str)),
            token_endpoint_auth_method: client.credential().method().as_str(),
            settings: ClientSettingsView::from(client.settings()),
            created_at: client.created_at(),
        }
    }
}

/// Each text of `items`, owned.
pub(crate) fn texts<'a>(items: impl Iterator<Item = &'a str>) -> Vec<String> {
    items.map(str::to_owned).collect()
}

/// Registered redirect addresses in the order they are presented to the client.
pub(crate) fn redirect_texts(uris: &[RedirectUri]) -> Vec<String> {
    texts(uris.iter().map(RedirectUri::as_str))
}

/// A client just registered, with its secret shown this once.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateClientResponse {
    /// The client's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: OAuthClientId,
    /// The OAuth `client_id` value external systems use.
    pub client_id: String,
    /// The raw client secret, shown once and never stored. Absent for a
    /// client that proves itself without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl From<CreateResult> for CreateClientResponse {
    fn from(result: CreateResult) -> Self {
        Self {
            id: result.client_id,
            client_id: result.client_id_value.as_str().to_owned(),
            client_secret: shown(result.secret),
        }
    }
}

/// The secret `secret` shows, if one was made.
pub(crate) fn shown(secret: ShownSecret) -> Option<String> {
    match secret {
        ShownSecret::NotIssued => None,
        ShownSecret::Shown(secret) => Some(secret.expose().to_owned()),
    }
}

/// Request body for rotating a client's secret.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RotateSecretBody {
    /// How long the old secret keeps working beside the new one, in
    /// seconds, at most thirty days. Left out or `0`, it stops at once.
    #[serde(default)]
    pub overlap_seconds: u32,
}

impl RotateSecretBody {
    /// The rotation of `client_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the overlap is not a valid lifetime.
    pub(crate) fn rotation_of(
        self,
        client_id: OAuthClientId,
    ) -> Result<RotateSecretRequest, ApiError> {
        let overlap = match self.overlap_seconds {
            0 => RotationOverlap::Immediate,
            seconds => RotationOverlap::For(
                Lifetime::seconds(i64::from(seconds)).map_err(ApiError::validation)?,
            ),
        };
        Ok(RotateSecretRequest { client_id, overlap })
    }
}

/// A client's new secret, shown this once.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RotatedSecretResponse {
    /// The new raw secret, shown once and never stored.
    pub client_secret: String,
}

impl From<Secret> for RotatedSecretResponse {
    fn from(secret: Secret) -> Self {
        Self {
            client_secret: secret.expose().to_owned(),
        }
    }
}

/// An app the signed-in person authorized.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuthorizedAppResponse {
    /// The client's id, by which the consent is withdrawn.
    #[schema(value_type = String, format = Uuid)]
    pub id: OAuthClientId,
    /// The OAuth `client_id` the app names itself with.
    pub client_id: String,
    /// The name people see.
    pub name: String,
    /// The image URL used to identify the app to the person who authorized it.
    pub logo_uri: Option<String>,
    /// How it treats people's data.
    pub policy_uri: Option<String>,
    /// Its terms of service.
    pub tos_uri: Option<String>,
    /// The scopes the person gave it.
    pub scopes: Vec<String>,
    /// When the person first gave it consent.
    #[serde(with = "time::serde::rfc3339")]
    pub granted_at: OffsetDateTime,
}

impl From<AuthorizedApp> for AuthorizedAppResponse {
    fn from(app: AuthorizedApp) -> Self {
        Self {
            id: app.client_id,
            client_id: app.client_id_value.as_str().to_owned(),
            name: app.name.as_str().to_owned(),
            logo_uri: uri_view(&app.links.logo),
            policy_uri: uri_view(&app.links.policy),
            tos_uri: uri_view(&app.links.terms),
            scopes: texts(app.scopes.iter().map(Scope::as_str)),
            granted_at: app.granted_at,
        }
    }
}
