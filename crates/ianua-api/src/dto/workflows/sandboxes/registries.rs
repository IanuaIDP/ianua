//! Image registries on the wire: the body that allows one, with the login
//! its images are pulled with, and a registry as listed, which never shows
//! the password.

use ianua_app::use_cases::workflows::sandboxes::images::registries::{AllowRequest, WrittenLogin};
use ianua_domain::domains::workflows::sandbox::image::RegistryHost;
use ianua_domain::domains::workflows::sandbox::registry::{
    ImageRegistry, RegistryLogin, RegistryUsername,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::security::secret::Secret;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::workflows::data::person_label;
use crate::error::ApiError;

/// Request body for allowing an image registry.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AllowRegistryBody {
    /// The registry's host, with an optional port, such as
    /// `registry.acme.example`.
    pub host: String,
    /// The user images are pulled as; left out, with `password`, for a
    /// registry that serves its images to anyone.
    #[serde(default)]
    pub username: Option<String>,
    /// The password or token images are pulled with. It is sealed before
    /// it is kept and never shown again.
    #[serde(default)]
    pub password: Option<String>,
}

impl TryFrom<AllowRegistryBody> for AllowRequest {
    type Error = ApiError;

    fn try_from(body: AllowRegistryBody) -> Result<Self, ApiError> {
        Ok(Self {
            host: RegistryHost::new(body.host).map_err(ApiError::validation)?,
            login: written_login(body.username, body.password)?,
        })
    }
}

/// The login `username` and `password` give: both, or neither.
fn written_login(
    username: Option<String>,
    password: Option<String>,
) -> Result<WrittenLogin, ApiError> {
    match (username, password) {
        (None, None) => Ok(WrittenLogin::Anonymous),
        (Some(username), Some(password)) if !password.is_empty() => Ok(WrittenLogin::Password {
            username: RegistryUsername::new(username).map_err(ApiError::validation)?,
            password: Secret::new(password),
        }),
        _ => Err(ApiError::validation(DomainError::invalid(message!(
            "workflows-a-registry-login-is-a-user-and-a-password",
            "give the registry's user and password together, or neither"
        )))),
    }
}

/// An image registry the tenant allowed.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RegistryResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The registry's host.
    pub host: String,
    /// How images are pulled from it: `anonymous`, or `password` with a
    /// login kept sealed.
    pub login: String,
    /// The user images are pulled as; absent for `anonymous`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The administrator who allowed it, as `<kind>:<uuid>`.
    pub allowed_by: String,
    /// When it was allowed.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<ImageRegistry<ResolvedTenant>> for RegistryResponse {
    fn from(registry: ImageRegistry<ResolvedTenant>) -> Self {
        let username = match registry.login() {
            RegistryLogin::Anonymous => None,
            RegistryLogin::Password { username, .. } => Some(username.as_str().to_owned()),
        };
        Self {
            id: *registry.id().as_uuid(),
            host: registry.host().as_str().to_owned(),
            login: registry.login().as_str().to_owned(),
            username,
            allowed_by: person_label(registry.allowed_by()),
            created_at: registry.created_at(),
        }
    }
}
