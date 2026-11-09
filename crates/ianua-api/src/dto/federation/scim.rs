//! SCIM switch bodies: turning a tenant's SCIM endpoint on and off, its
//! bearer token, and what it does with the users it creates and removes.

use ianua_app::use_cases::federation::scim::{ScimSettings, Status, SwitchedOn};
use ianua_domain::domains::federation::scim::{ScimActivation, ScimRemoval};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{RoleId, Setting};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// What SCIM does with the users it creates and removes.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ScimSettingsBody {
    /// The role every user SCIM creates starts with, on top of the tenant's
    /// defaults; `null` for none.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub default_role_id: Option<RoleId>,
    /// Whether users SCIM creates are active at once, rather than first
    /// confirming their address.
    #[schema(value_type = bool)]
    pub auto_activate: ScimActivation,
    /// Whether a user SCIM removes is deactivated and kept, rather than
    /// deleted.
    #[schema(value_type = bool)]
    pub deactivate_on_remove: ScimRemoval,
}

impl From<ScimSettingsBody> for ScimSettings {
    fn from(body: ScimSettingsBody) -> Self {
        Self {
            default_role_id: Setting::from_stored(body.default_role_id),
            auto_activate: body.auto_activate,
            deactivate_on_remove: body.deactivate_on_remove,
        }
    }
}

/// What SCIM does with the users it creates and removes, as set now.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ScimSettingsResponse {
    /// The role every user SCIM creates starts with, if any.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub default_role_id: Option<RoleId>,
    /// Whether users SCIM creates are active at once.
    pub auto_activate: bool,
    /// Whether a user SCIM removes is deactivated and kept.
    pub deactivate_on_remove: bool,
}

/// Whether the tenant's SCIM endpoint is set up and on, and how.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ScimStatusResponse {
    /// Whether SCIM was ever set up.
    pub configured: bool,
    /// Whether the endpoint takes requests now.
    pub enabled: bool,
    /// When a directory last synced, if ever.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_sync_at: Option<OffsetDateTime>,
    /// The SCIM base path a directory is configured with.
    pub scim_path: String,
    /// What SCIM does with users, once set up.
    pub settings: Option<ScimSettingsResponse>,
}

impl ScimStatusResponse {
    /// The status `status` reads, with the endpoint at `scim_path`.
    #[must_use]
    pub(crate) fn new(status: Status, scim_path: String) -> Self {
        let Status::SetUp(endpoint) = status else {
            return Self {
                configured: false,
                enabled: false,
                last_sync_at: None,
                scim_path,
                settings: None,
            };
        };
        Self {
            configured: true,
            enabled: endpoint.enabled(),
            last_sync_at: endpoint.last_sync_at(),
            scim_path,
            settings: Some(ScimSettingsResponse {
                default_role_id: endpoint.default_role_id().copied(),
                auto_activate: endpoint.auto_activate().into(),
                deactivate_on_remove: endpoint.deactivate_on_remove().into(),
            }),
        }
    }
}

/// The bearer token a directory calls the SCIM endpoint with.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ScimTokenResponse {
    /// The raw token, shown this once. `null` when SCIM was switched on
    /// again and keeps the token it had.
    pub bearer_token: Option<String>,
}

impl From<SwitchedOn> for ScimTokenResponse {
    fn from(switched: SwitchedOn) -> Self {
        match switched {
            SwitchedOn::SetUp(token) => Self::from(token),
            SwitchedOn::KeptToken => Self { bearer_token: None },
        }
    }
}

impl From<Secret> for ScimTokenResponse {
    fn from(token: Secret) -> Self {
        Self {
            bearer_token: Some(token.expose().to_owned()),
        }
    }
}
