//! Session bodies: refreshing one, what a sign-in page offers, trusted
//! devices and break-glass grants.

use ianua_app::error::AppError;
use ianua_app::use_cases::authentication::sessions::break_glass::BreakGlassGrantRequest;
use ianua_app::use_cases::authentication::sessions::device_trust::{
    RevokeDeviceRequest, TrustDeviceRequest,
};
use ianua_app::use_cases::authentication::sessions::{
    RefreshSuccess, SignInOptions, TokenRefreshRequest,
};
use ianua_app::use_cases::identity::whose::Whose;
use ianua_domain::domains::authentication::device_status::DeviceStatus;
use ianua_domain::domains::authentication::device_trust::{DeviceSecret, TrustedDevice};
use ianua_domain::domains::authorization::break_glass::BreakGlassAccess;
use ianua_domain::domains::authorization::permission::{CustomPermission, SystemPermission};
use ianua_domain::domains::federation::connection::FederationProtocol;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    BreakGlassGrantId, ConnectionId, Label, SessionId, Text, TrustedDeviceId, UserAgent, UserId,
};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::extractors::callers::RequestMeta;

/// The refresh token traded for a new one.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct TokenRefreshBody {
    /// The current refresh token, spent by the trade.
    pub refresh_token: String,
}

impl TokenRefreshBody {
    /// The trade, for `user_id`'s session.
    #[must_use]
    pub(crate) fn request(self, user_id: UserId) -> TokenRefreshRequest {
        TokenRefreshRequest {
            refresh_token: Secret::new(self.refresh_token),
            user_id,
        }
    }
}

/// The session a refresh started.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TokenRefreshResponse {
    /// The new session.
    #[schema(value_type = String, format = Uuid)]
    pub session_id: SessionId,
    /// Its refresh token, shown this once.
    pub refresh_token: String,
}

impl From<RefreshSuccess> for TokenRefreshResponse {
    fn from(success: RefreshSuccess) -> Self {
        Self {
            session_id: success.session_id,
            refresh_token: success.refresh_token.expose().to_owned(),
        }
    }
}

/// What a tenant's sign-in page offers besides a password.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SignInOptionsResponse {
    /// Whether to offer "email me a sign-in link".
    pub magic_link: bool,
    /// Whether to offer "continue with a passkey".
    pub passkey: bool,
    /// The identity providers to offer as "Sign in with ..." buttons.
    pub connections: Vec<SignInConnectionResponse>,
}

/// One identity provider a sign-in page offers as a button.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SignInConnectionResponse {
    /// The connection to begin single sign-on with.
    #[schema(value_type = String, format = Uuid)]
    pub id: ConnectionId,
    /// The name to show on the button.
    pub name: String,
    /// The protocol it signs in with.
    #[schema(schema_with = crate::dto::schemas::federation_protocol)]
    pub protocol: FederationProtocol,
}

impl From<SignInOptions> for SignInOptionsResponse {
    fn from(options: SignInOptions) -> Self {
        Self {
            magic_link: options.magic_link,
            passkey: options.passkey,
            connections: options
                .connections
                .into_iter()
                .map(|connection| SignInConnectionResponse {
                    id: connection.id,
                    name: connection.name,
                    protocol: connection.protocol,
                })
                .collect(),
        }
    }
}

/// The caller's trusted devices.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DeviceListResponse {
    /// Every device they trusted, revoked ones included, oldest first.
    pub devices: Vec<DeviceEntry>,
}

impl From<Vec<TrustedDevice<ResolvedTenant>>> for DeviceListResponse {
    fn from(devices: Vec<TrustedDevice<ResolvedTenant>>) -> Self {
        Self {
            devices: devices.iter().map(DeviceEntry::from).collect(),
        }
    }
}

/// One trusted device.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DeviceEntry {
    /// The device's id.
    pub id: String,
    /// The name it is listed under.
    pub name: String,
    /// When it was trusted.
    pub created_at: String,
    /// `trusted`, or `revoked` once trust was taken back.
    pub status: String,
}

impl From<&TrustedDevice<ResolvedTenant>> for DeviceEntry {
    fn from(device: &TrustedDevice<ResolvedTenant>) -> Self {
        let status = match device.status() {
            DeviceStatus::Trusted => "trusted",
            DeviceStatus::Revoked => "revoked",
        };
        Self {
            id: device.id().to_string(),
            name: device.device_name().as_str().to_owned(),
            created_at: device.created_at().to_string(),
            status: status.to_owned(),
        }
    }
}

/// What the caller supplies to trust the device they are signing in from.
///
/// Carries no `ip` or `user_agent`: both are read from the request itself,
/// so the device list records where the trust was actually granted rather
/// than whatever the client chose to type.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct TrustDeviceBody {
    /// The secret this browser made for itself: 64 hex digits, presented at
    /// later sign-ins.
    pub fingerprint_hash: String,
    /// The name the device is listed under.
    pub device_name: String,
}

impl TrustDeviceBody {
    /// The trust, granted from where `meta` says the request came from.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a secret or name that is not well
    /// formed, or a request whose client address cannot be told.
    pub(crate) fn request(self, meta: RequestMeta) -> Result<TrustDeviceRequest, ApiError> {
        let Some(ip) = meta.ip_address else {
            return Err(ApiError::validation(message!(
                "api-this-request-has-no-resolvable-client",
                "this request has no resolvable client address, so there would be \
                 nothing to say about where the device was trusted from"
            )));
        };
        Ok(TrustDeviceRequest {
            secret: DeviceSecret::new(self.fingerprint_hash).map_err(ApiError::validation)?,
            device_name: Label::new("device_name", self.device_name)
                .map_err(ApiError::validation)?,
            user_agent: meta.user_agent.unwrap_or_else(UserAgent::unknown),
            ip,
        })
    }
}

/// The device a trust was granted to.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TrustDeviceResponse {
    /// The new device's id.
    pub device_id: String,
}

impl From<TrustedDeviceId> for TrustDeviceResponse {
    fn from(device_id: TrustedDeviceId) -> Self {
        Self {
            device_id: device_id.to_string(),
        }
    }
}

/// The device whose trust is taken back.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RevokeDeviceBody {
    /// The device's id.
    pub device_id: String,
}

impl RevokeDeviceBody {
    /// The signed-in person forgetting their own device named.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an id that is not a UUID.
    pub(crate) fn own(&self) -> Result<RevokeDeviceRequest, ApiError> {
        let device_id = self
            .device_id
            .parse::<uuid::Uuid>()
            .map(TrustedDeviceId::from_uuid)
            .map_err(|_| {
                ApiError::validation(message!("api-invalid-device-id", "invalid device_id"))
            })?;
        Ok(RevokeDeviceRequest {
            whose: Whose::Own,
            device_id,
        })
    }
}

/// A request to open a break-glass grant.
///
/// There is no `approved_by`: the approver is whoever made this call, taken
/// from the session. A body-supplied approver is a field the requester
/// fills in about themselves, which is the opposite of what an approval
/// record is for.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct BreakGlassBody {
    /// The user who gets the access.
    pub user_id: String,
    /// Why it is needed, kept in the audit trail.
    pub reason: String,
    /// How long it lasts, in seconds.
    pub duration_seconds: i64,
    /// The built-in permissions it grants, such as `{"Users": "View"}`.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub system_permissions: Vec<SystemPermission>,
    /// The app-defined permissions it grants, such as `"invoices:approve"`.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub custom_permissions: Vec<CustomPermission>,
}

impl TryFrom<BreakGlassBody> for BreakGlassGrantRequest {
    type Error = ApiError;

    fn try_from(body: BreakGlassBody) -> Result<Self, Self::Error> {
        let user_id = body
            .user_id
            .parse::<uuid::Uuid>()
            .map(UserId::from_uuid)
            .map_err(|_| {
                ApiError::validation(message!("api-invalid-user-id", "invalid user_id"))
            })?;
        Ok(Self {
            user_id,
            access: BreakGlassAccess::new(body.system_permissions, body.custom_permissions)
                .map_err(|refused| ApiError(AppError::from_domain(refused)))?,
            reason: Text::new("reason", body.reason).map_err(ApiError::validation)?,
            duration_seconds: body.duration_seconds,
        })
    }
}

/// The grant a break-glass request opened.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct BreakGlassGrantResponse {
    /// The new grant's id.
    pub grant_id: String,
}

impl From<BreakGlassGrantId> for BreakGlassGrantResponse {
    fn from(grant_id: BreakGlassGrantId) -> Self {
        Self {
            grant_id: grant_id.to_string(),
        }
    }
}

/// The grant closed early.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct BreakGlassRevokeBody {
    /// The grant's id.
    pub grant_id: String,
}

impl BreakGlassRevokeBody {
    /// The grant named.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an id that is not a UUID.
    pub(crate) fn grant(&self) -> Result<BreakGlassGrantId, ApiError> {
        self.grant_id
            .parse::<uuid::Uuid>()
            .map(BreakGlassGrantId::from_uuid)
            .map_err(|_| ApiError::validation(message!("api-invalid-grant-id", "invalid grant_id")))
    }
}
