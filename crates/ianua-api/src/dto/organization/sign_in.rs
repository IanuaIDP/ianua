//! Organization sign-in bodies: password login and the organization
//! chooser, mailed sign-in links, the emailed confirmation, sessions,
//! remembered devices and moving between tenants.

use ianua_app::services::authentication::sign_in_gate::ClientOrigin;
use ianua_app::use_cases::organization::sign_in::{
    ActiveSessionInfo, LandedTenant, LinkedSwitchSuccess, MovedOrgSession, OfferedOrganization,
    OrgConfirmRequest, OrgConfirmed, OrgLoginOutcome, OrgLoginSuccess, OrgMagicLinkRequest,
    OrgPasswordLoginRequest, OrganizationChoice, TrustOrgDeviceRequest,
};
use ianua_domain::domains::authentication::device_status::DeviceStatus;
use ianua_domain::domains::authentication::device_trust::{DeviceSecret, TrustedDevice};
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    Email, Fact, Label, OrganizationId, SessionId, TenantId, TenantSlug, TrustedDeviceId,
    UserAgent, UserId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dto::authentication::password::challenge_proof_of;
use crate::dto::organization::members::OrgUserAccessResponse;
use crate::error::ApiError;
use crate::extractors::callers::RequestMeta;

/// Request body for signing an organization member in with a password.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgLoginBody {
    /// The email address to authenticate.
    pub email: String,
    /// The password to verify.
    pub password: String,
    /// The slug of the organization to sign in to, picked from those an
    /// earlier answer of `choose_organization` offered. Leave it out at
    /// first: every organization holding the address is tried.
    #[serde(default)]
    pub organization: Option<String>,
    /// The tenant to sign in to. Without it the session lands in the first
    /// active tenant the member reaches.
    #[serde(default)]
    pub tenant_slug: Option<String>,
    /// The secret of a device the member remembered, if the client holds
    /// one: 64 hex digits the browser made for itself.
    ///
    /// Matching a device the member already remembered is what lets the
    /// organization's step-up policy skip a second factor. Absent,
    /// unrecognised and forgotten all mean the same thing: challenge them.
    #[serde(default)]
    pub fingerprint_hash: Option<String>,
    /// The proof that this browser passed the challenge an earlier answer
    /// asked for (`challenge_required`), while sign-in is under pressure.
    /// Leave it out otherwise.
    #[serde(default)]
    pub challenge_proof: Option<String>,
}

impl OrgLoginBody {
    /// The sign-in this body asks for, from where `meta` says the request
    /// came.
    ///
    /// # Errors
    ///
    /// `422` when the address, a slug, the device secret or the challenge
    /// proof is malformed.
    pub(crate) fn into_request(
        self,
        meta: RequestMeta,
    ) -> Result<OrgPasswordLoginRequest, ApiError> {
        Ok(OrgPasswordLoginRequest {
            email: Email::new(&self.email).map_err(ApiError::validation)?,
            password: Secret::new(self.password),
            organization: organization_choice(self.organization)?,
            tenant_slug: slug_of(self.tenant_slug)?,
            device_secret: self
                .fingerprint_hash
                .map(DeviceSecret::new)
                .transpose()
                .map_err(ApiError::validation)?,
            challenge: challenge_proof_of(self.challenge_proof)?,
            origin: origin_of(meta),
        })
    }
}

/// Where a sign-in request came from, as the request arrived.
#[must_use]
pub(crate) fn origin_of(meta: RequestMeta) -> ClientOrigin {
    ClientOrigin {
        ip_address: Fact::from_option(meta.ip_address),
        user_agent: meta.user_agent,
    }
}

/// `raw` as a slug, when one is given.
///
/// # Errors
///
/// `422` when it is not a valid slug.
pub(crate) fn slug_of(raw: Option<String>) -> Result<Option<TenantSlug>, ApiError> {
    raw.map(|slug| TenantSlug::new(&slug, &SlugLimits::default()))
        .transpose()
        .map_err(ApiError::validation)
}

/// The organization a sign-in names, or none.
fn organization_choice(raw: Option<String>) -> Result<OrganizationChoice, ApiError> {
    Ok(slug_of(raw)?.map_or(OrganizationChoice::Unnamed, OrganizationChoice::Named))
}

/// What a sign-in still owes before its session is let in.
struct Owed {
    mfa_required: bool,
    mfa_enrollment_required: bool,
    email_confirmation_required: bool,
}

impl From<SecondFactor> for Owed {
    fn from(owed: SecondFactor) -> Self {
        let (mfa_required, mfa_enrollment_required, email_confirmation_required) = match owed {
            SecondFactor::NotOwed => (false, false, false),
            SecondFactor::Verify => (true, false, false),
            SecondFactor::Enrol => (true, true, false),
            SecondFactor::ConfirmByEmail | SecondFactor::ConfirmThenEnrol => (true, false, true),
        };
        Self {
            mfa_required,
            mfa_enrollment_required,
            email_confirmation_required,
        }
    }
}

/// The session a member's sign-in opened.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(tag = "status")]
pub(crate) enum OrgLoginResponse {
    /// Authentication succeeded: a session was opened.
    #[serde(rename = "authenticated")]
    Authenticated {
        /// The newly created session ID.
        #[schema(value_type = String)]
        session_id: SessionId,
        /// The raw refresh token, shown this once.
        refresh_token: String,
        /// Whether the session owes more before it is let in: a code from
        /// the member's second factor (`…/mfa/verify`), a factor to set up,
        /// or a confirmation from their mailbox.
        mfa_required: bool,
        /// Whether the member has no second factor and must set one up
        /// first, with `…/mfa/begin` and `…/mfa/confirm` (passing this
        /// `session_id` to confirm). Always `false` when `mfa_required` is
        /// `false`.
        mfa_enrollment_required: bool,
        /// Whether a link was mailed to the member's address and the
        /// session waits for it to be followed (`/api/v1/login/confirm`).
        /// Always `false` when `mfa_required` is `false`.
        email_confirmation_required: bool,
        /// The tenant the session works in. `null` when the member reaches
        /// no tenant: a billing contact, a viewer, or a member nobody
        /// granted a tenant yet. Their session works on the organization
        /// alone.
        #[schema(value_type = Option<String>)]
        tenant_id: Option<TenantId>,
        /// The member's organization.
        #[schema(value_type = String)]
        organization_id: OrganizationId,
        /// The tenant's URL slug, `null` when the session works in no
        /// tenant.
        tenant_slug: Option<String>,
        /// The organization's URL slug.
        org_slug: String,
        /// The organization's display name.
        organization_name: String,
        /// The member's display name.
        display_name: String,
        /// What this member reaches: their org role, the tenants they can
        /// enter, and their permissions in each.
        ///
        /// `null` while `mfa_required` is `true`: a session that proved only
        /// a password has not finished authenticating, and must not read
        /// the organization's tenant layout. Call `…/me/access` once it has.
        access: Option<OrgUserAccessResponse>,
    },
    /// The password opened an account on the address in more than one
    /// organization. Nothing was opened: sign in again with the same
    /// address and password, naming one of these in `organization`.
    #[serde(rename = "choose_organization")]
    ChooseOrganization {
        /// The organizations to choose from.
        organizations: Vec<OfferedOrganizationResponse>,
    },
}

impl From<OrgLoginSuccess> for OrgLoginResponse {
    fn from(success: OrgLoginSuccess) -> Self {
        let owed = Owed::from(success.second_factor);
        let (tenant_id, tenant_slug) = landed(success.tenant);
        Self::Authenticated {
            session_id: success.session_id,
            refresh_token: success.refresh_token.expose().to_owned(),
            mfa_required: owed.mfa_required,
            mfa_enrollment_required: owed.mfa_enrollment_required,
            email_confirmation_required: owed.email_confirmation_required,
            tenant_id,
            organization_id: success.organization_id,
            tenant_slug,
            org_slug: success.org_slug.as_str().to_owned(),
            organization_name: success.organization_name.as_str().to_owned(),
            display_name: success.display_name.as_str().to_owned(),
            access: success.access.map(OrgUserAccessResponse::from),
        }
    }
}

impl From<OrgLoginOutcome> for OrgLoginResponse {
    fn from(outcome: OrgLoginOutcome) -> Self {
        match outcome {
            OrgLoginOutcome::SignedIn(success) => Self::from(*success),
            OrgLoginOutcome::ChooseOrganization(offered) => Self::ChooseOrganization {
                organizations: offered
                    .into_iter()
                    .map(OfferedOrganizationResponse::from)
                    .collect(),
            },
        }
    }
}

/// The tenant id and slug a session landed in, both `None` when it works
/// in no tenant.
fn landed(tenant: LandedTenant) -> (Option<TenantId>, Option<String>) {
    match tenant {
        LandedTenant::Tenant { id, slug } => (Some(id), Some(slug.as_str().to_owned())),
        LandedTenant::NoTenantAccess => (None, None),
    }
}

/// An organization a sign-in may go on to, once the person names it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OfferedOrganizationResponse {
    /// The membership scope this sign-in choice would enter.
    #[schema(value_type = String, format = Uuid)]
    pub organization_id: OrganizationId,
    /// Its slug, to send as `organization` when signing in again.
    pub slug: String,
    /// Its name, as the person is shown it.
    pub name: String,
}

impl From<OfferedOrganization> for OfferedOrganizationResponse {
    fn from(offered: OfferedOrganization) -> Self {
        Self {
            organization_id: offered.organization_id,
            slug: offered.slug.as_str().to_owned(),
            name: offered.name.as_str().to_owned(),
        }
    }
}

/// Request body asking for a sign-in link by address.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgMagicLinkBody {
    /// The address to mail the link to.
    pub email: String,
}

impl TryFrom<OrgMagicLinkBody> for Email {
    type Error = ApiError;

    fn try_from(body: OrgMagicLinkBody) -> Result<Self, Self::Error> {
        Self::new(&body.email).map_err(ApiError::validation)
    }
}

/// Request body following a mailed sign-in link. Holds the link's token,
/// so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgMagicLinkConfirmBody {
    /// The token from the link.
    pub token: String,
    /// The tenant to sign in to. Without it the session lands in the first
    /// active tenant the member reaches.
    #[serde(default)]
    pub tenant_slug: Option<String>,
}

impl OrgMagicLinkConfirmBody {
    /// The sign-in this link asks for, from where `meta` says the request
    /// came.
    ///
    /// # Errors
    ///
    /// `422` when the tenant slug is malformed.
    pub(crate) fn into_request(self, meta: RequestMeta) -> Result<OrgMagicLinkRequest, ApiError> {
        Ok(OrgMagicLinkRequest {
            token: Secret::new(self.token),
            tenant_slug: slug_of(self.tenant_slug)?,
            origin: origin_of(meta),
        })
    }
}

/// Request body for confirming a sign-in from the member's mailbox.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgConfirmSignInBody {
    /// The token from the link mailed to the member.
    pub token: String,
    /// The refresh token of the sign-in waiting for the confirmation, as
    /// the browser that began it holds it.
    pub refresh_token: String,
}

impl From<OrgConfirmSignInBody> for OrgConfirmRequest {
    fn from(body: OrgConfirmSignInBody) -> Self {
        Self {
            link: Secret::new(body.token),
            session_token: Secret::new(body.refresh_token),
        }
    }
}

/// The sign-in a mailed link confirmed.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgConfirmedSignInResponse {
    /// The session confirmed.
    #[schema(value_type = String, format = Uuid)]
    pub session_id: SessionId,
    /// Whether the organization requires a second factor the member has
    /// not set up, so they set one up before the session is let in.
    pub mfa_enrollment_required: bool,
}

impl From<OrgConfirmed> for OrgConfirmedSignInResponse {
    fn from(confirmed: OrgConfirmed) -> Self {
        Self {
            session_id: confirmed.session_id,
            mfa_enrollment_required: !confirmed.second_factor.is_satisfied(),
        }
    }
}

/// Request body for org logout.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgLogoutBody {
    /// The session ID to revoke.
    pub session_id: String,
}

impl TryFrom<OrgLogoutBody> for SessionId {
    type Error = ApiError;

    fn try_from(body: OrgLogoutBody) -> Result<Self, Self::Error> {
        Uuid::parse_str(&body.session_id)
            .map(Self::from_uuid)
            .map_err(|_| {
                ApiError::validation(message!("api-invalid-session-id", "invalid session_id"))
            })
    }
}

/// An active session with where it signed in from.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ActiveSessionResponse {
    /// The handle used to identify and revoke this signed-in session.
    pub session_id: Uuid,
    /// The client network address observed when the session began, when known.
    pub ip_address: Option<String>,
    /// The estimated north-south location of the sign-in address, when known.
    pub latitude: Option<f64>,
    /// The estimated east-west location of the sign-in address, when known.
    pub longitude: Option<f64>,
    /// The country inferred from the sign-in address, when known.
    pub country_code: Option<String>,
    /// City name.
    pub city: Option<String>,
    /// When the session was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

impl From<ActiveSessionInfo> for ActiveSessionResponse {
    fn from(s: ActiveSessionInfo) -> Self {
        Self {
            session_id: *s.session_id.as_uuid(),
            ip_address: s.ip_address.map(|ip| ip.as_str().to_owned()),
            latitude: s.geo.as_ref().map(IpGeolocation::latitude),
            longitude: s.geo.as_ref().map(IpGeolocation::longitude),
            country_code: s.geo.as_ref().map(|g| g.country_code().as_str().to_owned()),
            city: s.geo.as_ref().and_then(|g| g.city().map(str::to_owned)),
            created_at: s.created_at,
        }
    }
}

/// The member's remembered devices.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgDeviceListResponse {
    /// Every device, forgotten ones included.
    pub devices: Vec<OrgDeviceEntry>,
}

impl OrgDeviceListResponse {
    /// One entry per device of `devices`, in the order given.
    #[must_use]
    pub(crate) fn of(devices: &[TrustedDevice<ResolvedOrganization>]) -> Self {
        Self {
            devices: devices.iter().map(OrgDeviceEntry::from).collect(),
        }
    }
}

/// A device the member remembered.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgDeviceEntry {
    /// Device ID.
    pub id: String,
    /// The name shown in the list.
    pub name: String,
    /// When it was remembered.
    pub created_at: String,
    /// `trusted`, or `revoked` once forgotten.
    pub status: String,
}

impl From<&TrustedDevice<ResolvedOrganization>> for OrgDeviceEntry {
    fn from(device: &TrustedDevice<ResolvedOrganization>) -> Self {
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

/// What the member supplies to remember the device they sign in from.
///
/// Carries no `ip` or `user_agent`: both are read from the request itself,
/// so the device list records where the trust was actually granted rather
/// than whatever the client chose to type.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgTrustDeviceBody {
    /// The secret the browser made for itself, 64 hex digits, presented at
    /// later sign-ins. Only its digest is kept.
    pub fingerprint_hash: String,
    /// The name shown in the member's device list.
    pub device_name: String,
}

impl OrgTrustDeviceBody {
    /// The device to remember, from where `meta` says the request came.
    ///
    /// # Errors
    ///
    /// `422` when the secret or name is malformed, or the request has no
    /// client address to record.
    pub(crate) fn into_request(self, meta: RequestMeta) -> Result<TrustOrgDeviceRequest, ApiError> {
        let Some(ip) = meta.ip_address else {
            return Err(ApiError::validation(message!(
                "api-this-request-has-no-resolvable-client",
                "this request has no resolvable client address, so there would be \
                 nothing to say about where the device was trusted from"
            )));
        };
        Ok(TrustOrgDeviceRequest {
            secret: DeviceSecret::new(self.fingerprint_hash).map_err(ApiError::validation)?,
            device_name: Label::new("device_name", self.device_name)
                .map_err(ApiError::validation)?,
            user_agent: meta.user_agent.unwrap_or_else(UserAgent::unknown),
            ip,
        })
    }
}

/// The device remembered.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgTrustDeviceResponse {
    /// The handle for the browser trust record that was just created.
    pub device_id: String,
}

impl From<TrustedDeviceId> for OrgTrustDeviceResponse {
    fn from(id: TrustedDeviceId) -> Self {
        Self {
            device_id: id.to_string(),
        }
    }
}

/// Request body naming a device to forget.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgRevokeDeviceBody {
    /// The device's ID.
    pub device_id: String,
}

impl TryFrom<OrgRevokeDeviceBody> for TrustedDeviceId {
    type Error = ApiError;

    fn try_from(body: OrgRevokeDeviceBody) -> Result<Self, Self::Error> {
        Uuid::parse_str(&body.device_id)
            .map(Self::from_uuid)
            .map_err(|_| {
                ApiError::validation(message!("api-invalid-device-id", "invalid device_id"))
            })
    }
}

/// Request body for moving the session to another tenant.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SwitchOrgTenantBody {
    /// The tenant to move to.
    pub tenant_id: Uuid,
}

impl From<SwitchOrgTenantBody> for TenantId {
    fn from(body: SwitchOrgTenantBody) -> Self {
        Self::from_uuid(body.tenant_id)
    }
}

/// The session that replaced the one moved.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MovedOrgSessionResponse {
    /// The new session.
    #[schema(value_type = String, format = Uuid)]
    pub session_id: SessionId,
    /// Its refresh token, shown this once. The old one stops working.
    pub refresh_token: String,
    /// The tenant the new session works in.
    #[schema(value_type = String, format = Uuid)]
    pub tenant_id: TenantId,
}

impl From<MovedOrgSession> for MovedOrgSessionResponse {
    fn from(moved: MovedOrgSession) -> Self {
        Self {
            session_id: moved.session_id,
            refresh_token: moved.refresh_token.expose().to_owned(),
            tenant_id: moved.tenant_id,
        }
    }
}

/// Request body for switching to a linked account in another tenant.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct LinkedTenantSwitchBody {
    /// The tenant to switch into.
    ///
    /// The identity is not named here: it is read from the caller's account
    /// in the current tenant and followed across.
    pub target_tenant_id: String,
}

impl TryFrom<LinkedTenantSwitchBody> for TenantId {
    type Error = ApiError;

    fn try_from(body: LinkedTenantSwitchBody) -> Result<Self, Self::Error> {
        Uuid::parse_str(&body.target_tenant_id)
            .map(Self::from_uuid)
            .map_err(|_| {
                ApiError::validation(message!(
                    "api-invalid-target-tenant-id",
                    "invalid target_tenant_id"
                ))
            })
    }
}

/// The session opened in the linked account.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LinkedTenantSwitchResponse {
    /// The new session, in the target tenant.
    #[schema(value_type = String, format = Uuid)]
    pub session_id: SessionId,
    /// Its refresh token, shown this once.
    pub refresh_token: String,
    /// The tenant switched to.
    #[schema(value_type = String, format = Uuid)]
    pub tenant_id: TenantId,
    /// The linked account signed in to there.
    #[schema(value_type = String, format = Uuid)]
    pub user_id: UserId,
    /// Whether the new session owes more before it is let in, as a sign-in
    /// to the target account would.
    pub mfa_required: bool,
    /// Whether that is a second factor to set up first.
    pub mfa_enrollment_required: bool,
    /// Whether that is a confirmation from the account's mailbox.
    pub email_confirmation_required: bool,
}

impl From<LinkedSwitchSuccess> for LinkedTenantSwitchResponse {
    fn from(success: LinkedSwitchSuccess) -> Self {
        let owed = Owed::from(success.second_factor);
        Self {
            session_id: success.session_id,
            refresh_token: success.refresh_token.expose().to_owned(),
            tenant_id: success.tenant_id,
            user_id: success.user_id,
            mfa_required: owed.mfa_required,
            mfa_enrollment_required: owed.mfa_enrollment_required,
            email_confirmation_required: owed.email_confirmation_required,
        }
    }
}
