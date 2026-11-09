//! Organization bodies: the organization itself, its plan, its metrics
//! overview and its sign-in settings.

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::organization::OrganizationSortField;
use ianua_app::use_cases::organization::lifecycle::{
    ListOrganizationsRequest, OrganizationFilter, OrganizationMetrics,
    UpdateOrganizationAuthConfigRequest, UpdateOrganizationRequest,
};
use ianua_domain::domains::authentication::credentials::breach::BreachedPasswordCheck;
use ianua_domain::domains::authentication::methods::{AuthMethod, MfaPolicy};
use ianua_domain::domains::authentication::mfa::enrollment::MfaMethod;
use ianua_domain::domains::authentication::risk_engine::assessment::RiskLevel;
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authentication::risk_engine::pressure::FailureThreshold;
use ianua_domain::domains::authentication::risk_engine::step_up::{
    MfaTrigger, StepUpPolicy, StepUpPolicyParams,
};
use ianua_domain::domains::organization::access::auth_config::{
    OrganizationAuthConfig, OrganizationAuthSettings, SsoEnforcement,
};
use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::status::OrganizationStatus;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{
    CidrRange, DisplayName, Email, Label, OrganizationId, PasswordPolicy, Seconds,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::metrics::{
    ApiUsageMetricsResponse, AuthenticationMetricsResponse, CountMetricResponse,
    MetricsWindowResponse,
};
use crate::dto::organization::proof::ReenteredProofBody;
use crate::dto::tenant::settings::default_challenge_threshold;
use crate::error::ApiError;

/// The owning company's identity, subscription and lifecycle state.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrganizationResponse {
    /// Unique identifier.
    #[schema(value_type = String, format = Uuid)]
    pub id: OrganizationId,
    /// The URL slug.
    pub slug: String,
    /// The organization's name.
    pub name: String,
    /// Where the organization is reached.
    pub contact_email: String,
    /// The name shown in the dashboard.
    pub display_name: String,
    /// `Active`, `Suspended` or `Closed`.
    #[schema(schema_with = crate::dto::schemas::organization_status)]
    pub status: OrganizationStatus,
    /// The plan it is on, such as `Free`.
    #[schema(schema_with = crate::dto::schemas::organization_plan)]
    pub plan: OrganizationPlan,
    /// How many tenants it has.
    pub tenant_count: usize,
    /// When it was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Organization> for OrganizationResponse {
    fn from(o: Organization) -> Self {
        Self {
            id: *o.id(),
            slug: o.slug().as_str().to_owned(),
            name: o.name().as_str().to_owned(),
            contact_email: o.contact_email().as_str().to_owned(),
            display_name: o.display_name().as_str().to_owned(),
            status: o.status(),
            plan: o.plan(),
            tenant_count: o.tenant_count(),
            created_at: o.created_at(),
            updated_at: o.updated_at(),
        }
    }
}

/// Query parameters for filtering an organization listing.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct OrganizationFilterParams {
    /// Only organizations of this status (`Active`, `Suspended`, `Closed`).
    /// Omit for every status.
    #[param(value_type = Option<String>)]
    pub status: Option<OrganizationStatus>,
}

impl OrganizationFilterParams {
    /// The listing asked for: these organizations, in `sort` order, the
    /// page `pagination` names.
    #[must_use]
    pub(crate) fn listing(
        self,
        sort: SortOrder<OrganizationSortField>,
        pagination: PageRequest,
    ) -> ListOrganizationsRequest {
        ListOrganizationsRequest {
            filter: OrganizationFilter {
                status: self.status,
            },
            sort,
            page: pagination,
        }
    }
}

/// The organization fields to change. Only fields given change.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateOrganizationBody {
    /// The new name.
    pub name: Option<String>,
    /// The new contact address.
    pub contact_email: Option<String>,
    /// The new display name.
    pub display_name: Option<String>,
}

impl UpdateOrganizationBody {
    /// The change asked for, each value checked against `limits`.
    ///
    /// # Errors
    ///
    /// `422` when a value is not a valid name or address.
    pub(crate) fn into_request(
        self,
        limits: &DomainLimits,
    ) -> Result<UpdateOrganizationRequest, ApiError> {
        Ok(UpdateOrganizationRequest {
            name: self
                .name
                .map(|name| Label::new("name", name))
                .transpose()
                .map_err(ApiError::validation)?,
            contact_email: self
                .contact_email
                .map(Email::new)
                .transpose()
                .map_err(ApiError::validation)?,
            display_name: self
                .display_name
                .map(|name| DisplayName::new(name, &limits.display_name))
                .transpose()
                .map_err(ApiError::validation)?,
        })
    }
}

/// The organization metrics overview.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgMetricsResponse {
    /// The window these figures cover.
    pub window: MetricsWindowResponse,
    /// Authentication figures and charts.
    pub authentication: AuthenticationMetricsResponse,
    /// Total users.
    pub users: CountMetricResponse,
    /// Total tenants.
    pub tenants: CountMetricResponse,
    /// The session count for the selected window and its change from the prior window.
    pub active_sessions: CountMetricResponse,
    /// Proxied API usage.
    pub api: ApiUsageMetricsResponse,
}

impl From<OrganizationMetrics> for OrgMetricsResponse {
    fn from(metrics: OrganizationMetrics) -> Self {
        Self {
            window: metrics.window.into(),
            authentication: metrics.authentication.into(),
            users: metrics.users.into(),
            tenants: metrics.tenants.into(),
            active_sessions: metrics.active_sessions.into(),
            api: metrics.api.into(),
        }
    }
}

/// How the people who administer an organization sign in.
///
/// Sent and received whole. A half-applied config is an organization in a
/// state nobody chose, and the rules only hold across the whole thing.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgAuthConfigBody {
    /// Which ways in are allowed. At least one, or every administrator is
    /// locked out. Only `Password` and `Passkey` are accepted: org sign-in
    /// implements no others.
    #[schema(schema_with = crate::dto::schemas::auth_method_list)]
    pub enabled_methods: Vec<AuthMethod>,
    /// How strong an administrator's password has to be. Applies from the
    /// next password change or reset.
    #[schema(value_type = Object)]
    pub password_policy: PasswordPolicy,
    /// `Disabled`, `Optional`, or `Required`. No setting demands a factor
    /// from an administrator who has not enrolled one.
    #[schema(schema_with = crate::dto::schemas::mfa_policy)]
    pub mfa_policy: MfaPolicy,
    /// How long an org session stays valid from creation, in seconds.
    pub session_lifetime_secs: u32,
    /// How long an org session may sit idle before expiring, in seconds.
    /// Cannot outlast the session it belongs to.
    pub idle_timeout_secs: u32,
    /// Failed attempts from one network before that network is locked out
    /// of the account. Sign-ins from anywhere else go on.
    pub max_login_attempts: u8,
    /// How long the network stays locked out of the account, in seconds.
    pub lockout_duration_secs: u32,
    /// CIDR ranges allowed to reach org sign-in. Empty means anywhere. With
    /// any range set, a request whose address cannot be resolved is refused.
    pub ip_allowlist: Vec<String>,
    /// When an org sign-in has to clear a higher bar than a password.
    pub step_up: SignInPolicyBody,
    /// `Enforced` signs members in only through the organization's identity
    /// provider (owners keep their own ways in); `Optional` when omitted.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::sso_enforcement)]
    pub sso: SsoEnforcement,
    /// The kinds of second factor members may set up. Members use an
    /// authenticator app or a passkey: mailed and texted codes are refused.
    /// `["Totp"]` when omitted.
    #[serde(default = "default_member_factors")]
    #[schema(schema_with = crate::dto::schemas::mfa_method_list)]
    pub second_factors: Vec<MfaMethod>,
    /// What setting a new password does about one found in known breaches:
    /// `Off`, `Warn` or `Block`. `Block` when omitted.
    #[serde(default = "default_member_breach_check")]
    #[schema(schema_with = crate::dto::schemas::breached_password_check)]
    pub breached_passwords: BreachedPasswordCheck,
    /// How many failed password sign-ins naming the organization, in the
    /// deployment's window, put its sign-in under pressure: from then on a
    /// device no member remembered must pass a challenge before its
    /// password is checked. From 10 to 1,000,000; 200 when omitted.
    #[serde(default = "default_challenge_threshold")]
    pub challenge_threshold: u32,
}

/// The second factors a body that names none offers members.
fn default_member_factors() -> Vec<MfaMethod> {
    vec![MfaMethod::Totp]
}

/// What a body that does not say does about a breached new password.
fn default_member_breach_check() -> BreachedPasswordCheck {
    BreachedPasswordCheck::Block
}

impl From<&OrganizationAuthConfig> for OrgAuthConfigBody {
    fn from(config: &OrganizationAuthConfig) -> Self {
        Self {
            enabled_methods: config.enabled_methods().to_vec(),
            password_policy: config.password_policy().clone(),
            mfa_policy: config.mfa_policy(),
            session_lifetime_secs: config.session_lifetime_secs().get(),
            idle_timeout_secs: config.idle_timeout_secs().get(),
            max_login_attempts: config.max_login_attempts(),
            lockout_duration_secs: config.lockout_duration_secs().get(),
            ip_allowlist: config
                .ip_allowlist()
                .iter()
                .map(|cidr| cidr.as_str().to_owned())
                .collect(),
            step_up: SignInPolicyBody::from(config.step_up_policy()),
            sso: config.sso(),
            second_factors: config.settings().second_factors.clone(),
            breached_passwords: config.breached_passwords(),
            challenge_threshold: config.challenge_threshold().get(),
        }
    }
}

impl From<Organization> for OrgAuthConfigBody {
    fn from(organization: Organization) -> Self {
        Self::from(organization.auth_config())
    }
}

impl TryFrom<OrgAuthConfigBody> for OrganizationAuthConfig {
    type Error = ApiError;

    fn try_from(body: OrgAuthConfigBody) -> Result<Self, Self::Error> {
        let ip_allowlist = body
            .ip_allowlist
            .into_iter()
            .map(CidrRange::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::validation)?;
        let challenge_threshold =
            FailureThreshold::new(body.challenge_threshold).map_err(ApiError::validation)?;
        OrganizationAuthConfig::new(OrganizationAuthSettings {
            enabled_methods: body.enabled_methods,
            password_policy: body.password_policy,
            mfa_policy: body.mfa_policy,
            session_lifetime_secs: Seconds::new(body.session_lifetime_secs),
            idle_timeout_secs: Seconds::new(body.idle_timeout_secs),
            max_login_attempts: body.max_login_attempts,
            lockout_duration_secs: Seconds::new(body.lockout_duration_secs),
            ip_allowlist,
            step_up_policy: body.step_up.try_into()?,
            sso: body.sso,
            second_factors: body.second_factors,
            breached_passwords: body.breached_passwords,
            challenge_threshold,
        })
        .map_err(ApiError::validation)
    }
}

/// The new sign-in settings, with what the owner typed again to prove who
/// they are.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateOrgAuthConfigBody {
    /// The settings that replace the current ones, whole.
    #[serde(flatten)]
    pub config: OrgAuthConfigBody,
    /// The caller's password typed again, with a code from their second
    /// factor when they have one.
    pub proof: ReenteredProofBody,
}

impl TryFrom<UpdateOrgAuthConfigBody> for UpdateOrganizationAuthConfigRequest {
    type Error = ApiError;

    fn try_from(body: UpdateOrgAuthConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            config: body.config.try_into()?,
            proof: body.proof.into(),
        })
    }
}

/// When a sign-in has to clear a higher bar than a password.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct SignInPolicyBody {
    /// Minimum assurance for an ordinary sign-in: `Aal1`, `Aal2` or `Aal3`.
    #[schema(schema_with = crate::dto::schemas::assurance_level)]
    pub baseline_aal: AssuranceLevel,
    /// Minimum assurance for a sensitive operation. May not be lower than
    /// the baseline.
    #[schema(schema_with = crate::dto::schemas::assurance_level)]
    pub sensitive_aal: AssuranceLevel,
    /// Whether a device the user has not trusted forces a second factor.
    /// This is what gives "remember this device" its meaning.
    pub require_mfa_new_device: bool,
    /// Whether signing in from an unfamiliar country forces a second factor.
    pub require_mfa_new_country: bool,
    /// The risk level from which a second factor is demanded regardless of
    /// every other signal: `Low`, `Medium`, `High` or `Critical`.
    #[schema(schema_with = crate::dto::schemas::risk_level)]
    pub mfa_risk_threshold: RiskLevel,
    /// The risk level from which the sign-in is refused outright. Checked
    /// before the one above.
    #[schema(schema_with = crate::dto::schemas::risk_level)]
    pub deny_risk_threshold: RiskLevel,
}

impl From<&StepUpPolicy> for SignInPolicyBody {
    fn from(policy: &StepUpPolicy) -> Self {
        Self {
            baseline_aal: policy.baseline_aal(),
            sensitive_aal: policy.sensitive_aal(),
            require_mfa_new_device: policy.require_mfa_new_device(),
            require_mfa_new_country: policy.require_mfa_new_country(),
            mfa_risk_threshold: policy.mfa_risk_threshold(),
            deny_risk_threshold: policy.deny_risk_threshold(),
        }
    }
}

impl TryFrom<SignInPolicyBody> for StepUpPolicy {
    type Error = ApiError;

    fn try_from(body: SignInPolicyBody) -> Result<Self, Self::Error> {
        StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal: body.baseline_aal,
            sensitive_aal: body.sensitive_aal,
            new_device: MfaTrigger::from(body.require_mfa_new_device),
            new_country: MfaTrigger::from(body.require_mfa_new_country),
            mfa_risk_threshold: body.mfa_risk_threshold,
            deny_risk_threshold: body.deny_risk_threshold,
        })
        .map_err(ApiError::validation)
    }
}
