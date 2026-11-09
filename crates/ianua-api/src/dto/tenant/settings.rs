//! Tenant settings bodies: the general settings, how its users sign in, its
//! mTLS trust anchor, the names it is reached on, its compliance posture,
//! and what its users may give themselves in an emergency.

use ianua_app::input::FieldUpdate;
use ianua_app::use_cases::tenant::settings::{
    ChangeComplianceRequest, TenantHostnames, UpdateAuthConfigRequest, UpdateMtlsConfigRequest,
    UpdateRequest,
};
use ianua_domain::domains::authentication::credentials::breach::BreachedPasswordCheck;
use ianua_domain::domains::authentication::methods::{AuthMethod, MfaPolicy};
use ianua_domain::domains::authentication::mfa::enrollment::MfaMethod;
use ianua_domain::domains::authentication::risk_engine::pressure::{
    DEFAULT_FAILURE_THRESHOLD, FailureThreshold,
};
use ianua_domain::domains::authorization::break_glass::{BreakGlassAccess, SelfService};
use ianua_domain::domains::authorization::permission::{CustomPermission, SystemPermission};
use ianua_domain::domains::identity::impersonation::state::ImpersonationConsent;
use ianua_domain::domains::tenant::access::auth_config::{
    SelfRegistration, TenantAuthConfig, TenantAuthSettings, TokenIssuer,
};
use ianua_domain::domains::tenant::access::network_security::{MtlsConfig, MtlsMode};
use ianua_domain::domains::tenant::compliance::{
    CompliancePosture, OperatorImpersonation, Residency,
};
use ianua_domain::domains::tenant::environment::TenantEnvironment;
use ianua_domain::domains::tenant::hosts::{
    PlatformAddressing, PlatformHostParts, PlatformHosts, ReadableAddress,
};
use ianua_domain::message;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{
    CertificatePem, CidrRange, DisplayName, DomainName, Email, HttpUrl, Locale, PasswordPolicy,
    RevocationListPem, Seconds, Timezone,
};
use serde::{Deserialize, Serialize};

use crate::dto::organization::lifecycle::SignInPolicyBody;
use crate::dto::tenant::proof::FreshProofBody;
use crate::error::ApiError;
use crate::patch;

/// The general settings to change. An omitted field is left alone.
///
/// Unknown fields are refused. The token issuer is a sign-in setting and
/// changes with the authentication configuration, so a body naming
/// `jwt_issuer` here learns that instead of having it dropped.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateTenantBody {
    /// The tenant's name.
    pub display_name: Option<String>,
    /// Where notices about the tenant go.
    pub contact_email: Option<String>,
    /// IANA timezone.
    pub timezone: Option<String>,
    /// BCP 47 locale.
    pub locale: Option<String>,
    /// The tenant's primary domain: one it has registered and proved.
    pub primary_domain: Option<String>,
    /// Explicit consent to public readable DNS names and certificate
    /// transparency entries. Null is refused; omitted leaves it unchanged.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub readable_address: Option<Option<bool>>,
}

impl UpdateTenantBody {
    /// The change this body asks for, names checked against `limits`.
    ///
    /// # Errors
    ///
    /// A validation error for a value that is not a valid one.
    pub(crate) fn into_request(self, limits: &DomainLimits) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            display_name: self
                .display_name
                .map(|name| DisplayName::new(name, &limits.display_name))
                .transpose()
                .map_err(ApiError::validation)?,
            contact_email: parsed(self.contact_email, Email::new)?,
            timezone: parsed(self.timezone, Timezone::new)?,
            locale: parsed(self.locale, Locale::new)?,
            primary_domain: parsed(self.primary_domain, DomainName::new)?,
            readable_address: readable_choice(self.readable_address)?,
        })
    }
}

/// The stage of its product a tenant is to serve.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChangeEnvironmentBody {
    /// `production`, `staging` or `development`.
    pub environment: String,
}

impl ChangeEnvironmentBody {
    /// The stage this body names.
    ///
    /// # Errors
    ///
    /// A validation error for a name that is no stage.
    pub(crate) fn environment(&self) -> Result<TenantEnvironment, ApiError> {
        TenantEnvironment::parse(&self.environment).ok_or_else(|| {
            ApiError::validation(message!(
                "api-environment-is-production-staging-or-development",
                "environment is production, staging or development"
            ))
        })
    }
}

/// A tenant's mTLS trust anchor.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MtlsConfigResponse {
    /// `Disabled`, `Optional` or `Required`.
    #[schema(schema_with = crate::dto::schemas::mtls_mode)]
    pub mode: MtlsMode,
    /// PEM-encoded CA certificates trusted to sign client certificates.
    pub trusted_ca_certs: Vec<String>,
    /// PEM-encoded revocation lists (`X509 CRL`) client certificates are
    /// checked against in the handshake. Empty when revocation is not
    /// checked.
    pub revocation_lists: Vec<String>,
}

impl From<&MtlsConfig> for MtlsConfigResponse {
    fn from(config: &MtlsConfig) -> Self {
        Self {
            mode: config.mode(),
            trusted_ca_certs: config
                .trusted_ca_certs()
                .iter()
                .map(|cert| cert.as_str().to_owned())
                .collect(),
            revocation_lists: config
                .revocation_lists()
                .iter()
                .map(|list| list.as_str().to_owned())
                .collect(),
        }
    }
}

/// A replacement mTLS trust anchor, with a fresh proof of the person.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateMtlsConfigBody {
    /// `Disabled`, `Optional` or `Required`.
    #[schema(schema_with = crate::dto::schemas::mtls_mode)]
    pub mode: MtlsMode,
    /// PEM-encoded CA certificates trusted to sign client certificates.
    /// Ignored, but harmless to send, when `mode` is `Disabled`.
    #[serde(default)]
    pub trusted_ca_certs: Vec<String>,
    /// PEM-encoded revocation lists (`X509 CRL`) from those authorities.
    /// When any is given, every client certificate is checked against
    /// them, and refused when revoked, when no list covers its issuer, or
    /// once a list is past its next update. Leave out to check none.
    #[serde(default)]
    pub revocation_lists: Vec<String>,
    /// The person making the change, proved again.
    pub proof: FreshProofBody,
}

impl TryFrom<UpdateMtlsConfigBody> for UpdateMtlsConfigRequest {
    type Error = ApiError;

    fn try_from(body: UpdateMtlsConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            mode: body.mode,
            trusted_ca_certs: body
                .trusted_ca_certs
                .into_iter()
                .map(CertificatePem::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ApiError::validation)?,
            revocation_lists: body
                .revocation_lists
                .into_iter()
                .map(RevocationListPem::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ApiError::validation)?,
            proof: body.proof.try_into()?,
        })
    }
}

/// Everything about how a tenant's users sign in.
///
/// Replaced whole rather than patched: the rules only hold across the
/// entire configuration, and a half-applied one leaves a tenant in a state
/// nobody chose.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct AuthConfigBody {
    /// Which ways in are allowed. At least one, or every user is locked
    /// out.
    #[schema(schema_with = crate::dto::schemas::auth_method_list)]
    pub enabled_methods: Vec<AuthMethod>,
    /// How strong a password has to be. Applies from the next password
    /// change or reset.
    #[schema(value_type = Object)]
    pub password_policy: PasswordPolicy,
    /// `Disabled`, `Optional` or `Required`.
    #[schema(schema_with = crate::dto::schemas::mfa_policy)]
    pub mfa_policy: MfaPolicy,
    /// How long a session stays valid from creation, in seconds.
    pub session_lifetime_secs: u32,
    /// How long a session may sit idle before expiring, in seconds. Cannot
    /// outlast the session it belongs to.
    pub idle_timeout_secs: u32,
    /// Whether users may register themselves without an invitation.
    pub self_registration: bool,
    /// Failed attempts from one network before that network is locked out
    /// of the account. Sign-ins from anywhere else go on.
    pub max_login_attempts: u8,
    /// How long the network stays locked out of the account, in seconds.
    pub lockout_duration_secs: u32,
    /// CIDR ranges allowed to reach this tenant's sign-in endpoints. Empty
    /// means anywhere.
    pub ip_allowlist: Vec<String>,
    /// Expected `iss` claim on incoming tokens, when the tenant set an
    /// issuer of its own. Absent means the platform's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_issuer: Option<String>,
    /// When a sign-in has to clear a higher bar than a password.
    pub step_up: SignInPolicyBody,
    /// The kinds of second factor users may set up: `Totp`, `EmailCode`,
    /// `SmsCode`. At least one, each once; a kind that cannot reach the
    /// tenant's baseline is not offered. `["Totp"]` when omitted.
    #[serde(default = "default_second_factors")]
    #[schema(schema_with = crate::dto::schemas::mfa_method_list)]
    pub second_factors: Vec<MfaMethod>,
    /// What setting a new password does about one found in known breaches:
    /// `Off`, `Warn` (taken, the person is told) or `Block` (refused).
    /// `Block` when omitted.
    #[serde(default = "default_breached_passwords")]
    #[schema(schema_with = crate::dto::schemas::breached_password_check)]
    pub breached_passwords: BreachedPasswordCheck,
    /// Whether the person approves before a tenant admin acts as them for
    /// support (`HolderApproves`), or the admin decides (`AdminDecides`).
    /// `HolderApproves` when omitted.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::impersonation_consent)]
    pub impersonation_consent: ImpersonationConsent,
    /// How many failed password sign-ins across the tenant, in the
    /// deployment's window, put its sign-in under pressure: from then on a
    /// device nobody trusted must pass a challenge before its password is
    /// checked. From 10 to 1,000,000; 200 when omitted.
    #[serde(default = "default_challenge_threshold")]
    pub challenge_threshold: u32,
}

/// The challenge threshold a body that names none takes.
pub(crate) fn default_challenge_threshold() -> u32 {
    DEFAULT_FAILURE_THRESHOLD
}

/// The second factors a body that names none offers: an authenticator app.
fn default_second_factors() -> Vec<MfaMethod> {
    vec![MfaMethod::Totp]
}

/// What a body that does not say does about a breached new password: it
/// refuses it.
fn default_breached_passwords() -> BreachedPasswordCheck {
    BreachedPasswordCheck::Block
}

impl From<&TenantAuthConfig> for AuthConfigBody {
    fn from(config: &TenantAuthConfig) -> Self {
        let settings = config.settings();
        Self {
            enabled_methods: settings.enabled_methods.clone(),
            password_policy: settings.password_policy.clone(),
            mfa_policy: settings.mfa_policy,
            session_lifetime_secs: settings.session_lifetime_secs.get(),
            idle_timeout_secs: settings.idle_timeout_secs.get(),
            self_registration: bool::from(settings.self_registration),
            max_login_attempts: settings.max_login_attempts,
            lockout_duration_secs: settings.lockout_duration_secs.get(),
            ip_allowlist: settings
                .ip_allowlist
                .iter()
                .map(|cidr| cidr.as_str().to_owned())
                .collect(),
            jwt_issuer: issuer_url(&settings.jwt_issuer),
            step_up: SignInPolicyBody::from(&settings.step_up_policy),
            second_factors: settings.second_factors.clone(),
            breached_passwords: settings.breached_passwords,
            impersonation_consent: settings.impersonation_consent,
            challenge_threshold: settings.challenge_threshold.get(),
        }
    }
}

impl TryFrom<AuthConfigBody> for TenantAuthConfig {
    type Error = ApiError;

    fn try_from(body: AuthConfigBody) -> Result<Self, Self::Error> {
        let settings = TenantAuthSettings {
            enabled_methods: body.enabled_methods,
            password_policy: body.password_policy,
            mfa_policy: body.mfa_policy,
            session_lifetime_secs: Seconds::new(body.session_lifetime_secs),
            idle_timeout_secs: Seconds::new(body.idle_timeout_secs),
            self_registration: SelfRegistration::from(body.self_registration),
            max_login_attempts: body.max_login_attempts,
            lockout_duration_secs: Seconds::new(body.lockout_duration_secs),
            ip_allowlist: body
                .ip_allowlist
                .into_iter()
                .map(CidrRange::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ApiError::validation)?,
            jwt_issuer: TokenIssuer::from(
                body.jwt_issuer
                    .map(HttpUrl::new)
                    .transpose()
                    .map_err(ApiError::validation)?,
            ),
            step_up_policy: body.step_up.try_into()?,
            second_factors: body.second_factors,
            breached_passwords: body.breached_passwords,
            impersonation_consent: body.impersonation_consent,
            challenge_threshold: FailureThreshold::new(body.challenge_threshold)
                .map_err(ApiError::validation)?,
        };
        Self::new(settings).map_err(ApiError::validation)
    }
}

/// A replacement authentication configuration, with a fresh proof of the
/// person.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateAuthConfigBody {
    /// The whole configuration.
    #[serde(flatten)]
    pub config: AuthConfigBody,
    /// The person making the change, proved again.
    pub proof: FreshProofBody,
}

impl TryFrom<UpdateAuthConfigBody> for UpdateAuthConfigRequest {
    type Error = ApiError;

    fn try_from(body: UpdateAuthConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            config: body.config.try_into()?,
            proof: body.proof.try_into()?,
        })
    }
}

/// The names a tenant is reached on.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct HostnameConfigResponse {
    /// The random platform address. The historical JSON key is retained for
    /// clients; it contains no UUID. Empty when platform addresses are off.
    pub uuid_subdomain: String,
    /// The opted-in readable name, `{tenant slug}.{org slug}.{base domain}`.
    pub slug_subdomain: Option<String>,
    /// The permanent opaque DNS label.
    pub platform_label: String,
    /// Whether readable names were explicitly enabled by the tenant.
    pub readable_address: bool,
    /// The tenant's own domain, such as `auth.acme.com`, when one is
    /// primary.
    pub custom_domain: Option<String>,
    /// The tenant's primary domain.
    pub primary_domain: Option<String>,
    /// The issuer the tenant set for its tokens, when it set one.
    pub jwt_issuer: Option<String>,
}

impl HostnameConfigResponse {
    /// The names in `hostnames`, the platform's subdomains built under
    /// `base_domain`.
    #[must_use]
    pub(crate) fn new(
        hostnames: &TenantHostnames,
        base_domain: &DomainName,
        shape: PlatformAddressing,
    ) -> Self {
        let platform = PlatformHosts::under(
            base_domain,
            PlatformHostParts {
                label: &hostnames.platform_label,
                organization_slug: &hostnames.organization_slug,
                tenant_slug: &hostnames.tenant_slug,
                readable: hostnames.readable_address,
            },
            shape,
        );
        let primary = hostnames
            .primary_domain
            .as_ref()
            .map(|domain| domain.as_str().to_owned());
        Self {
            platform_label: hostnames.platform_label.as_str().to_owned(),
            readable_address: hostnames.readable_address == ReadableAddress::On,
            uuid_subdomain: platform
                .stable()
                .map_or_else(String::new, |name| name.as_str().to_owned()),
            slug_subdomain: platform.readable().map(|name| name.as_str().to_owned()),
            custom_domain: primary.clone(),
            primary_domain: primary,
            jwt_issuer: issuer_url(&hostnames.jwt_issuer),
        }
    }
}

/// A tenant's compliance posture.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ComplianceResponse {
    /// The jurisdiction the tenant's data must stay in, such as `Eu`, or
    /// `null` for anywhere.
    #[schema(value_type = Option<String>)]
    pub data_residency: Residency,
    /// How many days audit records are kept.
    pub audit_retention_days: u32,
    /// Whether operators may act as the tenant's users.
    #[schema(value_type = bool)]
    pub operator_impersonation: OperatorImpersonation,
}

impl From<&CompliancePosture> for ComplianceResponse {
    fn from(posture: &CompliancePosture) -> Self {
        Self {
            data_residency: posture.data_residency(),
            audit_retention_days: posture.audit_retention_days(),
            operator_impersonation: posture.operator_impersonation(),
        }
    }
}

/// A replacement compliance posture, with a fresh proof of the person.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeComplianceBody {
    /// The jurisdiction the tenant's data must stay in, such as `Eu`, or
    /// `null` for anywhere.
    #[schema(value_type = Option<String>)]
    pub data_residency: Residency,
    /// How many days audit records are kept, within the deployment's
    /// range.
    pub audit_retention_days: u32,
    /// Whether operators may act as the tenant's users.
    #[schema(value_type = bool)]
    pub operator_impersonation: OperatorImpersonation,
    /// The person making the change, proved again.
    pub proof: FreshProofBody,
}

impl TryFrom<ChangeComplianceBody> for ChangeComplianceRequest {
    type Error = ApiError;

    fn try_from(body: ChangeComplianceBody) -> Result<Self, Self::Error> {
        Ok(Self {
            data_residency: body.data_residency,
            audit_retention_days: body.audit_retention_days,
            operator_impersonation: body.operator_impersonation,
            proof: body.proof.try_into()?,
        })
    }
}

/// What the tenant's users may give themselves in an emergency, with
/// nobody else approving. Both lists empty lets nothing: every grant then
/// needs someone else's approval.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct BreakGlassPolicyBody {
    /// Built-in permissions a user may give themselves.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub system_permissions: Vec<SystemPermission>,
    /// The tenant's own permissions a user may give themselves.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub custom_permissions: Vec<CustomPermission>,
}

impl TryFrom<BreakGlassPolicyBody> for SelfService {
    type Error = ApiError;

    fn try_from(body: BreakGlassPolicyBody) -> Result<Self, Self::Error> {
        if body.system_permissions.is_empty() && body.custom_permissions.is_empty() {
            return Ok(Self::Off);
        }
        BreakGlassAccess::new(body.system_permissions, body.custom_permissions)
            .map(Self::UpTo)
            .map_err(ApiError::validation)
    }
}

/// Converts the three wire states without treating null as an omitted choice.
fn readable_choice(value: Option<Option<bool>>) -> Result<Option<ReadableAddress>, ApiError> {
    match patch::value_field(value) {
        FieldUpdate::Keep => Ok(None),
        FieldUpdate::Clear => Err(ApiError::validation(message!(
            "api-readable-address-must-be-true-or",
            "readable_address must be true or false"
        ))),
        FieldUpdate::Set(true) => Ok(Some(ReadableAddress::On)),
        FieldUpdate::Set(false) => Ok(Some(ReadableAddress::Off)),
    }
}

/// The issuer's address, when the tenant set one of its own.
fn issuer_url(issuer: &TokenIssuer) -> Option<String> {
    match issuer {
        TokenIssuer::Platform => None,
        TokenIssuer::Custom(url) => Some(url.as_str().to_owned()),
    }
}

/// `value` checked by `parse`, where one was given.
fn parsed<T, E: Into<ianua_domain::shared::errors::DomainError>>(
    value: Option<String>,
    parse: impl FnOnce(String) -> Result<T, E>,
) -> Result<Option<T>, ApiError> {
    value.map(parse).transpose().map_err(ApiError::validation)
}
