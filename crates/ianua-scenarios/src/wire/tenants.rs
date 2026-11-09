//! An organization's tenants: making one, reading it while its setup runs,
//! changing it, copying parts of one into another, and how its users sign
//! in.

use serde::{Deserialize, Serialize};

/// `POST …/tenants`: a new tenant on the platform's own infrastructure.
#[derive(Debug, Clone, Serialize)]
pub struct NewTenant {
    /// Its slug, unique in the organization.
    pub slug: String,
    /// Human-readable label shown to organization members selecting a tenant.
    pub display_name: String,
    /// Who to write to about it.
    pub contact_email: String,
    /// Its IANA time zone, such as `Europe/Berlin`.
    pub timezone: String,
    /// Its BCP 47 locale, such as `en`.
    pub locale: String,
}

/// The tenant made; its setup runs on.
#[derive(Debug, Clone, Deserialize)]
pub struct TenantMade {
    /// Handle used to poll setup progress after creation.
    pub id: String,
}

/// Where a tenant is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum TenantStatus {
    /// Its setup still runs.
    Provisioning,
    /// Set up and in use.
    Active,
    /// Stopped for now.
    Suspended,
    /// Put away, restorable for a while.
    Archived,
    /// Gone.
    Deleted,
}

/// One tenant, from `GET …/tenants/{tenant}`.
#[derive(Debug, Clone, Deserialize)]
pub struct Tenant {
    /// Stable identifier used in grants and organization administration.
    pub id: String,
    /// Its organization's id.
    pub organization_id: String,
    /// URL segment addressing the tenant within its organization.
    pub slug: String,
    /// Human-readable label shown in the organization's tenant list.
    pub display_name: String,
    /// Who to write to about it.
    pub contact_email: String,
    /// Its IANA time zone, such as `Europe/Berlin`.
    pub timezone: String,
    /// Its BCP 47 locale, such as `en-US`.
    pub locale: String,
    /// Where it is in its life.
    pub status: TenantStatus,
    /// How its setup stands.
    pub setup: TenantSetup,
    /// The stage of the product it serves: `production`, `staging` or
    /// `development`.
    #[serde(default)]
    pub environment: String,
}

/// How a tenant's setup stands.
#[derive(Debug, Clone, Deserialize)]
pub struct TenantSetup {
    /// `running`, `failed` or `over`.
    pub state: String,
    /// The step that failed, when `state` is `failed`.
    pub failed_step: Option<String>,
}

/// `PATCH …/tenants/{tenant}`: what changes; the rest is left alone.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TenantChange {
    /// Explicit consent to publishing readable platform addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readable_address: Option<bool>,
    /// Its new name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Its new contact address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
    /// Its new IANA time zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// Its new BCP 47 locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

/// `POST …/tenant-clones`: parts of one tenant copied into another of the
/// same organization.
#[derive(Debug, Clone, Serialize)]
pub struct CloneSetup {
    /// The tenant copied from.
    pub source_tenant_id: String,
    /// The tenant copied into.
    pub target_tenant_id: String,
    /// What is copied, such as `roles_and_policies` or `settings`.
    pub parts: Vec<String>,
}

/// The copy started; it runs on as a job.
#[derive(Debug, Clone, Deserialize)]
pub struct CloneStarted {
    /// Handle used to poll the background copy's progress.
    pub id: String,
}

/// How a copy stands, from `GET …/tenant-clones/{id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct CloneProgress {
    /// The tenant copied from.
    pub source_tenant_id: String,
    /// The tenant copied into.
    pub target_tenant_id: String,
    /// `running`, `completed` or `failed`.
    pub state: String,
    /// The parts copied so far.
    pub copied: Vec<String>,
    /// Why it failed, when it did.
    #[serde(default)]
    pub failure: Option<String>,
}

/// Whether a tenant's users set up a second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaPolicy {
    /// No second factors.
    Disabled,
    /// Whoever sets one up uses it.
    Optional,
    /// Everyone sets one up.
    Required,
}

/// How a tenant's users sign in, from `GET …/auth-config`, and sent back
/// whole with `PUT`. The fields a scenario changes are named; every other
/// one is kept as it came, so a replace changes only what was meant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInSettings {
    /// Whether second factors are off, optional or required.
    pub mfa_policy: MfaPolicy,
    /// The ways in: `Password`, `MagicLink`, `Passkey`, `Saml`, `Oidc`.
    pub enabled_methods: Vec<String>,
    /// Every other setting, as the API answered it.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// `PUT …/auth-config`: the whole settings and the caller's password
/// typed again. Holds the password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ReplaceSignInSettings {
    /// The settings, whole.
    #[serde(flatten)]
    pub settings: SignInSettings,
    /// The caller, proved again.
    pub proof: PasswordAgain,
}

/// `GET …/compliance`: where the tenant's data must stay, how long its
/// audit records are kept, and whether operators may act as its users.
#[derive(Debug, Clone, Deserialize)]
pub struct Compliance {
    /// The jurisdiction its data must stay in, or none for anywhere.
    #[serde(default)]
    pub data_residency: Option<String>,
    /// How many days audit records are kept.
    pub audit_retention_days: u32,
    /// Whether operators may act as its users.
    pub operator_impersonation: bool,
}

/// `PUT …/compliance`: the whole posture and the caller's password typed
/// again. Holds the password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ReplaceCompliance {
    /// The jurisdiction its data must stay in, or none for anywhere.
    pub data_residency: Option<String>,
    /// How many days audit records are kept.
    pub audit_retention_days: u32,
    /// Whether operators may act as its users.
    pub operator_impersonation: bool,
    /// The caller, proved again.
    pub proof: PasswordAgain,
}

/// A signed-in member's password typed again, as tenant settings take it.
/// Holds the password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct PasswordAgain {
    /// Current account secret proving authority to change protected settings.
    pub password: String,
    /// A code from their authenticator, when they have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// `PUT …/tenants/{tenant}/environment`: the stage the tenant serves.
#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentChange {
    /// `production`, `staging` or `development`.
    pub environment: String,
}
