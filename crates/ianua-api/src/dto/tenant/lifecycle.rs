//! Tenant lifecycle bodies: a tenant to provision, a tenant as it is read
//! back, an early deletion, and the tenant's metrics overview.

use ianua_app::email::LinkScope;
use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::tenant::TenantSortField;
use ianua_app::use_cases::tenant::lifecycle::{
    DeleteTenantEarlyRequest, ListTenantsRequest, ProvisionTenantRequest, TenantLabel,
    TenantMetrics, TenantRead,
};
use ianua_domain::domains::tenant::lifecycle::EarlyDeletion;
use ianua_domain::domains::tenant::provisioning::infrastructure::DeploymentRegion;
use ianua_domain::domains::tenant::setup::SetupStanding;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::model::steps::PlanStep as _;
use ianua_domain::types::{
    DisplayName, Email, HttpsUrl, Locale, OrganizationId, TenantId, TenantSlug, Text, Timezone,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::metrics::{
    ApiUsageMetricsResponse, AuthenticationMetricsResponse, CountMetricResponse,
    MetricsWindowResponse,
};
use crate::dto::tenant::residency::{ResidencyBody, ResidencyResponse};
use crate::error::ApiError;

/// A tenant to provision.
///
/// A tenant starts with no primary domain: it proves a domain once it
/// exists, then makes that one primary. Unknown fields are refused, so a
/// body still naming `primary_domain` learns that instead of having it
/// dropped.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisionTenantBody {
    /// URL-safe slug for subdomains and API paths, unique within its organization.
    pub slug: String,
    /// The tenant's name in admin screens.
    pub display_name: String,
    /// Where notices about the tenant go.
    pub contact_email: String,
    /// IANA timezone, such as `Europe/Berlin`.
    pub timezone: String,
    /// BCP 47 locale, such as `en-US`.
    pub locale: String,
    /// Where this tenant's data should live.
    ///
    /// Omit it and the tenant lands on the platform's shared database in
    /// the deployment's default region.
    #[serde(default)]
    pub residency: Option<ResidencyBody>,
}

impl ProvisionTenantBody {
    /// The tenant this body asks for, in `organization_id`: names checked
    /// against `limits`, and on the platform in `default_region` when the
    /// body names no residency.
    ///
    /// # Errors
    ///
    /// A validation error for a slug, name, address, timezone, locale or
    /// residency that is not a valid one.
    pub(crate) fn into_request(
        self,
        organization_id: OrganizationId,
        limits: &DomainLimits,
        default_region: DeploymentRegion,
    ) -> Result<ProvisionTenantRequest, ApiError> {
        Ok(ProvisionTenantRequest {
            organization_id,
            slug: TenantSlug::new(self.slug, &limits.slug).map_err(ApiError::validation)?,
            display_name: DisplayName::new(self.display_name, &limits.display_name)
                .map_err(ApiError::validation)?,
            contact_email: Email::new(self.contact_email).map_err(ApiError::validation)?,
            timezone: Timezone::new(self.timezone).map_err(ApiError::validation)?,
            locale: Locale::new(self.locale).map_err(ApiError::validation)?,
            residency: ResidencyBody::residency(self.residency, default_region)?,
        })
    }
}

/// The id of a newly provisioned tenant.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ProvisionTenantResponse {
    /// The tenant's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: TenantId,
}

/// Which tenants to list.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct TenantFilterParams {
    /// Only tenants in this status: `Provisioning`, `Active`, `Suspended`,
    /// `Archived` or `Deleted`. Omit for every status.
    #[param(value_type = Option<String>)]
    pub status: Option<TenantStatus>,
}

impl TenantFilterParams {
    /// The listing asked for: these tenants, in `sort` order, the page
    /// `pagination` names.
    #[must_use]
    pub(crate) fn listing(
        &self,
        sort: SortOrder<TenantSortField>,
        pagination: PageRequest,
    ) -> ListTenantsRequest {
        ListTenantsRequest {
            status: self.status,
            sort,
            page: pagination,
        }
    }
}

/// The tenant's identity, owning organization and current provisioning state.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TenantResponse {
    /// The tenant's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: TenantId,
    /// The organization it belongs to.
    #[schema(value_type = String, format = Uuid)]
    pub organization_id: OrganizationId,
    /// URL-safe slug.
    pub slug: String,
    /// The tenant's name.
    pub display_name: String,
    /// The domain of its own it made primary, if any.
    pub primary_domain: Option<String>,
    /// Where notices about it go.
    pub contact_email: String,
    /// `Provisioning`, `Active`, `Suspended`, `Archived` or `Deleted`.
    #[schema(schema_with = crate::dto::schemas::tenant_status)]
    pub status: TenantStatus,
    /// IANA timezone.
    pub timezone: String,
    /// BCP 47 locale.
    pub locale: String,
    /// The first moment an archived tenant may be deleted. `null` unless
    /// it is archived.
    #[serde(with = "time::serde::rfc3339::option")]
    pub deletable_from: Option<OffsetDateTime>,
    /// When it was provisioned.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Where this tenant's own users sign in: the link an admin hands out.
    ///
    /// Always the platform's address, even when `primary_domain` is set:
    /// that domain is the tenant's own, claimed for identity and mail, and
    /// nothing serves a sign-in page on it.
    pub login_url: String,
    /// Where this tenant's data lives.
    pub residency: ResidencyResponse,
    /// The stage of its product it serves: `production`, `staging` or
    /// `development`.
    pub environment: &'static str,
    /// How its setup stands. A tenant whose setup failed stays
    /// `Provisioning`; this says it failed, and at which step.
    pub setup: TenantSetupResponse,
}

/// How a tenant's setup stands.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TenantSetupResponse {
    /// `running` while the tenant is provisioning and its setup goes on,
    /// `failed` when a step of it failed for good and it stopped, or `over`
    /// once the tenant left provisioning.
    pub state: &'static str,
    /// The step that failed when `state` is `failed`: `database`,
    /// `signing_key`, `assertion_key`, `starting_roles` or `activate`.
    /// `null` otherwise.
    pub failed_step: Option<&'static str>,
}

impl From<SetupStanding> for TenantSetupResponse {
    fn from(standing: SetupStanding) -> Self {
        match standing {
            SetupStanding::Running => Self {
                state: "running",
                failed_step: None,
            },
            SetupStanding::Failed(step) => Self {
                state: "failed",
                failed_step: Some(step.as_str()),
            },
            SetupStanding::Over => Self {
                state: "over",
                failed_step: None,
            },
        }
    }
}

impl TenantResponse {
    /// The tenant `read` names, with how its setup stands, its sign-in link
    /// resolved against `app_base_url` and the slug of its organization,
    /// `org_slug`.
    #[must_use]
    pub(crate) fn new(read: &TenantRead, app_base_url: &HttpsUrl, org_slug: &TenantSlug) -> Self {
        let tenant = &read.tenant;
        Self {
            setup: TenantSetupResponse::from(read.setup),
            login_url: LinkScope::tenant(org_slug.clone(), tenant.slug().clone())
                .login_url(app_base_url),
            residency: ResidencyResponse::from(tenant.residency()),
            environment: tenant.environment().as_str(),
            id: *tenant.id(),
            organization_id: *tenant.organization_id(),
            slug: tenant.slug().as_str().to_owned(),
            display_name: tenant.display_name().as_str().to_owned(),
            primary_domain: tenant
                .primary_domain()
                .map(|domain| domain.as_str().to_owned()),
            contact_email: tenant.contact_email().as_str().to_owned(),
            status: tenant.status(),
            timezone: tenant.timezone().as_str().to_owned(),
            locale: tenant.locale().as_str().to_owned(),
            deletable_from: tenant.deletable_from(),
            created_at: tenant.created_at(),
            updated_at: tenant.updated_at(),
        }
    }
}

/// Why the platform deletes an archived tenant before its grace has run.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EarlyDeletionReason {
    /// The tenant was used for abuse, such as phishing.
    Abuse,
    /// A court or regulator ordered it.
    LegalOrder,
}

/// An early deletion, with the platform's note on the record.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct EarlyDeletionBody {
    /// `abuse` or `legal_order`.
    pub reason: EarlyDeletionReason,
    /// What happened, or which order it was.
    pub note: String,
}

impl EarlyDeletionBody {
    /// Deleting `tenant_id` early for the reason this body gives.
    ///
    /// # Errors
    ///
    /// A validation error when the note is not a valid one.
    pub(crate) fn into_request(
        self,
        tenant_id: TenantId,
    ) -> Result<DeleteTenantEarlyRequest, ApiError> {
        let note = Text::new("note", self.note).map_err(ApiError::validation)?;
        let reason = match self.reason {
            EarlyDeletionReason::Abuse => EarlyDeletion::Abuse(note),
            EarlyDeletionReason::LegalOrder => EarlyDeletion::LegalOrder(note),
        };
        Ok(DeleteTenantEarlyRequest { tenant_id, reason })
    }
}

/// Whether the tenant has any usable API keys.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ApiKeysStatusResponse {
    /// Unexpired keys in `Active` status.
    pub active_count: u64,
    /// True when at least one key is usable.
    pub active: bool,
}

/// The tenant's identity, as the metrics page heads it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TenantCompanyOverview {
    /// URL-safe slug used in subdomains and API paths.
    pub slug: String,
    /// The tenant's name.
    pub display_name: String,
    /// The tenant's primary domain, if one is set.
    pub primary_domain: Option<String>,
    /// Where notices about the tenant go.
    pub contact_email: String,
    /// IANA timezone, such as `UTC`.
    pub timezone: String,
    /// Locale for sign-in pages and emails, such as `en-US`.
    pub locale: String,
    /// When the tenant was provisioned.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<&TenantLabel> for TenantCompanyOverview {
    fn from(label: &TenantLabel) -> Self {
        Self {
            slug: label.slug.as_str().to_owned(),
            display_name: label.display_name.as_str().to_owned(),
            primary_domain: label
                .primary_domain
                .as_ref()
                .map(|domain| domain.as_str().to_owned()),
            contact_email: label.contact_email.as_str().to_owned(),
            timezone: label.timezone.as_str().to_owned(),
            locale: label.locale.as_str().to_owned(),
            created_at: label.created_at,
        }
    }
}

/// The tenant metrics overview.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TenantMetricsResponse {
    /// The window these figures cover.
    pub window: MetricsWindowResponse,
    /// Composite health score in `[0, 100]`.
    pub health: u8,
    /// The tenant's lifecycle status.
    #[schema(schema_with = crate::dto::schemas::tenant_status)]
    pub status: TenantStatus,
    /// The tenant's identity.
    pub company: TenantCompanyOverview,
    /// API key availability.
    pub api_keys: ApiKeysStatusResponse,
    /// Authentication figures and charts.
    pub authentication: AuthenticationMetricsResponse,
    /// Total users.
    pub users: CountMetricResponse,
    /// Distinct users that signed in within the window.
    pub active_users: CountMetricResponse,
    /// The session count for the selected window and its change from the prior window.
    pub active_sessions: CountMetricResponse,
    /// Proxied API usage.
    pub api: ApiUsageMetricsResponse,
}

impl TenantMetricsResponse {
    /// The overview: what `label` says of the tenant, with its `metrics`.
    #[must_use]
    pub(crate) fn from_parts(label: &TenantLabel, metrics: TenantMetrics) -> Self {
        Self {
            window: metrics.window.into(),
            health: metrics.health.value(),
            status: label.status,
            company: TenantCompanyOverview::from(label),
            api_keys: ApiKeysStatusResponse {
                active_count: metrics.active_api_keys,
                active: metrics.active_api_keys > 0,
            },
            authentication: metrics.authentication.into(),
            users: metrics.users.into(),
            active_users: metrics.active_users.into(),
            active_sessions: metrics.active_sessions.into(),
            api: metrics.api.into(),
        }
    }
}
