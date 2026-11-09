//! Rows of the tenant context.

use ianua_domain::domains::tenant::access::auth_config::TenantAuthConfig;
use ianua_domain::domains::tenant::access::network_security::MtlsConfig;
use ianua_domain::domains::tenant::compliance::CompliancePosture;
use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
use ianua_domain::domains::tenant::environment::TenantEnvironment;
use ianua_domain::domains::tenant::hosts::{PlatformLabel, ReadableAddress};
use ianua_domain::domains::tenant::lifecycle::TenantRow;
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    DeploymentRegion, TenantResidency,
};
use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};
use ianua_domain::shared::config::{DisplayNameLimits, SlugLimits};
use ianua_domain::types::{
    DisplayName, Email, Locale, OrganizationId, Setting, TenantId, TenantSlug, Timezone,
};

use crate::crypto::OsRandomSource;
use crate::test_support::rows::at;

/// An active tenant of `organization` under `slug`, named after it, on
/// the platform's shared database.
///
/// # Panics
///
/// When `slug` is not a valid one, which is a mistake in the test.
#[must_use]
pub fn tenant_row(organization: OrganizationId, slug: &str) -> TenantRow {
    TenantRow {
        id: TenantId::new(),
        organization_id: organization,
        slug: TenantSlug::new(slug, &SlugLimits::default()).expect("a valid slug"),
        platform_label: PlatformLabel::generate(&mut OsRandomSource).expect("bounded randomness"),
        readable_address: ReadableAddress::Off,
        display_name: DisplayName::new(slug, &DisplayNameLimits::default()).expect("a valid name"),
        primary_domain: Setting::Unset,
        contact_email: Email::new("admin@acme.example").expect("a valid address"),
        status: TenantStatus::Active,
        hold: PlatformHold::Free,
        archival: Archival::NotArchived,
        compliance: CompliancePosture::default_from(&ComplianceLimits::default()),
        auth_config: TenantAuthConfig::default(),
        mtls: MtlsConfig::disabled(),
        timezone: Timezone::new("UTC").expect("a valid timezone"),
        locale: Locale::new("en-US").expect("a valid locale"),
        residency: TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1),
        environment: TenantEnvironment::Production,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// The row of a tenant of `organization` under `slug`, deleted after being
/// archived.
#[must_use]
pub fn deleted_tenant_row(organization: OrganizationId, slug: &str) -> TenantRow {
    TenantRow {
        status: TenantStatus::Deleted,
        archival: Archival::Since(at(1)),
        updated_at: at(2),
        ..tenant_row(organization, slug)
    }
}
