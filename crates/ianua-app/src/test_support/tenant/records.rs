//! Test tenants, read back as storage keeps them.

use std::sync::Arc;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::tenant::access::auth_config::{TenantAuthConfig, TenantAuthSettings};
use ianua_domain::domains::tenant::access::network_security::MtlsConfig;
use ianua_domain::domains::tenant::compliance::{CompliancePosture, OperatorImpersonation};
use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
use ianua_domain::domains::tenant::environment::TenantEnvironment;
use ianua_domain::domains::tenant::hosts::{PlatformLabel, ReadableAddress};
use ianua_domain::domains::tenant::lifecycle::{Tenant, TenantRow};
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    DeploymentRegion, IsolationLevel, Placement, TenantResidency,
};
use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};
use ianua_domain::shared::clock;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{
    DisplayName, DomainName, Email, Locale, OrganizationId, PasswordPolicy, Setting, TenantId,
    TenantSlug, Timezone,
};

use crate::test_support::tenant::FakeTenantStore;
use crate::test_support::test_ctx;

/// Shared domain limits for tests.
#[must_use]
pub fn cfg() -> DomainLimits {
    DomainLimits::default()
}

/// The residency every test tenant gets unless it is testing residency
/// itself: our infrastructure, shared database, Frankfurt.
#[must_use]
pub fn test_residency() -> TenantResidency {
    TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1)
}

/// A tenant still being provisioned, under `slug`, served on `domain`.
#[must_use]
pub fn test_tenant(slug: &str, domain: &str) -> Tenant {
    test_tenant_in(OrganizationId::new(), slug, domain)
}

/// [`test_tenant`], belonging to `organization_id`.
#[must_use]
pub fn test_tenant_in(organization_id: OrganizationId, slug: &str, domain: &str) -> Tenant {
    test_tenant_with_id(TenantId::new(), organization_id, slug, domain)
}

/// [`test_tenant_in`], under the id `id`.
///
/// # Panics
///
/// If `slug` or `domain` is not valid. Tests pass literals that are.
#[must_use]
pub fn test_tenant_with_id(
    id: TenantId,
    organization_id: OrganizationId,
    slug: &str,
    domain: &str,
) -> Tenant {
    let mut row = tenant_row(id, organization_id, slug);
    row.primary_domain = Setting::Set(DomainName::new(domain).expect("a valid domain"));
    row.contact_email = Email::new(format!("admin@{domain}")).expect("a valid address");
    Tenant::reconstitute(row).expect("a provisioning tenant is a consistent row")
}

/// A tenant whose id is the one [`test_ctx`] carries, still being
/// provisioned, with no primary domain.
///
/// Use cases look the tenant up by the id in their caller context, so a
/// store seeded with a randomly identified tenant answers `None`.
#[must_use]
pub fn test_tenant_for_ctx() -> Tenant {
    tenant_for_ctx_signing_in_with(TenantAuthSettings::default())
}

/// [`test_tenant_for_ctx`], letting operators act as its users or not as
/// `impersonation` says.
#[must_use]
pub fn test_tenant_for_ctx_with(impersonation: OperatorImpersonation) -> Tenant {
    let ctx = test_ctx();
    let limits = ComplianceLimits::default();
    let mut row = tenant_row(ctx.tenant_id(), ctx.organization_id(), "acme");
    row.compliance = CompliancePosture::new(
        limits.default_data_residency(),
        limits.default_retention_days(),
        impersonation,
        &limits,
    )
    .expect("the default retention lies inside the limits");
    Tenant::reconstitute(row).expect("a provisioning tenant is a consistent row")
}

/// A store holding [`test_tenant_for_ctx`] under the password rules
/// `password_policy`.
#[must_use]
pub fn tenant_store_with_password_policy(password_policy: PasswordPolicy) -> Arc<FakeTenantStore> {
    let tenant = tenant_for_ctx_signing_in_with(TenantAuthSettings {
        password_policy,
        ..TenantAuthSettings::default()
    });
    Arc::new(FakeTenantStore::holding(tenant))
}

/// A store holding [`test_tenant_for_ctx`], signing users in by passkey
/// only.
#[must_use]
pub fn tenant_store_without_password_login() -> Arc<FakeTenantStore> {
    let tenant = tenant_for_ctx_signing_in_with(TenantAuthSettings {
        enabled_methods: vec![AuthMethod::Passkey],
        ..TenantAuthSettings::default()
    });
    Arc::new(FakeTenantStore::holding(tenant))
}

/// A store holding [`test_tenant_for_ctx`], signing users in under
/// `settings`.
#[must_use]
pub fn tenant_store_signing_in_with(settings: TenantAuthSettings) -> Arc<FakeTenantStore> {
    Arc::new(FakeTenantStore::holding(tenant_for_ctx_signing_in_with(
        settings,
    )))
}

/// A store holding [`test_tenant_for_ctx`] in `status`, taken out of service
/// by its organization rather than by the platform.
///
/// # Panics
///
/// If `status` is archived or deleted, which needs an archive time this
/// tenant does not have.
#[must_use]
pub fn tenant_store_in_status(status: TenantStatus) -> Arc<FakeTenantStore> {
    let tenant = tenant_for_ctx_standing(status, PlatformHold::Free, Archival::NotArchived);
    Arc::new(FakeTenantStore::holding(tenant))
}

/// [`test_tenant_for_ctx`], archived `days_ago` days ago and held by the
/// platform or not as `hold` says.
#[must_use]
pub fn archived_tenant_for_ctx(days_ago: i64, hold: PlatformHold) -> Tenant {
    let ctx = test_ctx();
    let archived_at = clock::now() - time::Duration::days(days_ago);
    let mut row = tenant_row(ctx.tenant_id(), ctx.organization_id(), "acme");
    row.status = TenantStatus::Archived;
    row.hold = hold;
    row.archival = Archival::Since(archived_at);
    row.created_at = archived_at - time::Duration::days(1);
    row.updated_at = archived_at;
    Tenant::reconstitute(row).expect("an archived tenant is a consistent row")
}

/// [`test_tenant_for_ctx`] in `status`, held by the platform or not as
/// `hold` says, and archived as `archival` says.
///
/// # Panics
///
/// If the three contradict each other, as for an archived tenant with no
/// archive time or an active one the platform holds.
#[must_use]
pub fn tenant_for_ctx_standing(
    status: TenantStatus,
    hold: PlatformHold,
    archival: Archival,
) -> Tenant {
    let ctx = test_ctx();
    let mut row = tenant_row(ctx.tenant_id(), ctx.organization_id(), "acme");
    row.status = status;
    row.hold = hold;
    row.archival = archival;
    Tenant::reconstitute(row).expect("the standing is one a tenant can have")
}

/// The tenant `id` of `organization_id` under `slug`, still being
/// provisioned, signing users in under `settings`.
///
/// # Panics
///
/// If `slug` is not valid or `settings` do not hold together. Tests pass
/// ones that are.
#[must_use]
pub fn test_tenant_signing_in_with(
    id: TenantId,
    organization_id: OrganizationId,
    slug: &str,
    settings: TenantAuthSettings,
) -> Tenant {
    let mut row = tenant_row(id, organization_id, slug);
    row.auth_config = TenantAuthConfig::new(settings).expect("test sign-in settings hold");
    Tenant::reconstitute(row).expect("a provisioning tenant is a consistent row")
}

/// [`test_tenant_for_ctx`], signing users in under `settings`.
///
/// # Panics
///
/// If `settings` break the sign-in rules, which no test passes.
#[must_use]
pub fn tenant_for_ctx_signing_in_with(settings: TenantAuthSettings) -> Tenant {
    let ctx = test_ctx();
    let mut row = tenant_row(ctx.tenant_id(), ctx.organization_id(), "acme");
    row.display_name = DisplayName::new("Acme", &cfg().display_name).expect("a valid name");
    row.auth_config = TenantAuthConfig::new(settings).expect("test sign-in settings hold");
    Tenant::reconstitute(row).expect("a provisioning tenant is a consistent row")
}

/// A tenant still being provisioned, with a schema of its own on our
/// infrastructure in Frankfurt, so its setup makes its database first.
///
/// # Panics
///
/// Never in practice: the residency and the row are consistent.
#[must_use]
pub fn test_tenant_apart() -> Tenant {
    let mut row = tenant_row(TenantId::new(), OrganizationId::new(), "apart");
    row.residency = TenantResidency::new(
        Placement::Platform {
            region: DeploymentRegion::EuCentral1,
        },
        IsolationLevel::DedicatedSchema,
    )
    .expect("a schema of its own on our infrastructure is a residency");
    Tenant::reconstitute(row).expect("a provisioning tenant is a consistent row")
}

/// A tenant deleted after its archive, on the platform's database.
///
/// # Panics
///
/// Never in practice: a deleted row with its archive time is consistent.
#[must_use]
pub fn test_tenant_deleted() -> Tenant {
    let row = tenant_row(TenantId::new(), OrganizationId::new(), "gone");
    Tenant::reconstitute(deleted_row(row)).expect("a deleted tenant is a consistent row")
}

/// [`test_tenant_deleted`], with a schema of its own on our infrastructure
/// in Frankfurt, so its teardown moves its audit trail and removes its
/// database.
///
/// # Panics
///
/// Never in practice: the residency and the row are consistent.
#[must_use]
pub fn test_tenant_deleted_apart() -> Tenant {
    let mut row = tenant_row(TenantId::new(), OrganizationId::new(), "gone-apart");
    row.residency = TenantResidency::new(
        Placement::Platform {
            region: DeploymentRegion::EuCentral1,
        },
        IsolationLevel::DedicatedSchema,
    )
    .expect("a schema of its own on our infrastructure is a residency");
    Tenant::reconstitute(deleted_row(row)).expect("a deleted tenant is a consistent row")
}

/// `row`, deleted once its archive began.
fn deleted_row(row: TenantRow) -> TenantRow {
    TenantRow {
        status: TenantStatus::Deleted,
        archival: Archival::Since(row.created_at),
        ..row
    }
}

/// A provisioning tenant's row, under `slug` and named after it.
fn tenant_row(id: TenantId, organization_id: OrganizationId, slug: &str) -> TenantRow {
    let limits = cfg();
    let now = clock::now();
    TenantRow {
        id,
        organization_id,
        slug: TenantSlug::new(slug, &limits.slug).expect("a valid slug"),
        platform_label: PlatformLabel::new(id.as_uuid().simple().to_string()[16..].to_owned())
            .expect("the fixture id has sixteen hexadecimal tail characters"),
        readable_address: ReadableAddress::Off,
        display_name: DisplayName::new(slug, &limits.display_name).expect("a valid name"),
        primary_domain: Setting::Unset,
        contact_email: Email::new("admin@acme.com").expect("a valid address"),
        status: TenantStatus::Provisioning,
        hold: PlatformHold::Free,
        archival: Archival::NotArchived,
        compliance: CompliancePosture::default_from(&ComplianceLimits::default()),
        auth_config: TenantAuthConfig::default(),
        mtls: MtlsConfig::disabled(),
        timezone: Timezone::new("UTC").expect("a valid timezone"),
        locale: Locale::new("en-US").expect("a valid locale"),
        residency: test_residency(),
        environment: TenantEnvironment::Production,
        created_at: now,
        updated_at: now,
    }
}
