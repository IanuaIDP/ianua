//! The organization's tenants: the first one founded with it, the others
//! provisioned by the owner.

use ianua_app::use_case::Command as _;
use ianua_app::use_cases::tenant::lifecycle::ProvisionTenantRequest;
use ianua_app::use_cases::tenant::lifecycle::steward::TenantSteward;
use ianua_domain::domains::tenant::provisioning::infrastructure::TenantResidency;
use ianua_domain::types::{DisplayName, Email, Locale, TenantSlug, Timezone};

use crate::demo::DemoError;
use crate::demo::catalog::{self, TenantSeed};
use crate::demo::seeder::{DemoTenant, Seed, Seeder};

/// The tenant `seed` names, found by its slug in the organization, or
/// provisioned by the owner on the shared platform.
///
/// # Errors
///
/// [`DemoError`] when the tenant cannot be looked up or provisioned.
pub(super) async fn tenant(
    seeder: &Seeder<'_>,
    seed: &TenantSeed,
) -> Result<Seed<DemoTenant>, DemoError> {
    let slug = TenantSlug::new(seed.slug, &seeder.limits().slug)?;
    let organization = &seeder.organization.id;
    let tenants = seeder.adapters.tenant_store.as_ref();
    if let Some(found) = tenants.find_by_slug_in_org(&slug, organization).await? {
        return Ok(Seed::Found(DemoTenant {
            id: *found.id(),
            slug,
        }));
    }
    let request = provision_request(seeder, seed, slug.clone())?;
    let acting = seeder.in_organization().await?;
    let steward = TenantSteward::Member(acting.caller);
    let provision = seeder.state.tenant.lifecycle.provision.as_ref();
    let id = seeder
        .kept(
            "a tenant",
            provision.execute(&steward, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(DemoTenant { id, slug }))
}

/// What provisioning the tenant `seed` names takes.
fn provision_request(
    seeder: &Seeder<'_>,
    seed: &TenantSeed,
    slug: TenantSlug,
) -> Result<ProvisionTenantRequest, DemoError> {
    let region = seeder.settings.compliance_limits.default_region();
    Ok(ProvisionTenantRequest {
        organization_id: seeder.organization.id,
        slug,
        display_name: DisplayName::new(seed.name, &seeder.limits().display_name)?,
        contact_email: Email::new(catalog::OWNER_EMAIL)?,
        timezone: Timezone::new(catalog::TIMEZONE)?,
        locale: Locale::new(catalog::LOCALE)?,
        residency: TenantResidency::shared_on_platform(region),
    })
}
