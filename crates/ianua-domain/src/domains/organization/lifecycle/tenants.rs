//! Which tenants an organization holds: adding one within its plan's
//! limit, removing one, and asking whether it holds one.

use crate::domains::organization::billing::plan::PlanLimits;
use crate::domains::organization::events::organization::OrganizationTenantCreated;
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::control::{OrgControl, ensure_platform_or_may};
use crate::domains::organization::members::permission::{OrgPermission, TenantAction};
use crate::domains::tenant::lifecycle::Tenant;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ActedBy, EventLabel, TenantId};

impl Organization {
    /// Adds `tenant` to this organization, as `by` decides. Raises
    /// `organization.tenant_created`, naming the tenant as it is called now.
    /// A tenant it already has is left as it is, and raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the organization is closed.
    /// - [`DomainError::Forbidden`] when a member adds it without the right
    ///   to create tenants.
    /// - [`DomainError::Conflict`] when the plan allows no more tenants.
    pub fn add_tenant(
        &mut self,
        tenant: &Tenant,
        by: ActedBy<OrgControl<'_>>,
    ) -> Result<(), DomainError> {
        self.ensure_open()?;
        ensure_platform_or_may(by, &self.id, OrgPermission::Tenants(TenantAction::Create))?;
        if self.tenant_ids.contains(tenant.id()) {
            return Ok(());
        }
        ensure_plan_allows(&self.limits(), self.tenant_count().saturating_add(1))?;
        self.tenant_ids.push(*tenant.id());
        self.touch();
        self.raised.raise_organization(OrganizationTenantCreated {
            organization_id: self.id,
            tenant_id: *tenant.id(),
            tenant_label: EventLabel::of(tenant.display_name().as_str()),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Removes a tenant from this organization, as `by` decides.
    ///
    /// This works on a closed organization too. Taking a tenant away gives
    /// nobody anything, and closing down detaches the tenants one by one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a member removes it without the
    ///   right to delete tenants.
    pub fn remove_tenant(
        &mut self,
        tenant_id: &TenantId,
        by: ActedBy<OrgControl<'_>>,
    ) -> Result<(), DomainError> {
        ensure_platform_or_may(by, &self.id, OrgPermission::Tenants(TenantAction::Delete))?;
        self.tenant_ids.retain(|id| id != tenant_id);
        self.touch();
        Ok(())
    }

    /// Whether a tenant belongs to this organization.
    #[must_use]
    pub fn owns_tenant(&self, tenant_id: &TenantId) -> bool {
        self.tenant_ids.contains(tenant_id)
    }
}

/// Refuses `tenants` tenants under `limits` when they allow fewer.
pub(super) fn ensure_plan_allows(limits: &PlanLimits, tenants: usize) -> Result<(), DomainError> {
    let allowed = limits.max_tenants_per_org;
    if u32::try_from(tenants)
        .ok()
        .is_none_or(|count| count > allowed)
    {
        return Err(DomainError::conflict(message!(
            "organization-the-plan-allows-at-most-tenants",
            format!("the plan allows at most {allowed} tenants")
        )));
    }
    Ok(())
}
