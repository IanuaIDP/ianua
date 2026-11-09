//! What one member may reach: the answer a dashboard is built from.
//!
//! An owner or admin reaches every tenant of the organization with every
//! permission; a plain member reaches only the tenants they were granted,
//! with what their granted roles carry; a billing contact or viewer reaches
//! no tenant. Sign-in, the member's own view and the admin listing all
//! describe it the same way.

use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::authorization::role::effective_permissions;
use ianua_domain::domains::organization::members::membership::{OrgRole, TenantReach};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::types::{OrganizationId, RoleId, TenantId, TenantSlug};

use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::authorization::RoleStore;
use crate::ports::organization::OrgTenantGrantStore;
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;

/// The most tenants an access view lists. It is a navigation aid, not a
/// paged listing.
const MAX_TENANTS: u32 = 500;

/// One tenant a member can reach, and what they may do inside it.
#[derive(Debug, Clone)]
pub struct TenantAccess {
    /// The reachable workspace to which these permissions apply.
    pub tenant_id: TenantId,
    /// The tenant's slug, which is what URLs are built from.
    pub slug: TenantSlug,
    /// The tenant's human-facing name.
    pub display_name: String,
    /// Names of the roles the member holds here. Empty for an owner, whose
    /// access comes from their organization role.
    pub role_names: Vec<String>,
    /// Every permission the member holds in this tenant.
    pub permissions: Vec<SystemPermission>,
}

/// A member's whole reach across their organization.
#[derive(Debug, Clone)]
pub struct OrgUserAccess {
    /// The member's role in the organization.
    pub org_role: OrgRole,
    /// The tenants they can reach, with their permissions in each.
    pub tenants: Vec<TenantAccess>,
}

/// Where a member's reach is read from.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization) struct AccessSources<'a> {
    /// The organization's tenants.
    pub(in crate::use_cases::organization) tenants: &'a dyn TenantStore,
    /// The roles of each tenant, to name and expand granted roles.
    pub(in crate::use_cases::organization) roles: &'a dyn RoleStore,
    /// The tenants and roles members were granted.
    pub(in crate::use_cases::organization) grants: &'a dyn OrgTenantGrantStore,
}

impl AccessSources<'_> {
    /// What `member` reaches across their organization now.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::organization) async fn reach_of(
        &self,
        member: &OrgUser,
    ) -> Result<OrgUserAccess, AppError> {
        let tenants = match member.role().tenant_reach() {
            TenantReach::Every => self.every_tenant(member.organization_id()).await?,
            TenantReach::Granted => self.granted_tenants(member).await?,
            TenantReach::Nothing => Vec::new(),
        };
        Ok(OrgUserAccess {
            org_role: member.role(),
            tenants,
        })
    }

    async fn every_tenant(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<TenantAccess>, AppError> {
        let tenants = self
            .tenants
            .list_by_organization(
                organization_id,
                None,
                &SortOrder::default(),
                &PageRequest::first(Limit::internal(MAX_TENANTS)),
            )
            .await
            .or_internal()?
            .items;
        Ok(tenants
            .iter()
            .map(|tenant| described(tenant, Vec::new(), SystemPermission::all().to_vec()))
            .collect())
    }

    async fn granted_tenants(&self, member: &OrgUser) -> Result<Vec<TenantAccess>, AppError> {
        let grants = self.grants.list_by_user(member.id()).await.or_internal()?;
        let by_tenant = roles_by_tenant(
            grants
                .iter()
                .map(|grant| (*grant.tenant_id(), *grant.role_id())),
        );
        let mut access = Vec::with_capacity(by_tenant.len());
        for (tenant_id, role_ids) in by_tenant {
            let Some(tenant) = self.tenant_in(member.organization_id(), &tenant_id).await? else {
                continue;
            };
            access.push(self.granted(&tenant, &role_ids).await?);
        }
        Ok(access)
    }

    /// A granted tenant, or nothing when it no longer belongs to the
    /// organization: a grant never widens a view past its own organization.
    async fn tenant_in(
        &self,
        organization_id: &OrganizationId,
        tenant_id: &TenantId,
    ) -> Result<Option<Tenant>, AppError> {
        Ok(self
            .tenants
            .find_by_id(tenant_id)
            .await
            .or_internal()?
            .filter(|tenant| tenant.organization_id() == organization_id))
    }

    async fn granted(
        &self,
        tenant: &Tenant,
        role_ids: &[RoleId],
    ) -> Result<TenantAccess, AppError> {
        let roles = self
            .roles
            .find_by_ids(&ScopedTenant::from_registry(tenant), role_ids)
            .await
            .or_internal()?;
        let names = roles
            .iter()
            .map(|role| role.name().as_str().to_owned())
            .collect();
        Ok(described(tenant, names, effective_permissions(&roles)))
    }
}

/// The granted role ids, gathered under each tenant in grant order.
fn roles_by_tenant(
    grants: impl Iterator<Item = (TenantId, RoleId)>,
) -> Vec<(TenantId, Vec<RoleId>)> {
    let mut by_tenant: Vec<(TenantId, Vec<RoleId>)> = Vec::new();
    for (tenant_id, role_id) in grants {
        match by_tenant.iter_mut().find(|(id, _)| *id == tenant_id) {
            Some((_, ids)) => ids.push(role_id),
            None => by_tenant.push((tenant_id, vec![role_id])),
        }
    }
    by_tenant
}

fn described(
    tenant: &Tenant,
    role_names: Vec<String>,
    permissions: Vec<SystemPermission>,
) -> TenantAccess {
    TenantAccess {
        tenant_id: *tenant.id(),
        slug: tenant.slug().clone(),
        display_name: tenant.display_name().to_string(),
        role_names,
        permissions,
    }
}
