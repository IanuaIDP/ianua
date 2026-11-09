//! Where the links mailed to a tenant's users point, worked out from the
//! tenant's records.
//!
//! A person's request names the tenant it was made in, so the API hands its
//! use cases the scope. A directory calling SCIM, or a workflow's company
//! step, names nothing but its tenant, so its links take the slugs the
//! tenant and its organization keep, never anything a request carried.

use std::sync::Arc;

use ianua_domain::message;

use crate::email::LinkScope;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;

/// Works out a tenant's link scope from its stored slugs and its
/// organization's.
pub struct TenantLinkScopes {
    /// Reads the tenant, for its slug and organization.
    pub tenants: Arc<dyn TenantStore>,
    /// Reads the tenant's organization, for its slug.
    pub organizations: Arc<dyn OrganizationStore>,
}

impl TenantLinkScopes {
    /// The scope links mailed to `tenant`'s users carry.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant or its organization is not on
    ///   record.
    /// - `AppError::Internal` on storage failure.
    pub async fn of(&self, tenant: &ScopedTenant) -> Result<LinkScope, AppError> {
        let record = existing_tenant(self.tenants.as_ref(), tenant).await?;
        let organization = self
            .organizations
            .find_by_id(record.organization_id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-organization-not-found",
                "organization not found"
            ))?;
        Ok(LinkScope::tenant(
            organization.slug().clone(),
            record.slug().clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::organization::org_store_with;
    use crate::test_support::tenant::FakeTenantStore;
    use crate::test_support::{Fake, block_on, test_ctx};

    /// Acme's tenant `acme` belongs to the organization `acme`. Its links
    /// point at that tenant of that organization.
    #[test]
    fn a_tenants_links_carry_its_own_slugs() {
        let scopes: TenantLinkScopes = Fake::fake();

        let scope = block_on(scopes.of(&test_ctx().tenant())).unwrap();

        assert!(matches!(
            scope,
            LinkScope::Tenant { org, tenant } if org.as_str() == "acme" && tenant.as_str() == "acme"
        ));
    }

    /// Looking up an unknown tenant returns not found instead of a link scope.
    #[test]
    fn an_unknown_tenant_has_no_scope() {
        let scopes = TenantLinkScopes {
            tenants: Arc::new(FakeTenantStore::empty()),
            organizations: org_store_with([]),
        };

        let result = block_on(scopes.of(&ScopedTenant::for_test(TenantId::new())));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
