//! The roles a member could be given in one tenant, read by someone who
//! may manage tenant access.
//!
//! An organization session works in one tenant at a time, while the form
//! that gives access lists every tenant. So this read asks for the
//! organization's right, not a right inside the tenant, and gives back
//! names only: what the person giving access picks from.

use std::sync::Arc;

use ianua_domain::domains::organization::members::permission::{OrgPermission, TenantAccessAction};
use ianua_domain::types::{Label, TenantSlug};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::listing::{Page, PageRequest, Sort, SortOrder};
use crate::ports::authorization::{RoleSortField, RoleStore};
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::organization::lookup::existing_tenant_named;

/// Which tenant's roles to read, and which page of them.
pub struct ListGrantableRolesRequest {
    /// The tenant, named by its slug within the organization.
    pub tenant_slug: TenantSlug,
    /// Which page of the role names to return.
    pub page: PageRequest,
}

/// The ports [`ListGrantableRolesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListGrantableRolesPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Tenants, to find the one the slug names.
    pub tenants: Arc<dyn TenantStore>,
    /// The tenant's roles.
    pub roles: Arc<dyn RoleStore>,
}

/// Lists the names of the roles one tenant offers.
pub struct ListGrantableRolesUseCase {
    ports: ListGrantableRolesPorts,
}

impl ListGrantableRolesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListGrantableRolesPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListGrantableRolesUseCase {
    type Caller = OrgCaller;
    type Input = ListGrantableRolesRequest;
    type Output = Result<Page<Label>, AppError>;

    /// One page of the tenant's role names, in name order. The caller's
    /// right is asked for first, so someone without it cannot learn which
    /// tenants exist.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without tenant-access rights.
    /// - `AppError::NotFound` for a tenant outside the organization; `Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        request: ListGrantableRolesRequest,
    ) -> Result<Page<Label>, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::TenantAccess(TenantAccessAction::Manage),
            )
            .map_err(AppError::from_domain)?;
        let tenants = self.ports.tenants.as_ref();
        let tenant =
            existing_tenant_named(tenants, organization.id(), &request.tenant_slug).await?;
        let by_name = SortOrder::single(Sort::ascending(RoleSortField::Name));
        let roles = self
            .ports
            .roles
            .list_all(
                &ScopedTenant::from_registry(&tenant),
                &by_name,
                &request.page,
            )
            .await
            .or_internal()?;
        Ok(roles.map(|role| role.name().clone()))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::listing::Limit;
    use crate::test_support::acting::FakeOrgActors;
    use crate::test_support::authorization::{FakeRoleStore, stored_role};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{block_on, test_org_caller};

    /// Acme's production tenant, holding a Viewer and an Editor role, read
    /// by someone in `role`.
    fn use_case_as(role: OrgRole) -> ListGrantableRolesUseCase {
        let org_id = test_org_caller().organization_id();
        let tenant = test_tenant_in(org_id, "production", "production.test");
        let tenant_id = *tenant.id();
        let viewer = stored_role("Viewer", vec![SystemPermission::all()[1]], Vec::new());
        let editor = stored_role("Editor", vec![SystemPermission::all()[0]], Vec::new());
        ListGrantableRolesUseCase::new(ListGrantableRolesPorts {
            org_actors: Arc::new(FakeOrgActors::in_role(role).owning(&[tenant_id])),
            tenants: Arc::new(FakeTenantStore::holding(tenant)),
            roles: Arc::new(FakeRoleStore::holding(tenant_id, [viewer, editor])),
        })
    }

    fn names_in(
        use_case: &ListGrantableRolesUseCase,
        tenant: &str,
    ) -> Result<Vec<String>, AppError> {
        let request = ListGrantableRolesRequest {
            tenant_slug: TenantSlug::new(tenant, &DomainLimits::default().slug).unwrap(),
            page: PageRequest::first(Limit::internal(50)),
        };
        let page = block_on(use_case.execute(&test_org_caller(), request))?;
        Ok(page.items.iter().map(ToString::to_string).collect())
    }

    /// Olivia, an owner, is giving Sam access and reads production's roles
    /// without opening a session there.
    #[test]
    fn an_owner_reads_a_tenants_role_names_in_name_order() {
        let use_case = use_case_as(OrgRole::Owner);

        let names = names_in(&use_case, "production").unwrap();

        assert_eq!(names, ["Editor", "Viewer"]);
    }

    /// Sam, a plain member, may not give access, so he may not read the
    /// roles it is given in.
    #[test]
    fn a_member_who_may_not_give_access_is_refused() {
        let use_case = use_case_as(OrgRole::Member);

        let result = names_in(&use_case, "production");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Sam asks about a tenant that does not exist and is refused all the
    /// same, so the answer does not tell him which tenants do.
    #[test]
    fn without_the_right_a_missing_tenant_is_refused_too() {
        let use_case = use_case_as(OrgRole::Member);

        let result = names_in(&use_case, "nowhere");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Olivia names a tenant her organization does not have.
    #[test]
    fn a_tenant_outside_the_organization_is_not_found() {
        let use_case = use_case_as(OrgRole::Owner);

        let result = names_in(&use_case, "nowhere");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
