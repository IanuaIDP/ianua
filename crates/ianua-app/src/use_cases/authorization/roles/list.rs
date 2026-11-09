//! List roles: the tenant's roles, each with how many hold it.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::isolation::scope::{ResolvedTenant, TenantScope};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::authorization::{RoleAssignmentStore, RoleSortField, RoleStore};
use crate::use_case::Query;

/// A role paired with the number of principals it is given to directly.
#[derive(Debug, Clone)]
pub struct WithAssignments<T: TenantScope> {
    /// The permission definition accompanied by its direct-holder count.
    pub role: Role<T>,
    /// How many principals the role is given to directly.
    pub assigned_user_count: u64,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Loads roles.
    pub role_store: Arc<dyn RoleStore>,
    /// Counts who each role is given to.
    pub role_assignment_store: Arc<dyn RoleAssignmentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// The order and page of roles to list.
pub struct ListRequest {
    /// The field and direction to order by.
    pub sort: SortOrder<RoleSortField>,
    /// Which page of the ordered roles to return.
    pub page: PageRequest,
}

/// Lists the roles of the caller's tenant.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Page<WithAssignments<ResolvedTenant>>, AppError>;

    /// One page of the tenant's roles, in the order asked for, each with how
    /// many principals hold it directly.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<WithAssignments<ResolvedTenant>>, AppError> {
        let ListRequest { sort, page } = request;
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        let roles = self
            .ports
            .role_store
            .list_all(&ctx.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)?;
        let role_ids: Vec<_> = roles.items.iter().map(|role| *role.id()).collect();
        let counts = self
            .ports
            .role_assignment_store
            .count_by_roles(&ctx.tenant(), &role_ids)
            .await
            .or_internal()?;
        Ok(roles.map(|role| WithAssignments {
            assigned_user_count: counts.get(role.id()).copied().unwrap_or(0),
            role,
        }))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole};
    use ianua_domain::domains::authorization::role_assignment::{
        RoleAssignment, RoleAssignmentRow,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ActorRef, Expiry, Label, PrincipalRef, RoleId, UserId};

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeRoleAssignmentStore, FakeRoleStore};
    use crate::test_support::{block_on, test_ctx};

    fn role(name: &str) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", name).unwrap(),
            system_permissions: Vec::new(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn given(role_id: RoleId) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(UserId::new()),
            role_id,
            assigned_by: ActorRef::System,
            assigned_at: clock::now(),
            expires: Expiry::Never,
        })
        .unwrap()
    }

    fn roles(names: &[&str]) -> Arc<FakeRoleStore> {
        Arc::new(FakeRoleStore::holding(
            test_ctx().tenant_id(),
            names.iter().map(|name| role(name)),
        ))
    }

    fn first_page(sort: SortOrder<RoleSortField>) -> ListRequest {
        ListRequest {
            sort,
            page: PageRequest::default(),
        }
    }

    fn list(ports: ListPorts) -> Result<Page<WithAssignments<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(&test_ctx(), first_page(SortOrder::default())))
    }

    /// A tenant with no roles lists none.
    #[test]
    fn a_tenant_without_roles_lists_none() {
        let page = list(ListPorts::fakes()).unwrap();

        assert!(page.is_empty());
    }

    /// Ann lists the roles of a tenant with "admin" and "viewer". Both are
    /// on the page.
    #[test]
    fn every_role_is_listed() {
        let page = list(ListPorts {
            role_store: roles(&["admin", "viewer"]),
            ..ListPorts::fakes()
        })
        .unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(!page.has_next());
    }

    /// Ann lists roles by name, last first. "gamma" leads and "alpha" ends
    /// the page.
    #[test]
    fn roles_are_ordered_as_asked() {
        let uc = ListUseCase::new(ListPorts {
            role_store: roles(&["alpha", "gamma", "beta"]),
            ..ListPorts::fakes()
        });
        let sort = SortOrder::single(Sort::descending(RoleSortField::Name));

        let page = block_on(uc.execute(&test_ctx(), first_page(sort))).unwrap();

        assert_eq!(page.items[0].role.name().as_str(), "gamma");
        assert_eq!(page.items[2].role.name().as_str(), "alpha");
    }

    /// Three people hold "admin" and nobody holds "viewer". The listing says
    /// so for each.
    #[test]
    fn each_role_shows_how_many_hold_it() {
        let admin = role("admin");
        let admin_id = *admin.id();
        let tenant = test_ctx().tenant_id();
        let page = list(ListPorts {
            role_store: Arc::new(FakeRoleStore::holding(tenant, [admin, role("viewer")])),
            role_assignment_store: Arc::new(FakeRoleAssignmentStore::holding(
                tenant,
                (0..3).map(|_| given(admin_id)),
            )),
            ..ListPorts::fakes()
        })
        .unwrap();

        let count_of = |name: &str| {
            page.items
                .iter()
                .find(|item| item.role.name().as_str() == name)
                .map(|item| item.assigned_user_count)
        };
        assert_eq!(count_of("admin"), Some(3));
        assert_eq!(count_of("viewer"), Some(0));
    }

    /// Listing roles requires role-view permission; a caller without it
    /// receives a forbidden result.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let result = list(ListPorts {
            role_store: roles(&["admin"]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ListPorts::fakes()
        });

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Signed-out authority cannot list roles and receives unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ListPorts::fakes()
        });

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
