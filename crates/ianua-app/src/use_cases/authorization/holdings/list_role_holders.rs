//! List role holders: who holds one role of the tenant, given straight to
//! them, and which groups carry it to their members, a page at a time.
//!
//! Holdings whose end has passed are left out, since they grant nothing.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::shared::clock;
use ianua_domain::types::RoleId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::authorization::{RoleHolder, RoleHolderQueries, RoleStore};
use crate::services::lookup::existing_role;
use crate::use_case::Query;

/// The ports [`ListRoleHoldersUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListRoleHoldersPorts {
    /// Loads the role asked about.
    pub role_store: Arc<dyn RoleStore>,
    /// Reads the role's holders, a page at a time.
    pub role_holder_queries: Arc<dyn RoleHolderQueries>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which role's holders to list, and which page of them.
pub struct ListRoleHoldersRequest {
    /// The permission bundle whose direct and group holders are requested.
    pub role_id: RoleId,
    /// Which page: the principals given it straight first, then the groups
    /// carrying it.
    pub page: PageRequest,
}

/// Lists who holds a role of the caller's tenant.
pub struct ListRoleHoldersUseCase {
    ports: ListRoleHoldersPorts,
}

impl ListRoleHoldersUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListRoleHoldersPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListRoleHoldersUseCase {
    type Caller = CallerContext;
    type Input = ListRoleHoldersRequest;
    type Output = Result<Page<RoleHolder>, AppError>;

    /// One page of who holds `request.role_id` now: each principal given it
    /// straight, once, then each group carrying it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles.
    /// - `AppError::NotFound` when the tenant has no such role.
    /// - `AppError::Internal` when the holders cannot be read.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRoleHoldersRequest,
    ) -> Result<Page<RoleHolder>, AppError> {
        let ListRoleHoldersRequest { role_id, page } = request;
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        existing_role(self.ports.role_store.as_ref(), &tenant, &role_id).await?;
        self.ports
            .role_holder_queries
            .holders_of(&tenant, &role_id, clock::now(), &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::types::{Expiry, GroupId, PrincipalRef, UserId};
    use time::Duration;

    use super::*;
    use crate::listing::Limit;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        FakeGroupStore, FakeRoleAssignmentStore, FakeRoleHolderQueries, FakeRoleStore,
        stored_assignment, stored_assignment_until, stored_group, stored_role,
    };
    use crate::test_support::{block_on, test_ctx};

    /// "admin" is held by Ann and `extra` others, was held by Bob until an
    /// hour ago, and is carried by "Admins".
    struct Tenant {
        role_id: RoleId,
        ann: PrincipalRef,
        group_id: GroupId,
        ports: ListRoleHoldersPorts,
    }

    fn tenant_with(extra: usize) -> Tenant {
        let tenant = test_ctx().tenant_id();
        let admin = stored_role("admin", Vec::new(), Vec::new());
        let role_id = *admin.id();
        let admins = stored_group("Admins", GroupPlace::TopLevel, vec![role_id]);
        let group_id = *admins.id();
        let ann = PrincipalRef::User(UserId::new());
        let bob = PrincipalRef::User(UserId::new());
        let ended = Expiry::At(clock::now() - Duration::hours(1));
        let assignments = [
            stored_assignment(ann, role_id),
            stored_assignment_until(bob, role_id, ended),
        ]
        .into_iter()
        .chain((0..extra).map(|_| stored_assignment(PrincipalRef::User(UserId::new()), role_id)));
        let queries = FakeRoleHolderQueries {
            assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, assignments)),
            groups: Arc::new(FakeGroupStore::holding(tenant, [admins])),
        };
        Tenant {
            role_id,
            ann,
            group_id,
            ports: ListRoleHoldersPorts {
                role_store: Arc::new(FakeRoleStore::holding(tenant, [admin])),
                role_holder_queries: Arc::new(queries),
                ..ListRoleHoldersPorts::fakes()
            },
        }
    }

    fn tenant() -> Tenant {
        tenant_with(0)
    }

    fn list_page(
        ports: ListRoleHoldersPorts,
        role_id: RoleId,
        page: PageRequest,
    ) -> Result<Page<RoleHolder>, AppError> {
        let request = ListRoleHoldersRequest { role_id, page };
        block_on(ListRoleHoldersUseCase::new(ports).execute(&test_ctx(), request))
    }

    fn list(ports: ListRoleHoldersPorts, role_id: RoleId) -> Result<Page<RoleHolder>, AppError> {
        list_page(ports, role_id, PageRequest::default())
    }

    /// Ann asks who holds "admin". She sees herself and "Admins"; Bob's
    /// ended assignment is not listed.
    #[test]
    fn the_holders_and_the_groups_carrying_a_role_are_listed() {
        let tenant = tenant();

        let holders = list(tenant.ports, tenant.role_id).unwrap();

        assert_eq!(
            holders.items,
            [
                RoleHolder::Direct(tenant.ann),
                RoleHolder::Group(tenant.group_id)
            ]
        );
    }

    /// "admin" is held by Ann and 24 others, and carried by "Admins". Ann
    /// reads them 20 at a time: the first page holds twenty people, the
    /// second the last five and the group.
    #[test]
    fn holders_are_listed_a_page_at_a_time() {
        let tenant = tenant_with(24);
        let ports = ListRoleHoldersPorts {
            role_store: tenant.ports.role_store.clone(),
            role_holder_queries: tenant.ports.role_holder_queries.clone(),
            tenant_authorities: tenant.ports.tenant_authorities.clone(),
        };

        let asked = PageRequest::first(Limit::new(20).unwrap());

        let first = list_page(ports, tenant.role_id, asked.clone()).unwrap();
        let next = asked.following(&first).unwrap();
        let second = list_page(tenant.ports, tenant.role_id, next).unwrap();

        assert_eq!(first.items.len(), 20);
        assert_eq!(second.items.len(), 6);
        assert!(!second.has_next());
        assert!(second.items.iter().all(|held| !first.items.contains(held)));
        assert_eq!(
            second.items.last(),
            Some(&RoleHolder::Group(tenant.group_id))
        );
    }

    /// Ann asks about a role the tenant does not have. It is not found.
    #[test]
    fn an_unknown_role_is_not_found() {
        let tenant = tenant();

        let result = list(tenant.ports, RoleId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Listing admin role holders requires role view permission.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let tenant = tenant();
        let ports = ListRoleHoldersPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports
        };

        assert!(matches!(
            list(ports, tenant.role_id),
            Err(AppError::Forbidden(_))
        ));
    }

    /// A signed-out session cannot list role holders.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = tenant();
        let ports = ListRoleHoldersPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports
        };

        assert!(matches!(
            list(ports, tenant.role_id),
            Err(AppError::Unauthenticated)
        ));
    }
}
