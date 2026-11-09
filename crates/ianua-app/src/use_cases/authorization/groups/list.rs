//! List groups: the tenant's groups, a page at a time.

use std::sync::Arc;

use ianua_domain::domains::authorization::group::Group;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::authorization::{GroupSortField, GroupStore};
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Loads groups.
    pub group_store: Arc<dyn GroupStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// The order and page of groups to list.
pub struct ListRequest {
    /// The field and direction to order by.
    pub sort: SortOrder<GroupSortField>,
    /// Which page of the ordered groups to return.
    pub page: PageRequest,
}

/// Lists the groups of the caller's tenant.
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
    type Output = Result<Page<Group<ResolvedTenant>>, AppError>;

    /// One page of the tenant's groups, in the order asked for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles, which
    ///   covers groups.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<Group<ResolvedTenant>>, AppError> {
        let ListRequest { sort, page } = request;
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .group_store
            .list_all(&ctx.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeGroupStore, stored_group};
    use crate::test_support::{block_on, test_ctx};

    fn groups(names: &[&str]) -> Arc<FakeGroupStore> {
        Arc::new(FakeGroupStore::holding(
            test_ctx().tenant_id(),
            names
                .iter()
                .map(|name| stored_group(name, GroupPlace::TopLevel, Vec::new())),
        ))
    }

    fn list(
        ports: ListPorts,
        sort: SortOrder<GroupSortField>,
    ) -> Result<Page<Group<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(
            &test_ctx(),
            ListRequest {
                sort,
                page: PageRequest::default(),
            },
        ))
    }

    /// A tenant with no groups lists none.
    #[test]
    fn a_tenant_without_groups_lists_none() {
        let page = list(ListPorts::fakes(), SortOrder::default()).unwrap();

        assert!(page.is_empty());
    }

    /// Ann lists a tenant with "Engineering" and "Sales". Both are on the
    /// page.
    #[test]
    fn every_group_is_listed() {
        let ports = ListPorts {
            group_store: groups(&["Engineering", "Sales"]),
            ..ListPorts::fakes()
        };

        let page = list(ports, SortOrder::default()).unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(!page.has_next());
    }

    /// Ann lists groups by name, last first. "Gamma" leads and "Alpha" ends
    /// the page.
    #[test]
    fn groups_are_ordered_as_asked() {
        let ports = ListPorts {
            group_store: groups(&["Alpha", "Gamma", "Beta"]),
            ..ListPorts::fakes()
        };
        let sort = SortOrder::single(Sort::descending(GroupSortField::Name));

        let page = list(ports, sort).unwrap();

        assert_eq!(page.items[0].name().as_str(), "Gamma");
        assert_eq!(page.items[2].name().as_str(), "Alpha");
    }

    /// Listing groups requires role view permission, even when an admin group exists.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let ports = ListPorts {
            group_store: groups(&["Admins"]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ListPorts::fakes()
        };

        let result = list(ports, SortOrder::default());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list the tenant's groups.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ListPorts::fakes()
        };

        let result = list(ports, SortOrder::default());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
