//! List resource types: read the tenant's permission catalogue.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::resource_type::ResourceType;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::authorization::{ResourceTypeSortField, ResourceTypeStore};
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Loads the catalogue.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// The order and page of resource types to list.
pub struct ListRequest {
    /// The field and direction to order by.
    pub sort: SortOrder<ResourceTypeSortField>,
    /// Which page of the ordered catalogue to return.
    pub page: PageRequest,
}

/// Lists the permission catalogue of the caller's tenant.
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
    type Output = Result<Page<ResourceType<ResolvedTenant>>, AppError>;

    /// One page of the catalogue, in the order asked for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles, whose
    ///   permissions the catalogue declares.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<ResourceType<ResolvedTenant>>, AppError> {
        let ListRequest { sort, page } = request;
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .resource_type_store
            .list_all(&ctx.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::Limit;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::{block_on, test_ctx};

    fn list(ports: ListPorts) -> Result<Page<ResourceType<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(
            &test_ctx(),
            ListRequest {
                sort: SortOrder::default(),
                page: PageRequest::first(Limit::new(20).unwrap()),
            },
        ))
    }

    fn declaring_two() -> ListPorts {
        ListPorts {
            resource_type_store: Arc::new(FakeResourceTypeStore::seeded(test_ctx().tenant_id())),
            ..ListPorts::fakes()
        }
    }

    /// The tenant declares `project` and `billing`. Ann lists both.
    #[test]
    fn the_whole_catalogue_is_listed() {
        let page = list(declaring_two()).unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(!page.has_next());
    }

    /// A tenant that declared nothing lists nothing.
    #[test]
    fn an_empty_catalogue_lists_nothing() {
        let page = list(ListPorts::fakes()).unwrap();

        assert_eq!(page.items.len(), 0);
        assert!(page.items.is_empty());
    }

    /// Listing the permission catalogue is forbidden without role view permission.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..declaring_two()
        };

        let result = list(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the resource catalogue.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..declaring_two()
        };

        let result = list(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
