//! List domains: the tenant's registered domains, a page at a time.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::domain::{DomainSortField, RegisteredDomainStore};
use crate::use_case::Query;

/// In what order to list the tenant's domains, and which page of them.
pub struct ListDomainsRequest {
    /// The fields and directions to order by.
    pub sort: SortOrder<DomainSortField>,
    /// Which page of the ordered domains to return.
    pub page: PageRequest,
}

/// The ports [`ListDomainsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListDomainsPorts {
    /// Lists the tenant's registrations.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists a tenant's domains with ordering and pagination.
pub struct ListDomainsUseCase {
    ports: ListDomainsPorts,
}

impl ListDomainsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListDomainsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListDomainsUseCase {
    type Caller = CallerContext;
    type Input = ListDomainsRequest;
    type Output = Result<Page<RegisteredDomain<ResolvedTenant>>, AppError>;

    /// The caller's tenant's domains in the order and page asked for, once
    /// they may view its domains.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view domains.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        request: ListDomainsRequest,
    ) -> Result<Page<RegisteredDomain<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Domains(DomainAction::View))
            .map_err(AppError::from_domain)?;
        let ListDomainsRequest { sort, page } = request;
        self.ports
            .domain_store
            .list_by_tenant(&caller.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{DomainSeed, FakeDomainStore};
    use crate::test_support::{block_on, test_ctx};

    fn store() -> FakeDomainStore {
        let store = FakeDomainStore::holding(
            test_ctx().tenant_id(),
            [
                DomainSeed::pending("b.acme.test").build(),
                DomainSeed::verified("a.acme.test").build(),
            ],
        );
        block_on(store.save(
            &crate::tenancy::ScopedTenant::for_test(TenantId::new()),
            &DomainSeed::pending("globex.test").build(),
        ))
        .unwrap();
        store
    }

    fn use_case_with(authorities: FakeTenantAuthorities) -> ListDomainsUseCase {
        ListDomainsUseCase::new(ListDomainsPorts {
            domain_store: Arc::new(store()),
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn request(sort: SortOrder<DomainSortField>) -> ListDomainsRequest {
        ListDomainsRequest {
            sort,
            page: PageRequest::default(),
        }
    }

    /// Ann lists Acme's domains. She sees Acme's two and not Globex's.
    #[test]
    fn the_tenants_own_domains_are_listed() {
        let use_case = use_case_with(FakeTenantAuthorities::holding_everything());

        let page = block_on(use_case.execute(&test_ctx(), request(SortOrder::default()))).unwrap();

        assert_eq!(page.items.len(), 2);
    }

    /// Ann lists Acme's domains by name. They come back alphabetically.
    #[test]
    fn domains_are_ordered_by_name_on_request() {
        let use_case = use_case_with(FakeTenantAuthorities::holding_everything());
        let by_name = SortOrder::single(Sort::ascending(DomainSortField::Domain));

        let page = block_on(use_case.execute(&test_ctx(), request(by_name))).unwrap();

        let names: Vec<&str> = page.items.iter().map(|d| d.domain().as_str()).collect();
        assert_eq!(names, ["a.acme.test", "b.acme.test"]);
    }

    /// A caller without domain-viewing rights receives forbidden instead
    /// of Acme's domain list.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let use_case = use_case_with(FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list the tenant's registered domains.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(use_case.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
