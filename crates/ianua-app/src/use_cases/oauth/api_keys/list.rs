//! Listing the tenant's API keys, ordered and paged.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ApiKeyAction, SystemPermission};
use ianua_domain::domains::oauth::clients::api_key::ApiKey;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::oauth::{ApiKeySortField, ApiKeyStore};
use crate::use_case::Query;

/// Which page of the tenant's API keys to return, in what order.
pub struct ListRequest {
    /// The fields and directions to order by.
    pub sort: SortOrder<ApiKeySortField>,
    /// Which page of the ordered keys to return.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Where keys are kept.
    pub key_store: Arc<dyn ApiKeyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's API keys.
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
    type Output = Result<Page<ApiKey<ResolvedTenant>>, AppError>;

    /// The page of `caller`'s tenant's keys that `request` asks for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view API keys.
    /// - `AppError::Internal` when the keys cannot be read.
    async fn execute(
        &self,
        caller: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<ApiKey<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::ApiKeys(ApiKeyAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .key_store
            .list_all(&caller.tenant(), &request.sort, &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::{Limit, Sort};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeApiKeyStore, stored_api_key};
    use crate::test_support::{block_on, test_ctx};

    fn store_of(names: &[&str]) -> Arc<FakeApiKeyStore> {
        let store = Arc::new(FakeApiKeyStore::empty());
        for name in names {
            let key = stored_api_key(name, test_ctx().actor());
            block_on(store.insert(&test_ctx().tenant(), &key)).unwrap();
        }
        store
    }

    fn list_as(
        authorities: FakeTenantAuthorities,
        store: Arc<FakeApiKeyStore>,
        request: ListRequest,
    ) -> Result<Page<ApiKey<ResolvedTenant>>, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            key_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), request))
    }

    fn first_page() -> ListRequest {
        ListRequest {
            sort: SortOrder::default(),
            page: PageRequest::default(),
        }
    }

    /// Acme has five keys. Ann asks for three and gets the first three, told
    /// there are five and more to come.
    #[test]
    fn keys_are_paged() {
        let page = list_as(
            FakeTenantAuthorities::holding_everything(),
            store_of(&["A", "B", "C", "D", "E"]),
            ListRequest {
                page: PageRequest::first(Limit::new(3).unwrap()),
                ..first_page()
            },
        )
        .unwrap();

        assert_eq!(page.items.len(), 3);
        assert!(page.has_next());
    }

    /// Ann orders the keys by name and gets them alphabetically.
    #[test]
    fn keys_are_ordered_by_name() {
        let page = list_as(
            FakeTenantAuthorities::holding_everything(),
            store_of(&["Charlie", "Alice", "Bob"]),
            ListRequest {
                sort: SortOrder::single(Sort::ascending(ApiKeySortField::Name)),
                ..first_page()
            },
        )
        .unwrap();

        let names: Vec<_> = page.items.iter().map(|k| k.name().as_str()).collect();
        assert_eq!(names, ["Alice", "Bob", "Charlie"]);
    }

    /// A caller without API-key view permission is forbidden from listing
    /// the tenant's keys.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = list_as(
            FakeTenantAuthorities::holding(&[]),
            store_of(&["CI"]),
            first_page(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives unauthenticated when listing API keys.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            store_of(&["CI"]),
            first_page(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
