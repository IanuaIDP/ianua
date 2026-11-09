//! List consumers: retrieve all consumers for a tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ConsumersAction, SystemPermission};
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::consumers::{ConsumerSortField, ConsumerStore};
use crate::use_case::Query;

/// Which page of the tenant's consumers to list, and in what order.
pub struct ListRequest {
    /// The field and direction to order by.
    pub sort: SortOrder<ConsumerSortField>,
    /// Which page of the ordered consumers to return.
    pub page: PageRequest,
}

/// Ports needed by the list consumers use case.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Port for loading consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a sorted page of the caller's tenant's machine identities.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Page<Consumer<ResolvedTenant>>, AppError>;

    /// Lists consumers for the tenant with ordering and pagination.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view consumers.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<Consumer<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Consumers(ConsumersAction::View))
            .map_err(AppError::from_domain)?;
        let ListRequest { sort, page } = request;
        self.ports
            .consumer_store
            .list_all(&ctx.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{FakeConsumerStore, consumer_named};
    use crate::test_support::{block_on, test_ctx};

    fn request(sort: SortOrder<ConsumerSortField>) -> ListRequest {
        ListRequest {
            sort,
            page: PageRequest::default(),
        }
    }

    fn use_case_over(store: Arc<FakeConsumerStore>) -> ListUseCase {
        ListUseCase::new(ListPorts {
            consumer_store: store,
            ..ListPorts::fakes()
        })
    }

    fn three_in(tenant: TenantId) -> Arc<FakeConsumerStore> {
        let store = Arc::new(FakeConsumerStore::empty());
        for i in 0..3 {
            let consumer = consumer_named(&format!("consumer-{i}"), DataClassLevel::Internal);
            store.consumers.lock().unwrap().push((tenant, consumer));
        }
        store
    }

    /// Acme has three consumers. Ann lists them and sees all three.
    #[test]
    fn every_consumer_of_the_tenant_is_listed() {
        let use_case = use_case_over(three_in(test_ctx().tenant_id()));

        let page = block_on(use_case.execute(&test_ctx(), request(SortOrder::default()))).unwrap();

        assert_eq!(page.items.len(), 3);
    }

    /// Consumers stored in another tenant are absent from the caller's listing.
    #[test]
    fn another_tenants_consumers_are_not_listed() {
        let use_case = use_case_over(three_in(TenantId::new()));

        let page = block_on(use_case.execute(&test_ctx(), request(SortOrder::default()))).unwrap();

        assert!(page.is_empty());
    }

    /// Ann lists the consumers by name, last first.
    #[test]
    fn consumers_are_ordered_as_asked() {
        let use_case = use_case_over(three_in(test_ctx().tenant_id()));
        let sort = SortOrder::single(Sort::descending(ConsumerSortField::Name));

        let page = block_on(use_case.execute(&test_ctx(), request(sort))).unwrap();

        assert_eq!(page.items[0].name().as_str(), "consumer-2");
        assert_eq!(page.items[2].name().as_str(), "consumer-0");
    }

    /// A caller without consumer-view rights is refused a consumer listing.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            consumer_store: three_in(test_ctx().tenant_id()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ListPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives an authentication error instead of a consumer page.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            consumer_store: three_in(test_ctx().tenant_id()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ListPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
