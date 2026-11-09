//! List schemas: retrieve all event schemas for a tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::messaging::schema::EventSchema;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::messaging::{EventSchemaSortField, SchemaStore};
use crate::use_case::Query;

/// The order and page of schemas to list.
pub struct ListRequest {
    /// The field and direction to order by.
    pub sort: SortOrder<EventSchemaSortField>,
    /// Which page of the ordered schemas to return.
    pub page: PageRequest,
}

/// Ports needed by the list schemas use case.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Port for schema persistence.
    pub schema_store: Arc<dyn SchemaStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a sorted page of the tenant's registered message definitions.
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
    type Output = Result<Page<EventSchema<ResolvedTenant>>, AppError>;

    /// Lists schemas for the tenant with ordering and pagination.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view messaging.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<EventSchema<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Messaging(MessagingAction::View))
            .map_err(AppError::from_domain)?;
        let ListRequest { sort, page } = request;
        self.ports
            .schema_store
            .list_all(&ctx.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{FakeSchemaStore, SchemaShape, schema_named};
    use crate::test_support::{block_on, test_ctx};

    fn request(sort: SortOrder<EventSchemaSortField>) -> ListRequest {
        ListRequest {
            sort,
            page: PageRequest::default(),
        }
    }

    fn three_schemas() -> Arc<FakeSchemaStore> {
        FakeSchemaStore::of_test_tenant(
            ["schema-0", "schema-1", "schema-2"]
                .map(|name| schema_named(name, SchemaShape::FREE_JSON, r#"{"type":"object"}"#)),
        )
    }

    fn use_case_over(store: Arc<FakeSchemaStore>) -> ListUseCase {
        ListUseCase::new(ListPorts {
            schema_store: store,
            ..ListPorts::fakes()
        })
    }

    /// Acme has three schemas. Ann lists them and sees all three.
    #[test]
    fn every_schema_of_the_tenant_is_listed() {
        let use_case = use_case_over(three_schemas());

        let page = block_on(use_case.execute(&test_ctx(), request(SortOrder::default()))).unwrap();

        assert_eq!(page.items.len(), 3);
    }

    /// A tenant without schemas lists none.
    #[test]
    fn a_tenant_without_schemas_lists_none() {
        let use_case = use_case_over(Arc::new(FakeSchemaStore::empty()));

        let page = block_on(use_case.execute(&test_ctx(), request(SortOrder::default()))).unwrap();

        assert!(page.is_empty());
    }

    /// Ann lists the schemas by name, last first.
    #[test]
    fn schemas_are_ordered_as_asked() {
        let use_case = use_case_over(three_schemas());
        let sort = SortOrder::single(Sort::descending(EventSchemaSortField::SchemaName));

        let page = block_on(use_case.execute(&test_ctx(), request(sort))).unwrap();

        let names: Vec<&str> = page
            .items
            .iter()
            .map(|s| s.schema_name().as_str())
            .collect();
        assert_eq!(names, ["schema-2", "schema-1", "schema-0"]);
    }

    /// Listing registered schemas without messaging view rights returns a
    /// forbidden error.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            schema_store: three_schemas(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
        });

        let result = block_on(use_case.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives an unauthenticated error when listing schemas.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            schema_store: three_schemas(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        });

        let result = block_on(use_case.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
