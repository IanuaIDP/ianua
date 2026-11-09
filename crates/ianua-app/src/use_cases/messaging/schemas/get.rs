//! Get schema: retrieve a single event schema by ID.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::messaging::schema::EventSchema;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::EventSchemaId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::messaging::SchemaStore;
use crate::use_case::Query;
use crate::use_cases::messaging::lookup::existing_schema;

/// Ports needed by the get schema use case.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Port for schema persistence.
    pub schema_store: Arc<dyn SchemaStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a registered message definition within the caller's tenant.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = EventSchemaId;
    type Output = Result<EventSchema<ResolvedTenant>, AppError>;

    /// Retrieves a schema by ID.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view messaging.
    /// - `AppError::NotFound` if the schema doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: EventSchemaId,
    ) -> Result<EventSchema<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Messaging(MessagingAction::View))
            .map_err(AppError::from_domain)?;
        existing_schema(self.ports.schema_store.as_ref(), &ctx.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{FakeSchemaStore, SchemaShape, schema_named};
    use crate::test_support::{block_on, test_ctx};

    fn bench(people: FakeTenantAuthorities) -> (GetUseCase, EventSchemaId) {
        let schema = schema_named(
            "order-created",
            SchemaShape::FREE_JSON,
            r#"{"type":"object"}"#,
        );
        let id = *schema.id();
        let use_case = GetUseCase::new(GetPorts {
            schema_store: FakeSchemaStore::of_test_tenant([schema]),
            tenant_authorities: Arc::new(people),
        });
        (use_case, id)
    }

    /// Ann may view messaging. She opens `order-created` and sees it.
    #[test]
    fn a_viewer_gets_the_schema() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::View)]);
        let (use_case, id) = bench(viewer);

        let found = block_on(use_case.execute(&test_ctx(), id)).unwrap();

        assert_eq!(found.schema_name().as_str(), "order-created");
    }

    /// A schema the tenant does not have is not found.
    #[test]
    fn an_unknown_schema_is_not_found() {
        let (use_case, _) = bench(FakeTenantAuthorities::holding_everything());

        let result = block_on(use_case.execute(&test_ctx(), EventSchemaId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading an existing schema without messaging view rights returns a
    /// forbidden error.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let (use_case, id) = bench(FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives an unauthenticated error when reading a schema.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (use_case, id) = bench(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
