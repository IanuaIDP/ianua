//! Delete schema: remove an event schema with every version it holds.
//!
//! A topic keeps its own copy of the definition its messages are checked
//! against, so no topic stops working when a registered schema goes. The
//! services that generate their types from it do, which is why deleting
//! takes the right to delete in messaging.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::control::MessagingControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::EventSchemaId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::SchemaStore;
use crate::use_case::Command;
use crate::use_cases::messaging::lookup::existing_schema;

/// Ports needed by the delete schema use case.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Port for schema persistence.
    pub schema_store: Arc<dyn SchemaStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a registered definition and all its versions from the tenant.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = EventSchemaId;
    type Output = Result<(), AppError>;

    /// Deletes the schema `schema_id` and every version it holds. Records
    /// `messaging.schema_deleted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the schema doesn't exist.
    /// - `AppError::Forbidden` when the caller may not delete in messaging.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        schema_id: EventSchemaId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = MessagingControl::new(&authority);
        control
            .ensure_may(MessagingAction::Delete)
            .map_err(AppError::from_domain)?;
        let store = self.ports.schema_store.as_ref();
        let mut schema = existing_schema(store, &tenant, &schema_id).await?;
        schema.delete(&control).map_err(AppError::from_domain)?;

        store.delete(&tenant, &schema_id).await.or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), schema.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{FakeSchemaStore, SchemaShape, schema_named};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Bench {
        use_case: DeleteUseCase,
        store: Arc<FakeSchemaStore>,
        id: EventSchemaId,
    }

    /// The tenant holds `order-created`, and the caller holds what
    /// `people` say.
    fn bench(people: FakeTenantAuthorities) -> Bench {
        let schema = schema_named(
            "order-created",
            SchemaShape::FREE_JSON,
            r#"{"type":"object"}"#,
        );
        let id = *schema.id();
        let store = FakeSchemaStore::of_test_tenant([schema]);
        let use_case = DeleteUseCase::new(DeletePorts {
            schema_store: store.clone(),
            tenant_authorities: Arc::new(people),
        });
        Bench {
            use_case,
            store,
            id,
        }
    }

    fn delete(
        bench: &Bench,
        id: EventSchemaId,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(bench.use_case.execute(
            &test_ctx(),
            &test_auditor(audit.clone()),
            id,
        ));
        (result, audit)
    }

    /// Ann deletes `order-created`. It is gone, and the record names it,
    /// scoped to her tenant.
    #[test]
    fn a_schema_is_deleted_and_recorded() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, audit) = delete(&bench, bench.id);

        result.unwrap();
        assert_eq!(bench.store.count(), 0);
        const DELETED: &str = "messaging.schema_deleted";
        assert_eq!(
            audit.label_of(DELETED, "schema").as_deref(),
            Some("order-created")
        );
        assert_eq!(audit.tenant_of(DELETED), Some(test_ctx().tenant_id()));
    }

    /// Publishing rights do not permit deleting a schema; the forbidden
    /// request keeps the schema and records no event.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let publisher = FakeTenantAuthorities::holding(&[SystemPermission::Messaging(
            MessagingAction::Publish,
        )]);
        let bench = bench(publisher);

        let (result, audit) = delete(&bench, bench.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.store.count(), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller receives an unauthenticated error when deleting
    /// a schema, which remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = bench(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = delete(&bench, bench.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(bench.store.count(), 1);
    }

    /// A schema the tenant does not have is not found, and nothing is
    /// deleted.
    #[test]
    fn an_unknown_schema_is_not_found() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, _) = delete(&bench, EventSchemaId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.store.count(), 1);
    }
}
