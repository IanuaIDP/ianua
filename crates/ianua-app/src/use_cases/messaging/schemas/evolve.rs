//! Evolve schema: add a new version to an existing schema.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::control::MessagingControl;
use ianua_domain::domains::messaging::schema::{EventSchema, SchemaDefinition, VersionChange};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::EventSchemaId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::SchemaStore;
use crate::use_case::Command;
use crate::use_cases::messaging::lookup::existing_schema;
use crate::use_cases::messaging::schemas::definition::{
    ensure_well_formed, required_fields_change,
};

/// Which schema gains which new definition.
pub struct EvolveRequest {
    /// The schema to evolve.
    pub schema_id: EventSchemaId,
    /// The definition of the new version.
    pub definition: SchemaDefinition,
}

/// Ports needed by the evolve schema use case.
#[derive(ianua_macros::Fakes)]
pub struct EvolvePorts {
    /// Port for schema persistence.
    pub schema_store: Arc<dyn SchemaStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Adds a version to a tenant's registered message definition.
pub struct EvolveUseCase {
    ports: EvolvePorts,
}

impl EvolveUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: EvolvePorts) -> Self {
        Self { ports }
    }
}

impl Command for EvolveUseCase {
    type Caller = CallerContext;
    type Input = EvolveRequest;
    type Output = Result<u32, AppError>;

    /// Adds a new version to the schema and returns the new version number.
    /// Records `messaging.schema_evolved`, naming the version step.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the schema doesn't exist.
    /// - `AppError::Forbidden` when the caller does not manage messaging.
    /// - `AppError::Domain` if the definition is malformed, breaks the
    ///   schema's compatibility mode, or the schema holds all the versions
    ///   it may.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: EvolveRequest,
    ) -> Result<u32, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = MessagingControl::new(&authority);
        control
            .ensure_may(MessagingAction::Manage)
            .map_err(AppError::from_domain)?;
        let store = self.ports.schema_store.as_ref();
        let tenant = ctx.tenant();
        let mut schema = existing_schema(store, &tenant, &request.schema_id).await?;
        add_version(&mut schema, request.definition, &control)?;

        store.save(&tenant, &schema).await.or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), schema.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(schema.latest_version())
    }
}

/// Adds `definition` to `schema` as its next version, once it is well
/// formed and the domain holds it to the schema's compatibility mode.
fn add_version(
    schema: &mut EventSchema<ResolvedTenant>,
    definition: SchemaDefinition,
    control: &MessagingControl<'_>,
) -> Result<(), AppError> {
    ensure_well_formed(&definition, schema.format())?;
    let fields = required_fields_change(schema, &definition)?;
    let change = fields
        .as_ref()
        .map_or(VersionChange::NotComparable, VersionChange::Compared);
    schema
        .add_version(definition, change, control)
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::messaging::schema::{CompatibilityMode, SchemaFormat};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{FakeSchemaStore, SchemaShape, schema_named};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const BOTH: &str = r#"{"type":"object","required":["id","name"]}"#;

    const BACKWARD_JSON: SchemaShape = SchemaShape {
        format: SchemaFormat::JsonSchema,
        compatibility: CompatibilityMode::Backward,
    };

    struct Bench {
        use_case: EvolveUseCase,
        store: Arc<FakeSchemaStore>,
        id: EventSchemaId,
    }

    fn bench(shape: SchemaShape, people: FakeTenantAuthorities) -> Bench {
        let schema = schema_named("order-created", shape, BOTH);
        let id = *schema.id();
        let store = FakeSchemaStore::of_test_tenant([schema]);
        let use_case = EvolveUseCase::new(EvolvePorts {
            schema_store: store.clone(),
            tenant_authorities: Arc::new(people),
        });
        Bench {
            use_case,
            store,
            id,
        }
    }

    fn evolve(
        bench: &Bench,
        definition: &str,
    ) -> (Result<u32, AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = EvolveRequest {
            schema_id: bench.id,
            definition: SchemaDefinition::new(definition).unwrap(),
        };
        let result = block_on(bench.use_case.execute(
            &test_ctx(),
            &test_auditor(audit.clone()),
            request,
        ));
        (result, audit)
    }

    fn versions_of(bench: &Bench) -> usize {
        block_on(bench.store.find_by_id(&test_ctx().tenant(), &bench.id))
            .unwrap()
            .unwrap()
            .versions()
            .len()
    }

    /// Ann adds a field to `order-created` that no one must send. It becomes
    /// version 2.
    #[test]
    fn a_compatible_definition_becomes_the_next_version() {
        let bench = bench(BACKWARD_JSON, FakeTenantAuthorities::holding_everything());

        let (result, _) = evolve(
            &bench,
            r#"{"type":"object","required":["id","name"],"properties":{"note":{"type":"string"}}}"#,
        );

        assert_eq!(result.unwrap(), 2);
        assert_eq!(versions_of(&bench), 2);
    }

    /// Removing required `name` from a backward-compatible schema returns
    /// a validation error, keeps one version and records no event.
    #[test]
    fn a_backward_incompatible_definition_is_refused() {
        let bench = bench(BACKWARD_JSON, FakeTenantAuthorities::holding_everything());

        let (result, audit) = evolve(&bench, r#"{"type":"object","required":["id"]}"#);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(versions_of(&bench), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A JSON Schema version that is not JSON is refused.
    #[test]
    fn a_malformed_definition_is_refused() {
        let bench = bench(BACKWARD_JSON, FakeTenantAuthorities::holding_everything());

        let (result, _) = evolve(&bench, "{not json");

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    /// The audit record names the schema and the version step, and is
    /// scoped to the tenant whose schema moved, the subject it publishes on.
    #[test]
    fn the_audit_record_names_the_schema_the_version_step_and_the_tenant() {
        let bench = bench(
            SchemaShape::FREE_JSON,
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, audit) = evolve(&bench, r#"{"type":"object","title":"v2"}"#);

        result.unwrap();
        const EVOLVED: &str = "messaging.schema_evolved";
        assert_eq!(
            audit.label_of(EVOLVED, "schema").as_deref(),
            Some("order-created")
        );
        let version = audit.payload_of(EVOLVED).value("version").cloned();
        assert!(
            matches!(
                version,
                Some(FieldValue::Change(ref c)) if c.from() == Some("1") && c.to() == Some("2")
            ),
            "{version:?}"
        );
        assert_eq!(audit.tenant_of(EVOLVED), Some(test_ctx().tenant_id()));
    }

    /// Messaging creation rights do not permit adding a schema version;
    /// the forbidden request leaves the schema with one version.
    #[test]
    fn a_caller_who_does_not_manage_messaging_is_refused() {
        let creator =
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Create)]);
        let bench = bench(SchemaShape::FREE_JSON, creator);

        let (result, _) = evolve(&bench, r#"{"type":"object"}"#);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(versions_of(&bench), 1);
    }

    /// A signed-out caller receives an unauthenticated error when adding
    /// a schema version.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = bench(
            SchemaShape::FREE_JSON,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let (result, _) = evolve(&bench, r#"{"type":"object"}"#);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A schema the tenant does not have is not found.
    #[test]
    fn evolving_an_unknown_schema_is_not_found() {
        let use_case = EvolveUseCase::new(EvolvePorts::fakes());
        let request = EvolveRequest {
            schema_id: EventSchemaId::new(),
            definition: SchemaDefinition::new(r#"{"type":"object"}"#).unwrap(),
        };

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
