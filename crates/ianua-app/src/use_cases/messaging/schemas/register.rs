//! Register schema: create a new event schema with its initial version.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::messaging::schema::{
    CompatibilityMode, EventSchema, RegisterSchemaParams, SchemaDefinition, SchemaFormat,
};
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{EventSchemaId, Label};

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::SchemaStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};
use crate::use_cases::messaging::schemas::definition::ensure_well_formed;

/// Request to register a new schema.
pub struct RegisterRequest {
    /// Human-readable name (e.g. `"Order Created"`).
    pub name: Label,
    /// Machine-readable identifier (e.g. `"order-created"`).
    pub schema_name: Label,
    /// Optional description.
    pub description: Option<Label>,
    /// Schema format.
    pub format: SchemaFormat,
    /// Compatibility mode.
    pub compatibility: CompatibilityMode,
    /// Initial schema definition.
    pub definition: SchemaDefinition,
}

/// Ports needed by the register schema use case.
#[derive(ianua_macros::Fakes)]
pub struct RegisterPorts {
    /// Port for schema persistence.
    pub schema_store: Arc<dyn SchemaStore>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// What a consumer's roles give it, once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
}

/// Stores a named message definition with its initial version.
pub struct RegisterUseCase {
    ports: RegisterPorts,
}

impl RegisterUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: RegisterPorts) -> Self {
        Self { ports }
    }

    /// Refuses a schema name the tenant already uses.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` if the name is taken.
    /// - `AppError::Internal` on storage failure.
    async fn ensure_name_free(&self, tenant: &ScopedTenant, name: &Label) -> Result<(), AppError> {
        let existing = self
            .ports
            .schema_store
            .find_by_name(tenant, name)
            .await
            .or_internal()?;
        if existing.is_some() {
            return Err(AppError::Conflict(message!(
                "messaging-schema-already-exists",
                format!("schema '{}' already exists", name.as_str())
            )));
        }
        Ok(())
    }
}

impl Command for RegisterUseCase {
    type Caller = MessagingCaller;
    type Input = RegisterRequest;
    type Output = Result<EventSchemaId, AppError>;

    /// Registers a new schema, recording the person or consumer who made
    /// it. Records `messaging.schema_registered`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or consumer
    ///   credential no longer counts.
    /// - `AppError::Forbidden` when the person, or the consumer's roles, do
    ///   not give the right to create in messaging.
    /// - `AppError::Domain` if the definition is malformed for its format.
    /// - `AppError::Conflict` if a schema with the same name exists.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        auditor: &RequestAuditor,
        req: RegisterRequest,
    ) -> Result<EventSchemaId, AppError> {
        let tenant = caller.tenant();
        let actor = MessagingActor::of(
            caller,
            self.ports.tenant_authorities.as_ref(),
            self.ports.consumers.as_ref(),
        )
        .await?;
        actor.ensure_holds(SystemPermission::Messaging(MessagingAction::Create))?;
        ensure_well_formed(&req.definition, req.format)?;
        self.ensure_name_free(&tenant, &req.schema_name).await?;
        let mut schema =
            actor.creating(|creator| EventSchema::register(schema_params(req), creator))?;

        self.ports
            .schema_store
            .save(&tenant, &schema)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&actor.actor(), schema.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(*schema.id())
    }
}

fn schema_params(req: RegisterRequest) -> RegisterSchemaParams {
    RegisterSchemaParams {
        name: req.name,
        schema_name: req.schema_name,
        description: req.description,
        format: req.format,
        compatibility: req.compatibility,
        definition: req.definition,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::messaging::control::CreatedBy;
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{billing_sync, key_caller, sign_in_of, test_key_digest};
    use crate::test_support::messaging::{FakeSchemaStore, SchemaShape, schema_named};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const CREATE: SystemPermission = SystemPermission::Messaging(MessagingAction::Create);
    const PUBLISH: SystemPermission = SystemPermission::Messaging(MessagingAction::Publish);

    fn request() -> RegisterRequest {
        RegisterRequest {
            name: Label::new("name", "Order Created").unwrap(),
            schema_name: Label::new("name", "order-created").unwrap(),
            description: None,
            format: SchemaFormat::JsonSchema,
            compatibility: CompatibilityMode::Backward,
            definition: SchemaDefinition::new(r#"{"type":"object"}"#).unwrap(),
        }
    }

    fn person() -> MessagingCaller {
        MessagingCaller::Person(test_ctx())
    }

    fn use_case_over(store: Arc<FakeSchemaStore>) -> RegisterUseCase {
        RegisterUseCase::new(RegisterPorts {
            schema_store: store,
            ..RegisterPorts::fakes()
        })
    }

    fn consumer_holding(store: Arc<FakeSchemaStore>, held: &[SystemPermission]) -> RegisterUseCase {
        RegisterUseCase::new(RegisterPorts {
            schema_store: store,
            consumers: sign_in_of(billing_sync(), held),
            ..RegisterPorts::fakes()
        })
    }

    fn run(
        use_case: &RegisterUseCase,
        caller: &MessagingCaller,
        req: RegisterRequest,
    ) -> (Result<EventSchemaId, AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(caller, &test_auditor(audit.clone()), req));
        (result, audit)
    }

    /// Ann registers `order-created`. It is kept with its first version.
    #[test]
    fn a_person_registers_a_schema() {
        let store = Arc::new(FakeSchemaStore::empty());

        let (result, _) = run(&use_case_over(store.clone()), &person(), request());

        let schema = block_on(store.find_by_id(&test_ctx().tenant(), &result.unwrap()))
            .unwrap()
            .unwrap();
        assert_eq!(schema.latest_version(), 1);
        assert!(matches!(schema.created_by(), CreatedBy::Person(_)));
    }

    /// The record names the schema and is scoped to the tenant it belongs
    /// to, which is the subject other processes receive it on.
    #[test]
    fn the_audit_record_names_the_schema_and_its_tenant() {
        let (result, audit) = run(
            &use_case_over(Arc::new(FakeSchemaStore::empty())),
            &person(),
            request(),
        );

        result.unwrap();
        const REGISTERED: &str = "messaging.schema_registered";
        assert_eq!(
            audit.label_of(REGISTERED, "schema").as_deref(),
            Some("order-created")
        );
        assert_eq!(audit.tenant_of(REGISTERED), Some(test_ctx().tenant_id()));
    }

    /// "billing-sync" holds a role that may create in messaging. It
    /// registers a schema with its own key, and the schema names it.
    #[test]
    fn a_consumer_registers_a_schema_of_its_own() {
        let store = Arc::new(FakeSchemaStore::empty());
        let caller = MessagingCaller::Consumer(key_caller(test_key_digest()));

        let (result, _) = run(
            &consumer_holding(store.clone(), &[CREATE]),
            &caller,
            request(),
        );

        let schema = block_on(store.find_by_id(&test_ctx().tenant(), &result.unwrap()))
            .unwrap()
            .unwrap();
        assert!(matches!(schema.created_by(), CreatedBy::Consumer(_)));
    }

    /// A consumer with publishing rights cannot register a schema; the
    /// forbidden request saves no schema.
    #[test]
    fn a_consumer_whose_roles_only_publish_is_refused() {
        let store = Arc::new(FakeSchemaStore::empty());
        let caller = MessagingCaller::Consumer(key_caller(test_key_digest()));

        let (result, _) = run(
            &consumer_holding(store.clone(), &[PUBLISH]),
            &caller,
            request(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// A person with messaging view rights cannot register a schema; the
    /// forbidden request saves no schema.
    #[test]
    fn a_person_without_the_create_right_is_refused() {
        let store = Arc::new(FakeSchemaStore::empty());
        let use_case = RegisterUseCase::new(RegisterPorts {
            schema_store: store.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Messaging(MessagingAction::View),
            ])),
            ..RegisterPorts::fakes()
        });

        let (result, _) = run(&use_case, &person(), request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// A signed-out person receives an unauthenticated error when registering
    /// a schema.
    #[test]
    fn a_signed_out_person_is_refused() {
        let use_case = RegisterUseCase::new(RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..RegisterPorts::fakes()
        });

        let (result, _) = run(&use_case, &person(), request());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// The tenant already has `order-created`. A person who may only view
    /// messaging, naming it too, is refused for lacking the right and is
    /// not told the name is taken.
    #[test]
    fn a_taken_name_is_not_told_to_someone_without_the_create_right() {
        let store = FakeSchemaStore::of_test_tenant([schema_named(
            "order-created",
            SchemaShape::FREE_JSON,
            r#"{"type":"object"}"#,
        )]);
        let use_case = RegisterUseCase::new(RegisterPorts {
            schema_store: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Messaging(MessagingAction::View),
            ])),
            ..RegisterPorts::fakes()
        });

        let (result, _) = run(&use_case, &person(), request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// The tenant already has `order-created`. A second schema by that name
    /// is refused as a conflict.
    #[test]
    fn a_taken_schema_name_is_a_conflict() {
        let store = FakeSchemaStore::of_test_tenant([schema_named(
            "order-created",
            SchemaShape::FREE_JSON,
            r#"{"type":"object"}"#,
        )]);

        let (result, _) = run(&use_case_over(store.clone()), &person(), request());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(store.count(), 1);
    }

    /// A JSON Schema that is not JSON is refused before anything is kept.
    #[test]
    fn a_malformed_definition_is_refused() {
        let store = Arc::new(FakeSchemaStore::empty());
        let malformed = RegisterRequest {
            definition: SchemaDefinition::new("{not json").unwrap(),
            ..request()
        };

        let (result, _) = run(&use_case_over(store.clone()), &person(), malformed);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(store.count(), 0);
    }
}
