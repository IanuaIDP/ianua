//! Fake for the event schemas topics are held to, and the schemas their
//! tests share.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::messaging::control::MessagingCreator;
use ianua_domain::domains::messaging::schema::{
    CompatibilityMode, EventSchema, EventSchemaRow, RegisterSchemaParams, SchemaDefinition,
    SchemaFormat,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{EventSchemaId, Label, TenantId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::messaging::{EventSchemaSortField, SchemaStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::messaging::messaging_admin;
use crate::test_support::{Fake, test_ctx};

/// How a test schema is written and held to its versions.
#[derive(Debug, Clone, Copy)]
pub struct SchemaShape {
    /// The schema language.
    pub format: SchemaFormat,
    /// How a new version must relate to the one before it.
    pub compatibility: CompatibilityMode,
}

impl SchemaShape {
    /// A JSON Schema held to no compatibility mode.
    pub const FREE_JSON: Self = Self {
        format: SchemaFormat::JsonSchema,
        compatibility: CompatibilityMode::None,
    };
}

/// A schema named `schema_name`, of `shape`, whose first version is
/// `definition`, registered by someone who manages messaging.
#[must_use]
pub fn schema_named(
    schema_name: &str,
    shape: SchemaShape,
    definition: &str,
) -> EventSchema<ResolvedTenant> {
    let admin = messaging_admin();
    EventSchema::register(
        RegisterSchemaParams {
            name: Label::new("name", schema_name).unwrap(),
            schema_name: Label::new("name", schema_name).unwrap(),
            description: None,
            format: shape.format,
            compatibility: shape.compatibility,
            definition: SchemaDefinition::new(definition).unwrap(),
        },
        MessagingCreator::Person(&admin),
    )
    .unwrap()
}

/// In-memory schema store, each schema kept under its tenant.
#[derive(Default)]
pub struct FakeSchemaStore {
    schemas: Mutex<Vec<(TenantId, EventSchema<ResolvedTenant>)>>,
}

impl TenantScoped for FakeSchemaStore {}

impl FakeSchemaStore {
    /// A store holding no schema.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `schemas` in the tenant every test caller acts in.
    #[must_use]
    pub fn of_test_tenant(
        schemas: impl IntoIterator<Item = EventSchema<ResolvedTenant>>,
    ) -> Arc<Self> {
        let tenant = test_ctx().tenant_id();
        let store = Self::default();
        store
            .schemas
            .lock()
            .unwrap()
            .extend(schemas.into_iter().map(|held| (tenant, held)));
        Arc::new(store)
    }

    /// How many schemas are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.schemas.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: &ScopedTenant,
        keeps: impl Fn(&EventSchema<ResolvedTenant>) -> bool,
    ) -> Result<Vec<EventSchema<ResolvedTenant>>, DomainError> {
        self.schemas
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, schema)| tenant == &**tenant_id && keeps(schema))
            .map(|(_, schema)| copy_schema(schema))
            .collect()
    }
}

#[async_trait]
impl SchemaStore for FakeSchemaStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &EventSchemaId,
    ) -> Result<Option<EventSchema<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |schema| schema.id() == id)?;
        Ok(found.into_iter().next())
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &Label,
    ) -> Result<Option<EventSchema<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |schema| schema.schema_name() == name)?;
        Ok(found.into_iter().next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<EventSchemaSortField>,
        request: &PageRequest,
    ) -> Result<Page<EventSchema<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |_| true)?;
        page(found, sort, request)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        schema: &EventSchema<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_schema(schema)?;
        let mut schemas = self.schemas.lock().unwrap();
        let taken = schemas.iter().any(|(tenant, kept)| {
            tenant == &**tenant_id
                && kept.id() != schema.id()
                && kept.schema_name() == schema.schema_name()
        });
        if taken {
            return Err(DomainError::conflict(
                "another schema of the tenant has this machine name",
            ));
        }
        schemas.retain(|(tenant, kept)| !(tenant == &**tenant_id && kept.id() == schema.id()));
        schemas.push((**tenant_id, copy));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &EventSchemaId,
    ) -> Result<(), DomainError> {
        self.schemas
            .lock()
            .unwrap()
            .retain(|(tenant, schema)| !(tenant == &**tenant_id && schema.id() == id));
        Ok(())
    }
}

impl Fake for Arc<dyn SchemaStore> {
    fn fake() -> Self {
        Arc::new(FakeSchemaStore::empty())
    }
}

/// `schema` written out and read back, as storage would return it.
fn copy_schema(
    schema: &EventSchema<ResolvedTenant>,
) -> Result<EventSchema<ResolvedTenant>, DomainError> {
    EventSchema::reconstitute(EventSchemaRow {
        id: *schema.id(),
        name: schema.name().clone(),
        schema_name: schema.schema_name().clone(),
        description: schema.description().cloned(),
        format: schema.format(),
        compatibility: schema.compatibility(),
        versions: schema.versions().to_vec(),
        created_by: schema.created_by().clone(),
        created_at: Aggregate::created_at(schema),
        updated_at: Aggregate::updated_at(schema),
    })
}
