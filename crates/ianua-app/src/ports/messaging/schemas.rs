//! Event schemas messages are checked against.

use async_trait::async_trait;
use ianua_domain::domains::messaging::schema::EventSchema;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{EventSchemaId, Label};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field an event schema listing can be ordered by.
    pub enum EventSchemaSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by display name.
        Name => "name",
        /// Order by machine-readable schema name.
        SchemaName => "schema_name",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<EventSchemaSortField> for EventSchema<ResolvedTenant> {
    fn sort_key(&self, field: EventSchemaSortField) -> SortKey {
        match field {
            EventSchemaSortField::CreatedAt => Aggregate::created_at(self).into(),
            EventSchemaSortField::UpdatedAt => Aggregate::updated_at(self).into(),
            EventSchemaSortField::Name => self.name().as_str().into(),
            EventSchemaSortField::SchemaName => self.schema_name().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving event schemas.
#[async_trait]
pub trait SchemaStore: Send + Sync + TenantScoped {
    /// Finds a schema by its unique ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &EventSchemaId,
    ) -> Result<Option<EventSchema<ResolvedTenant>>, DomainError>;

    /// Finds a schema by its machine name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &Label,
    ) -> Result<Option<EventSchema<ResolvedTenant>>, DomainError>;

    /// Lists a page of schemas for a tenant in the requested order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<EventSchemaSortField>,
        page: &PageRequest,
    ) -> Result<Page<EventSchema<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated schema (including new versions).
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when another schema of the tenant has its
    ///   machine name.
    /// - `DomainError` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        schema: &EventSchema<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a schema by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &EventSchemaId)
    -> Result<(), DomainError>;
}
