//! A tenant's event schemas, each row under row-level security, with every
//! version in a row of its own.
//!
//! A version is only ever added, so a save sends only the versions past
//! the latest one kept. One machine name is one schema of the tenant. A
//! read of schemas reads their versions in one more query, and a list
//! first reads the ids of its page, then reads those rows by id.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::messaging::{EventSchemaSortField, SchemaStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::messaging::schema::EventSchema;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EventSchemaId, Label, TenantId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{SchemaColumns, SchemaRecord, VersionColumns, VersionRecord, Versions};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a machine name to one schema of a tenant.
const NAME_KEY: &str = "event_schemas_name_key";

/// The Postgres event schema store.
pub struct PgSchemaStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSchemaStore {}

impl PgSchemaStore {
    /// A store keeping event schemas in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Writes `schema` for `tenant` with the versions it adds, or finds its
    /// machine name taken by another schema of the tenant.
    async fn write(
        &self,
        tenant: &ScopedTenant,
        schema: &EventSchema<ResolvedTenant>,
    ) -> Result<Uniqueness, DomainError> {
        let columns = SchemaColumns::of(schema);
        scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                if write_schema(&mut *connection, tenant, &columns).await? == Uniqueness::Taken {
                    return Ok(Uniqueness::Taken);
                }
                let stored = sqlx::query_file_scalar!(
                    "queries/event_schema_versions/latest.sql",
                    tenant.as_uuid(),
                    columns.id
                )
                .fetch_one(&mut *connection)
                .await?;
                add_versions(
                    connection,
                    tenant,
                    columns.id,
                    &VersionColumns::after(schema, stored),
                )
                .await?;
                Ok(Uniqueness::Kept)
            },
        )
        .await
    }
}

/// The schemas `records` hold, each with its own of `versions`, in the
/// order of `records`.
fn assembled(
    records: Vec<SchemaRecord>,
    versions: Vec<VersionRecord>,
) -> Result<Vec<EventSchema<ResolvedTenant>>, DomainError> {
    let mut versions = Versions::of(versions);
    records
        .into_iter()
        .map(|record| {
            let own = versions.take(&record.id);
            record.into_schema(own)
        })
        .collect()
}

/// Writes the schema `columns` describe, without its versions.
async fn write_schema(
    connection: &mut PgConnection,
    tenant: &TenantId,
    columns: &SchemaColumns<'_>,
) -> Result<Uniqueness, sqlx::Error> {
    let maker = &columns.created_by;
    let attempt = sqlx::query_file!(
        "queries/event_schemas/save.sql",
        columns.id,
        tenant.as_uuid(),
        columns.name,
        columns.schema_name,
        columns.description,
        columns.format,
        columns.compatibility,
        maker.kind,
        maker.id,
        maker.person,
        columns.created_at,
        columns.updated_at,
    )
    .execute(connection)
    .await;
    unique_on(attempt, NAME_KEY)
}

/// Adds the versions `added` describes to the schema `schema_id`.
async fn add_versions(
    connection: &mut PgConnection,
    tenant: &TenantId,
    schema_id: &Uuid,
    added: &VersionColumns,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/event_schema_versions/add.sql",
        tenant.as_uuid(),
        schema_id,
        &added.numbers,
        &added.definitions,
        &added.created_at,
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// The records of the schemas of `tenant` that `ids` names, in no order,
/// and every version of them.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<(Vec<SchemaRecord>, Vec<VersionRecord>), sqlx::Error> {
    let records = sqlx::query_file_as!(
        SchemaRecord,
        "queries/event_schemas/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(&mut *connection)
    .await?;
    let versions = versions_of(connection, tenant, ids).await?;
    Ok((records, versions))
}

/// Every version of the schemas of `tenant` that `ids` names.
async fn versions_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<VersionRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        VersionRecord,
        "queries/event_schema_versions/of_schemas.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

impl SortColumns for EventSchemaSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
            Self::SchemaName => "schema_name",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl SchemaStore for PgSchemaStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &EventSchemaId,
    ) -> Result<Option<EventSchema<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let (records, versions) = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        Ok(assembled(records, versions)?.into_iter().next())
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &Label,
    ) -> Result<Option<EventSchema<ResolvedTenant>>, DomainError> {
        let (records, versions) = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let records = sqlx::query_file_as!(
                    SchemaRecord,
                    "queries/event_schemas/by_name.sql",
                    tenant_id.as_uuid(),
                    name.as_str()
                )
                .fetch_all(&mut *connection)
                .await?;
                let ids: Vec<Uuid> = records.iter().map(|record| record.id).collect();
                let versions = versions_of(connection, tenant_id, &ids).await?;
                Ok((records, versions))
            },
        )
        .await?;
        Ok(assembled(records, versions)?.into_iter().next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<EventSchemaSortField>,
        page: &PageRequest,
    ) -> Result<Page<EventSchema<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed =
            PageQuery::ids("id", "event_schemas").filter("tenant_id = ?", *tenant_id.as_uuid());
        let (records, versions) = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let (records, versions) = records_of(connection, tenant_id, &ids).await?;
                Ok((in_page_order(&ids, records, |record| record.id), versions))
            },
        )
        .await?;
        Ok(keyset.seal(assembled(records, versions)?))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        schema: &EventSchema<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        match self.write(tenant_id, schema).await? {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-schema-of-the-tenant-has",
                "another schema of the tenant has this machine name"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &EventSchemaId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/event_schemas/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_domain::domains::messaging::control::CreatedBy;
    use ianua_domain::domains::messaging::schema::{
        CompatibilityMode, EventSchemaRow, SchemaFormat,
    };
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::ConsumerId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::messaging::{ORDER_SCHEMA, schema_row, version};

    struct Fixture {
        db: TestDb,
        store: PgSchemaStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep schemas
    /// for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgSchemaStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn schema(row: EventSchemaRow) -> EventSchema<ResolvedTenant> {
        EventSchema::reconstitute(row).unwrap()
    }

    fn named(schema_name: &str) -> EventSchema<ResolvedTenant> {
        schema(schema_row(schema_name))
    }

    fn label(text: &str) -> Label {
        Label::new("schema_name", text).unwrap()
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn names(page: &Page<EventSchema<ResolvedTenant>>) -> Vec<&str> {
        page.items
            .iter()
            .map(|schema| schema.schema_name().as_str())
            .collect()
    }

    impl Fixture {
        async fn save_all(&self, schemas: &[&EventSchema<ResolvedTenant>]) {
            for schema in schemas {
                self.store.save(&self.tenant, schema).await.unwrap();
            }
        }

        async fn found(&self, id: &EventSchemaId) -> Option<EventSchema<ResolvedTenant>> {
            self.store.find_by_id(&self.tenant, id).await.unwrap()
        }
    }

    /// An Avro schema held to full compatibility, registered by a consumer
    /// with three versions, is found by its id as it was saved, every
    /// version in order.
    #[tokio::test]
    async fn a_saved_schema_is_found_with_every_version() {
        let fx = fixture().await;
        let orders = schema(EventSchemaRow {
            format: SchemaFormat::Avro,
            compatibility: CompatibilityMode::Full,
            versions: vec![
                version(1, ORDER_SCHEMA, 0),
                version(2, r#"{"type":"record"}"#, 5),
                version(3, r#"{"type":"record","name":"Order"}"#, 9),
            ],
            created_by: CreatedBy::Consumer(ConsumerId::new()),
            updated_at: at(9),
            ..schema_row("order-created")
        });
        fx.save_all(&[&orders]).await;

        let found = fx.found(orders.id()).await.unwrap();

        assert_eq!(found.name(), orders.name());
        assert_eq!(found.schema_name(), orders.schema_name());
        assert_eq!(found.format(), SchemaFormat::Avro);
        assert_eq!(found.compatibility(), CompatibilityMode::Full);
        assert_eq!(found.versions(), orders.versions());
        assert_eq!(found.created_by(), orders.created_by());
        assert_eq!(found.created_at(), orders.created_at());
        assert_eq!(found.updated_at(), at(9));
    }

    /// A version added since the last save is kept beside the first, and a
    /// published version stays as it was published, whatever a later save
    /// carries for it.
    #[tokio::test]
    async fn a_save_adds_new_versions_and_never_changes_a_published_one() {
        let fx = fixture().await;
        let orders = named("order-created");
        fx.save_all(&[&orders]).await;
        let evolved = schema(EventSchemaRow {
            id: *orders.id(),
            versions: vec![
                version(1, r#"{"rewritten":true}"#, 0),
                version(2, r#"{"type":"object"}"#, 5),
            ],
            updated_at: at(5),
            ..schema_row("order-created")
        });

        fx.save_all(&[&evolved]).await;

        let found = fx.found(orders.id()).await.unwrap();
        assert_eq!(found.latest_version(), 2);
        assert_eq!(found.versions().first(), orders.versions().first());
        assert_eq!(found.versions().get(1), evolved.versions().get(1));
    }

    /// A schema is found by its machine name; a name nobody uses, and
    /// another tenant asking, find nothing.
    #[tokio::test]
    async fn a_schema_is_found_by_its_name_in_its_tenant() {
        let fx = fixture().await;
        let orders = named("order-created");
        fx.save_all(&[&orders]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let by_name = fx
            .store
            .find_by_name(&fx.tenant, &label("order-created"))
            .await
            .unwrap()
            .unwrap();
        let unknown = fx
            .store
            .find_by_name(&fx.tenant, &label("order-lost"))
            .await
            .unwrap();
        let elsewhere = fx
            .store
            .find_by_name(&other, &label("order-created"))
            .await
            .unwrap();

        assert_eq!(by_name.id(), orders.id());
        assert_eq!(by_name.versions(), orders.versions());
        assert!(unknown.is_none());
        assert!(elsewhere.is_none());
    }

    /// An id nobody has finds nothing, and another tenant does not find
    /// this tenant's schema by its id.
    #[tokio::test]
    async fn a_schema_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let orders = named("order-created");
        fx.save_all(&[&orders]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(fx.found(&EventSchemaId::new()).await.is_none());
        assert!(
            fx.store
                .find_by_id(&other, orders.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Saving a second schema with the tenant's existing machine name
    /// returns a conflict.
    #[tokio::test]
    async fn a_name_another_schema_has_is_refused() {
        let fx = fixture().await;
        fx.save_all(&[&named("order-created")]).await;

        let second = fx.store.save(&fx.tenant, &named("order-created")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// The tenant's schemas list by machine name page by page, each page
    /// after the last, each with its versions.
    #[tokio::test]
    async fn schemas_are_listed_page_by_page() {
        let fx = fixture().await;
        fx.save_all(&[&named("c-schema"), &named("a-schema"), &named("b-schema")])
            .await;
        let order = SortOrder::single(Sort::ascending(EventSchemaSortField::SchemaName));

        let page_one = fx
            .store
            .list_all(&fx.tenant, &order, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.store.list_all(&fx.tenant, &order, &after).await.unwrap();

        assert_eq!(names(&page_one), ["a-schema", "b-schema"]);
        assert_eq!(names(&page_two), ["c-schema"]);
        assert!(!page_two.has_next());
        assert_eq!(
            page_two.items.first().map(EventSchema::latest_version),
            Some(1)
        );
    }

    /// A deleted schema is gone with its versions, and its name is free for
    /// a new one starting again at version 1.
    #[tokio::test]
    async fn a_deleted_schema_is_gone_with_its_versions() {
        let fx = fixture().await;
        let orders = named("order-created");
        fx.save_all(&[&orders]).await;

        fx.store.delete(&fx.tenant, orders.id()).await.unwrap();
        let again = named("order-created");
        fx.save_all(&[&again]).await;

        assert!(fx.found(orders.id()).await.is_none());
        assert_eq!(fx.found(again.id()).await.unwrap().latest_version(), 1);
    }

    /// A tenant with a database of its own keeps its schemas there.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_schemas_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let orders = named("order-created");

        fx.store.save(&apart, &orders).await.unwrap();

        let there = PgSchemaStore::new(Arc::clone(&own.databases));
        assert!(
            there
                .find_by_id(&apart, orders.id())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A stored schema missing version one while retaining version two
    /// fails to load as corrupt storage.
    #[tokio::test]
    async fn a_schema_with_a_version_missing_is_refused() {
        let fx = fixture().await;
        let orders = schema(EventSchemaRow {
            versions: vec![version(1, ORDER_SCHEMA, 0), version(2, ORDER_SCHEMA, 1)],
            updated_at: at(1),
            ..schema_row("order-created")
        });
        fx.save_all(&[&orders]).await;
        fx.db
            .tamper("DELETE FROM event_schema_versions WHERE version = 1")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, orders.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
