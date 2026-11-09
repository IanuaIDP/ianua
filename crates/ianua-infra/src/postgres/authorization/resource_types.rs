//! The resource types a tenant declares: the catalogue its roles' own
//! permissions are checked against.

pub(crate) mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{ResourceTypeSortField, ResourceTypeStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::authorization::resource_type::ResourceType;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ResourceTypeId;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{ResourceTypeColumns, ResourceTypeRecord, resource_types_from};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a key to one resource type of a tenant.
const KEY_KEY: &str = "resource_types_key_key";

/// The Postgres store of a tenant's resource types.
pub struct PgResourceTypeStore {
    databases: Arc<Databases>,
}

impl PgResourceTypeStore {
    /// A store keeping resource types in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgResourceTypeStore {}

/// The records of the resource types of `tenant_id` that `ids` names, in
/// no order.
async fn resource_types_of(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<ResourceTypeRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        ResourceTypeRecord,
        "queries/resource_types/by_ids.sql",
        tenant_id,
        ids
    )
    .fetch_all(connection)
    .await
}

/// Every resource type `tenant_id` declares, by key.
pub(crate) async fn catalogue_of(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
) -> Result<Vec<ResourceTypeRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        ResourceTypeRecord,
        "queries/resource_types/of_tenant.sql",
        tenant_id
    )
    .fetch_all(connection)
    .await
}

impl SortColumns for ResourceTypeSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Key => "key",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl ResourceTypeStore for PgResourceTypeStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ResourceTypeId,
    ) -> Result<Option<ResourceType<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| resource_types_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(resource_types_from(records)?.pop())
    }

    async fn find_by_key(
        &self,
        tenant_id: &ScopedTenant,
        key: &PermissionSegment,
    ) -> Result<Option<ResourceType<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ResourceTypeRecord,
                    "queries/resource_types/by_key.sql",
                    tenant_id.as_uuid(),
                    key.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record
            .map(ResourceTypeRecord::into_resource_type)
            .transpose()
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ResourceTypeSortField>,
        page: &PageRequest,
    ) -> Result<Page<ResourceType<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed =
            PageQuery::ids("id", "resource_types").filter("tenant_id = ?", *tenant_id.as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = resource_types_of(connection, tenant_id.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(resource_types_from(records)?))
    }

    async fn list_every(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ResourceType<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| catalogue_of(connection, tenant_id.as_uuid()).await,
        )
        .await?;
        resource_types_from(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        resource_type: &ResourceType<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ResourceTypeColumns::of(resource_type)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/resource_types/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.key,
                    columns.display_name,
                    columns.description,
                    columns.actions,
                    columns.data_class,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, KEY_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-tenant-already-declares-a-resource",
                "the tenant already declares a resource type with this key"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &ResourceTypeId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/resource_types/delete.sql",
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

    async fn count_roles_using(
        &self,
        tenant_id: &ScopedTenant,
        key: &PermissionSegment,
    ) -> Result<u64, DomainError> {
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/roles/using_resource.sql",
                    tenant_id.as_uuid(),
                    key.as_str()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::authorization::RoleStore;
    use ianua_domain::domains::authorization::permission::CustomPermission;
    use ianua_domain::domains::authorization::resource_type::ResourceTypeRow;
    use ianua_domain::domains::authorization::role::{Role, RoleRow};

    use super::*;
    use crate::postgres::authorization::PgRoleStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{
        resource_type, resource_type_row, role_row, segment, tenant,
    };

    /// A fresh database, the store on it, and a tenant to declare in.
    async fn fixture() -> (TestDb, PgResourceTypeStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgResourceTypeStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    fn keys(types: &[ResourceType<ResolvedTenant>]) -> Vec<&str> {
        types
            .iter()
            .map(|declared| declared.key().as_str())
            .collect()
    }

    /// A declared type is found by its id and its key, with its actions,
    /// its description and the data it holds.
    #[tokio::test]
    async fn a_declared_type_is_found_by_its_id_and_its_key() {
        let (_db, store, acme) = fixture().await;
        let project = resource_type("project");

        store.save(&acme, &project).await.unwrap();

        let by_id = store
            .find_by_id(&acme, project.id())
            .await
            .unwrap()
            .unwrap();
        let by_key = store
            .find_by_key(&acme, project.key())
            .await
            .unwrap()
            .unwrap();
        for found in [&by_id, &by_key] {
            assert_eq!(found.actions(), project.actions());
            assert_eq!(found.description(), project.description());
            assert_eq!(found.data_class(), project.data_class());
        }
    }

    /// An id or key the tenant declares nothing under finds nothing, and
    /// another tenant sees none of this one's types.
    #[tokio::test]
    async fn an_unknown_or_foreign_type_is_not_found() {
        let (_db, store, acme) = fixture().await;
        let project = resource_type("project");
        store.save(&acme, &project).await.unwrap();
        let globex = tenant();

        let unknown = store
            .find_by_id(&acme, &ResourceTypeId::new())
            .await
            .unwrap();
        let foreign = store.find_by_key(&globex, project.key()).await.unwrap();
        let every = store.list_every(&globex).await.unwrap();

        assert!(unknown.is_none());
        assert!(foreign.is_none());
        assert!(every.is_empty());
    }

    /// Saving a second resource type with Acme's existing key conflicts.
    #[tokio::test]
    async fn a_key_another_type_has_is_refused() {
        let (_db, store, acme) = fixture().await;
        store.save(&acme, &resource_type("project")).await.unwrap();

        let second = store.save(&acme, &resource_type("project")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// The catalogue is paged by key, and read whole in the same order.
    #[tokio::test]
    async fn the_catalogue_is_paged_and_read_whole_by_key() {
        let (_db, store, acme) = fixture().await;
        for key in ["invoice", "billing", "project"] {
            store.save(&acme, &resource_type(key)).await.unwrap();
        }
        let order = SortOrder::single(Sort::ascending(ResourceTypeSortField::Key));

        let page_one = store
            .list_all(&acme, &order, &PageRequest::first(Limit::new(2).unwrap()))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = store.list_all(&acme, &order, &after).await.unwrap();
        let every = store.list_every(&acme).await.unwrap();

        assert_eq!(keys(&page_one.items), ["billing", "invoice"]);
        assert_eq!(keys(&page_two.items), ["project"]);
        assert_eq!(keys(&every), ["billing", "invoice", "project"]);
    }

    /// Saving again keeps the new values; deleting removes the type.
    #[tokio::test]
    async fn a_type_is_changed_and_deleted() {
        let (_db, store, acme) = fixture().await;
        let project = resource_type("project");
        store.save(&acme, &project).await.unwrap();
        let changed = ResourceType::reconstitute(ResourceTypeRow {
            id: *project.id(),
            description: None,
            updated_at: at(5),
            ..resource_type_row("project")
        })
        .unwrap();

        store.save(&acme, &changed).await.unwrap();
        let found = store
            .find_by_id(&acme, project.id())
            .await
            .unwrap()
            .unwrap();
        store.delete(&acme, project.id()).await.unwrap();

        assert_eq!(found.description(), None);
        assert_eq!(found.updated_at(), at(5));
        assert!(
            store
                .find_by_id(&acme, project.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The roles holding a permission of their own on `project` are
    /// counted; one on `billing` and one with built-in ones only are not.
    #[tokio::test]
    async fn the_roles_using_a_key_are_counted() {
        let (db, store, acme) = fixture().await;
        let roles = PgRoleStore::new(Arc::clone(&db.databases));
        for (name, custom) in [
            ("editor", vec!["project:write", "billing:read"]),
            ("viewer", vec!["project:read"]),
            ("biller", vec!["billing:read"]),
            ("admin", Vec::new()),
        ] {
            let held = Role::reconstitute(RoleRow {
                custom_permissions: custom
                    .into_iter()
                    .map(|written| CustomPermission::parse(written).unwrap())
                    .collect(),
                ..role_row(name)
            })
            .unwrap();
            roles.save(&acme, &held).await.unwrap();
        }

        let using = store
            .count_roles_using(&acme, &segment("project"))
            .await
            .unwrap();
        let elsewhere = store
            .count_roles_using(&tenant(), &segment("project"))
            .await
            .unwrap();

        assert_eq!(using, 2);
        assert_eq!(elsewhere, 0);
    }

    /// An action duplicated directly in a stored resource type makes its
    /// lookup fail as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_type_is_refused() {
        let (db, store, acme) = fixture().await;
        let project = resource_type("project");
        store.save(&acme, &project).await.unwrap();
        db.tamper(
            "UPDATE resource_types SET actions = jsonb_set(actions, '{value}', \
             (actions->'value') || (actions->'value'))",
        )
        .await;

        let read = store.find_by_id(&acme, project.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
