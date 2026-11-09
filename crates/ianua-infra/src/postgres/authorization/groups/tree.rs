//! A tenant's groups: their tree, and the roles each carries.
//!
//! A group's roles live in `group_roles`, beside its row, so a role can be
//! asked which groups carry it from an index. Saving a group writes both
//! in one transaction.

pub(crate) mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{GroupSortField, GroupStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::group::Group;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, Label, RoleId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{GroupColumns, GroupRecord, groups_from};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a name to one group of a tenant.
const NAME_KEY: &str = "groups_name_key";

/// The Postgres group store.
pub struct PgGroupStore {
    databases: Arc<Databases>,
}

impl PgGroupStore {
    /// A store keeping groups in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgGroupStore {}

/// The records of the groups of `tenant_id` that `ids` names, in no order.
async fn groups_of(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<GroupRecord>, sqlx::Error> {
    sqlx::query_file_as!(GroupRecord, "queries/groups/by_ids.sql", tenant_id, ids)
        .fetch_all(connection)
        .await
}

/// Writes the group `columns` describe, and puts exactly its roles on it.
async fn write_group(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &GroupColumns<'_>,
) -> Result<Uniqueness, sqlx::Error> {
    let attempt = sqlx::query_file!(
        "queries/groups/save.sql",
        columns.id,
        tenant_id,
        columns.name,
        columns.origin,
        columns.parent_id,
        columns.created_at,
        columns.updated_at,
    )
    .execute(&mut *connection)
    .await;
    if unique_on(attempt, NAME_KEY)? == Uniqueness::Taken {
        return Ok(Uniqueness::Taken);
    }
    sqlx::query_file!("queries/group_roles/withdraw.sql", tenant_id, columns.id)
        .execute(&mut *connection)
        .await?;
    sqlx::query_file!(
        "queries/group_roles/give.sql",
        tenant_id,
        columns.id,
        &columns.role_ids
    )
    .execute(connection)
    .await?;
    Ok(Uniqueness::Kept)
}

impl SortColumns for GroupSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl GroupStore for PgGroupStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &GroupId,
    ) -> Result<Option<Group<ResolvedTenant>>, DomainError> {
        Ok(self.find_by_ids(tenant_id, &[*id]).await?.pop())
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[GroupId],
    ) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| groups_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        groups_from(records)
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &Label,
    ) -> Result<Option<Group<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    GroupRecord,
                    "queries/groups/by_name.sql",
                    tenant_id.as_uuid(),
                    name.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(GroupRecord::into_group).transpose()
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<GroupSortField>,
        page: &PageRequest,
    ) -> Result<Page<Group<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed = PageQuery::ids("id", "groups").filter("tenant_id = ?", *tenant_id.as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = groups_of(connection, tenant_id.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(groups_from(records)?))
    }

    async fn list_children(
        &self,
        tenant_id: &ScopedTenant,
        parent_id: &GroupId,
    ) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    GroupRecord,
                    "queries/groups/children.sql",
                    tenant_id.as_uuid(),
                    parent_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        groups_from(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        group: &Group<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = GroupColumns::of(group);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_group(connection, tenant_id.as_uuid(), &columns).await,
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-group-of-this-tenant-already",
                "another group of this tenant already has this name"
            ))),
        }
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &GroupId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/groups/delete.sql",
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

    async fn count_carrying_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError> {
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/group_roles/count_carrying.sql",
                    tenant_id.as_uuid(),
                    role_id.as_uuid()
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
    use ianua_app::ports::authorization::{GroupMembershipStore, RoleStore};
    use ianua_domain::domains::authorization::group::{GroupOrigin, GroupPlace, GroupRow};
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::postgres::authorization::{PgGroupMembershipStore, PgRoleStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{
        group, group_row, group_under, membership, role, tenant,
    };

    /// A fresh database, the store on it, and a tenant to keep groups in.
    async fn fixture() -> (TestDb, PgGroupStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgGroupStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    /// Saves a role called `name` in `tenant_id` through the role store.
    async fn hold_role(db: &TestDb, tenant_id: &ScopedTenant, name: &str) -> Role<ResolvedTenant> {
        let held = role(name);
        PgRoleStore::new(Arc::clone(&db.databases))
            .save(tenant_id, &held)
            .await
            .unwrap();
        held
    }

    fn names(groups: &[Group<ResolvedTenant>]) -> Vec<&str> {
        groups.iter().map(|group| group.name().as_str()).collect()
    }

    /// Requires a returned batch to retain the expected group's directly carried roles.
    fn assert_group_roles(groups: &[Group<ResolvedTenant>], id: &GroupId, roles: &[RoleId]) {
        let group = groups.iter().find(|group| group.id() == id).unwrap();
        assert_eq!(group.role_ids(), roles);
    }

    /// A saved group is found by its id and its name, with its place and
    /// its roles in the order they were given.
    #[tokio::test]
    async fn a_saved_group_is_found_with_its_roles_in_order() {
        let (db, store, acme) = fixture().await;
        let (admin, viewer) = (
            hold_role(&db, &acme, "admin").await,
            hold_role(&db, &acme, "viewer").await,
        );
        let engineering = group("Engineering", vec![*viewer.id(), *admin.id()]);

        store.save(&acme, &engineering).await.unwrap();

        let by_id = store
            .find_by_id(&acme, engineering.id())
            .await
            .unwrap()
            .unwrap();
        let by_name = store
            .find_by_name(&acme, engineering.name())
            .await
            .unwrap()
            .unwrap();
        for found in [&by_id, &by_name] {
            assert_eq!(found.role_ids(), [*viewer.id(), *admin.id()]);
            assert_eq!(found.place(), &GroupPlace::TopLevel);
            assert_eq!(found.origin(), GroupOrigin::Dashboard);
            assert_eq!(found.created_at(), engineering.created_at());
        }
    }

    /// A group batch keeps local groups with their roles and omits unknown
    /// and foreign ids, without duplicating repeated ids.
    #[tokio::test]
    async fn group_batches_keep_the_tenant_boundary() {
        let (db, store, acme) = fixture().await;
        let role = hold_role(&db, &acme, "admin").await;
        let first = group("Engineering", vec![*role.id()]);
        let second = group("Sales", vec![]);
        let foreign = group("Other", vec![]);
        store.save(&acme, &first).await.unwrap();
        store.save(&acme, &second).await.unwrap();
        store.save(&tenant(), &foreign).await.unwrap();

        let found = store
            .find_by_ids(
                &acme,
                &[
                    *second.id(),
                    *foreign.id(),
                    GroupId::new(),
                    *first.id(),
                    *first.id(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|group| group.id() == second.id()));
        assert_group_roles(&found, first.id(), &[*role.id()]);
        assert!(store.find_by_ids(&acme, &[]).await.unwrap().is_empty());
    }

    /// An id or a name the tenant has no group under finds nothing.
    #[tokio::test]
    async fn an_unknown_group_is_not_found() {
        let (_db, store, acme) = fixture().await;

        let by_id = store.find_by_id(&acme, &GroupId::new()).await.unwrap();
        let by_name = store
            .find_by_name(&acme, &Label::new("name", "nobody").unwrap())
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(by_name.is_none());
    }

    /// Globex cannot find Acme's group by ID or include it in a group page.
    #[tokio::test]
    async fn another_tenants_groups_are_invisible() {
        let (_db, store, acme) = fixture().await;
        let engineering = group("Engineering", Vec::new());
        store.save(&acme, &engineering).await.unwrap();
        let globex = tenant();
        let order = SortOrder::single(Sort::ascending(GroupSortField::Name));

        let by_id = store.find_by_id(&globex, engineering.id()).await.unwrap();
        let listed = store
            .list_all(
                &globex,
                &order,
                &PageRequest::first(Limit::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(listed.items.is_empty());
    }

    /// A second Engineering group in Acme is refused as a name conflict.
    #[tokio::test]
    async fn a_name_another_group_has_is_refused() {
        let (_db, store, acme) = fixture().await;
        store
            .save(&acme, &group("Engineering", Vec::new()))
            .await
            .unwrap();

        let second = store.save(&acme, &group("Engineering", Vec::new())).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Saving again keeps the new name and exactly the new roles.
    #[tokio::test]
    async fn saving_again_keeps_the_new_name_and_roles() {
        let (db, store, acme) = fixture().await;
        let (admin, viewer) = (
            hold_role(&db, &acme, "admin").await,
            hold_role(&db, &acme, "viewer").await,
        );
        let engineering = group("Engineering", vec![*admin.id()]);
        store.save(&acme, &engineering).await.unwrap();
        let renamed = Group::reconstitute(GroupRow {
            id: *engineering.id(),
            name: Label::new("name", "Platform").unwrap(),
            role_ids: vec![*viewer.id()],
            updated_at: at(5),
            ..group_row("Engineering")
        })
        .unwrap();

        store.save(&acme, &renamed).await.unwrap();

        let found = store
            .find_by_id(&acme, engineering.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "Platform");
        assert_eq!(found.role_ids(), [*viewer.id()]);
        assert_eq!(
            store.count_carrying_role(&acme, admin.id()).await.unwrap(),
            0
        );
    }

    /// The groups are paged by name, each page after the last.
    #[tokio::test]
    async fn a_list_is_read_page_by_page_in_its_order() {
        let (_db, store, acme) = fixture().await;
        for name in ["Carol", "Alice", "Bob"] {
            store.save(&acme, &group(name, Vec::new())).await.unwrap();
        }
        let order = SortOrder::single(Sort::ascending(GroupSortField::Name));

        let page_one = store
            .list_all(&acme, &order, &PageRequest::first(Limit::new(2).unwrap()))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = store.list_all(&acme, &order, &after).await.unwrap();

        assert_eq!(names(&page_one.items), ["Alice", "Bob"]);
        assert_eq!(names(&page_two.items), ["Carol"]);
        assert!(!page_two.has_next());
    }

    /// The groups under Engineering are its children, and no others.
    #[tokio::test]
    async fn the_children_of_a_group_are_listed() {
        let (_db, store, acme) = fixture().await;
        let engineering = group("Engineering", Vec::new());
        store.save(&acme, &engineering).await.unwrap();
        let backend = group_under("Backend", GroupPlace::Under(*engineering.id()));
        store.save(&acme, &backend).await.unwrap();
        store
            .save(&acme, &group("Sales", Vec::new()))
            .await
            .unwrap();

        let children = store.list_children(&acme, engineering.id()).await.unwrap();

        assert_eq!(names(&children), ["Backend"]);
    }

    /// Groups carrying a role are counted, others are not.
    #[tokio::test]
    async fn the_groups_carrying_a_role_are_counted() {
        let (db, store, acme) = fixture().await;
        let admin = hold_role(&db, &acme, "admin").await;
        for name in ["Admins", "Owners"] {
            store
                .save(&acme, &group(name, vec![*admin.id()]))
                .await
                .unwrap();
        }
        store
            .save(&acme, &group("Sales", Vec::new()))
            .await
            .unwrap();

        let carrying = store.count_carrying_role(&acme, admin.id()).await.unwrap();

        assert_eq!(carrying, 2);
    }

    /// A deleted group is gone, and so are its members.
    #[tokio::test]
    async fn a_deleted_group_is_gone_with_its_members() {
        let (db, store, acme) = fixture().await;
        let engineering = group("Engineering", Vec::new());
        store.save(&acme, &engineering).await.unwrap();
        let ann = PrincipalRef::User(UserId::new());
        let memberships = PgGroupMembershipStore::new(Arc::clone(&db.databases));
        memberships
            .save(&acme, &membership(ann, *engineering.id()))
            .await
            .unwrap();

        store.delete(&acme, engineering.id()).await.unwrap();

        assert!(
            store
                .find_by_id(&acme, engineering.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !memberships
                .exists(&acme, &ann, engineering.id())
                .await
                .unwrap()
        );
    }

    /// Deleting Engineering fails while Backend still names it as its parent.
    #[tokio::test]
    async fn a_group_with_a_group_under_it_is_not_deleted() {
        let (_db, store, acme) = fixture().await;
        let engineering = group("Engineering", Vec::new());
        store.save(&acme, &engineering).await.unwrap();
        store
            .save(
                &acme,
                &group_under("Backend", GroupPlace::Under(*engineering.id())),
            )
            .await
            .unwrap();

        let deleted = store.delete(&acme, engineering.id()).await;

        assert!(matches!(deleted, Err(DomainError::Infrastructure(_))));
    }

    /// An unknown origin written directly to a group row makes its lookup
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_row_with_an_unknown_origin_is_refused() {
        let (db, store, acme) = fixture().await;
        let engineering = group("Engineering", Vec::new());
        store.save(&acme, &engineering).await.unwrap();
        db.tamper(
            "ALTER TABLE groups DROP CONSTRAINT groups_origin_known; \
             UPDATE groups SET origin = 'ldap'",
        )
        .await;

        let read = store.find_by_id(&acme, engineering.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
