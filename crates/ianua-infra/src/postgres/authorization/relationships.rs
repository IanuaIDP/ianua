//! Relationships on the objects of a tenant's app: who holds which
//! relation on which object, and which object sits under which.
//!
//! An access check reads an object's relationships and those of every
//! object above it in one recursive query.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{
    RelationshipFilter, RelationshipSortField, RelationshipStore,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::relationship::{ObjectRef, RelationLink, Relationship};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::RelationshipId;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{RelationshipColumns, RelationshipRecord, subject_columns};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps one fact about an object to one row.
const FACT_KEY: &str = "relationships_fact_key";

/// The Postgres relationship store.
pub struct PgRelationshipStore {
    databases: Arc<Databases>,
}

impl PgRelationshipStore {
    /// A store keeping relationships in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgRelationshipStore {}

fn rebuilt(
    records: Vec<RelationshipRecord>,
) -> Result<Vec<Relationship<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(RelationshipRecord::into_relationship)
        .collect()
}

impl SortColumns for RelationshipSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The ids of the relationships of `tenant_id` that `filter` keeps.
fn listed(tenant_id: &ScopedTenant, filter: &RelationshipFilter) -> PageQuery<'static> {
    let every = PageQuery::ids("id", "relationships").filter("tenant_id = ?", *tenant_id.as_uuid());
    match filter {
        RelationshipFilter::All => every,
        RelationshipFilter::OnObject(object) => every
            .filter(
                "object_type = ?",
                object.resource_type().as_str().to_owned(),
            )
            .filter("object_key = ?", object.key().as_str().to_owned()),
        RelationshipFilter::HeldBy(subject) => {
            let (kind, id) = subject_columns(subject);
            every
                .keep("link = 'holds'")
                .filter("subject_kind = ?", kind)
                .filter("subject_id = ?", id)
        }
    }
}

/// Inserts one relationship and translates only its known duplicate-fact constraint.
async fn write_relationship(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    relationship: &Relationship<ResolvedTenant>,
    columns: &RelationshipColumns<'_>,
) -> Result<Uniqueness, sqlx::Error> {
    let attempt = sqlx::query_file!(
        "queries/relationships/save.sql",
        relationship.id().as_uuid(),
        tenant_id,
        columns.object_type,
        columns.object_key,
        columns.link,
        columns.relation,
        columns.subject_kind,
        columns.subject_id,
        columns.parent_type,
        columns.parent_key,
        relationship.created_at(),
    )
    .execute(connection)
    .await;
    unique_on(attempt, FACT_KEY)
}

#[async_trait]
impl RelationshipStore for PgRelationshipStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &RelationshipId,
    ) -> Result<Option<Relationship<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RelationshipRecord,
                    "queries/relationships/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(rebuilt(records)?.pop())
    }

    async fn find_same(
        &self,
        tenant_id: &ScopedTenant,
        object: &ObjectRef,
        link: &RelationLink,
    ) -> Result<Option<Relationship<ResolvedTenant>>, DomainError> {
        let columns = RelationshipColumns::of(object, link);
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RelationshipRecord,
                    "queries/relationships/same.sql",
                    tenant_id.as_uuid(),
                    columns.object_type,
                    columns.object_key,
                    columns.link,
                    columns.relation,
                    columns.subject_kind,
                    columns.subject_id,
                    columns.parent_type,
                    columns.parent_key,
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record
            .map(RelationshipRecord::into_relationship)
            .transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: &RelationshipFilter,
        page: &PageRequest,
    ) -> Result<Page<Relationship<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<RelationshipSortField>::default();
        let keyset = page.keyset(&order)?;
        let listed = listed(tenant_id, filter);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = sqlx::query_file_as!(
                    RelationshipRecord,
                    "queries/relationships/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn find_chain(
        &self,
        tenant_id: &ScopedTenant,
        object: &ObjectRef,
        depth: usize,
    ) -> Result<Vec<Relationship<ResolvedTenant>>, DomainError> {
        self.find_chains(tenant_id, std::slice::from_ref(object), depth)
            .await
    }

    async fn find_chains(
        &self,
        tenant_id: &ScopedTenant,
        objects: &[ObjectRef],
        depth: usize,
    ) -> Result<Vec<Relationship<ResolvedTenant>>, DomainError> {
        if objects.is_empty() {
            return Ok(Vec::new());
        }
        let types: Vec<_> = objects
            .iter()
            .map(|object| object.resource_type().as_str().to_owned())
            .collect();
        let keys: Vec<_> = objects
            .iter()
            .map(|object| object.key().as_str().to_owned())
            .collect();
        let depth = i32::try_from(depth).unwrap_or(i32::MAX);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RelationshipRecord,
                    "queries/relationships/chain.sql",
                    tenant_id.as_uuid(),
                    &types,
                    &keys,
                    depth
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        relationship: &Relationship<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = RelationshipColumns::of(relationship.object(), relationship.link());
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                write_relationship(connection, tenant_id.as_uuid(), relationship, &columns).await
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-tenant-already-holds-this-relationship",
                "the tenant already holds this relationship"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &RelationshipId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/relationships/delete.sql",
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
    use ianua_app::listing::Limit;
    use ianua_domain::domains::authorization::relationship::RelationSubject;
    use ianua_domain::types::{GroupId, PrincipalRef, UserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{holds, object, tenant, under};

    /// A fresh database, the store on it, and a tenant whose app writes.
    async fn fixture() -> (TestDb, PgRelationshipStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgRelationshipStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    fn ann() -> RelationSubject {
        RelationSubject::Principal(PrincipalRef::User(UserId::new()))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    /// Reads a relationship page through the store with the requested filter and cursor.
    async fn list_relationships(
        store: &PgRelationshipStore,
        tenant: &ScopedTenant,
        filter: &RelationshipFilter,
        page: &PageRequest,
    ) -> Page<Relationship<ResolvedTenant>> {
        store.list(tenant, filter, page).await.unwrap()
    }

    /// Extracts relationship identifiers without changing their page order.
    fn ids(page: &Page<Relationship<ResolvedTenant>>) -> Vec<RelationshipId> {
        page.items.iter().map(|written| *written.id()).collect()
    }

    /// Saves two objects for one subject and a newer relation for another subject.
    async fn relationships_in_creation_order(
        store: &PgRelationshipStore,
        tenant: &ScopedTenant,
        subject: RelationSubject,
    ) -> [Relationship<ResolvedTenant>; 3] {
        let older = holds(object("project", "42"), "editor", subject, at(0));
        let newer = holds(object("project", "43"), "viewer", subject, at(1));
        let other = holds(object("project", "42"), "viewer", ann(), at(2));
        for written in [&older, &newer, &other] {
            store.save(tenant, written).await.unwrap();
        }
        [older, newer, other]
    }

    /// Two document roots and their shared cyclic ancestry, with expected query order.
    struct Ancestry {
        roots: [ObjectRef; 4],
        written: [Relationship<ResolvedTenant>; 5],
    }

    /// Builds two roots, a shared folder and drive cycle, and one inherited owner.
    fn ancestry() -> Ancestry {
        let first = object("doc", "first");
        let second = object("doc", "second");
        let folder = object("folder", "shared");
        let drive = object("drive", "parent");
        let written = [
            under(first.clone(), folder.clone(), at(0)),
            under(second.clone(), folder.clone(), at(1)),
            under(folder.clone(), drive.clone(), at(2)),
            under(drive.clone(), folder.clone(), at(3)),
            holds(folder.clone(), "owner", ann(), at(4)),
        ];
        Ancestry {
            roots: [first.clone(), second, first, object("doc", "missing")],
            written,
        }
    }

    /// Saves the ancestry and unrelated controls, returning the tenant of the foreign control.
    async fn save_ancestry(
        store: &PgRelationshipStore,
        acme: &ScopedTenant,
        ancestry: &Ancestry,
    ) -> ScopedTenant {
        for relationship in &ancestry.written {
            store.save(acme, relationship).await.unwrap();
        }
        store
            .save(
                acme,
                &holds(object("doc", "unrelated"), "owner", ann(), at(5)),
            )
            .await
            .unwrap();
        let foreign = tenant();
        store
            .save(
                &foreign,
                &holds(ancestry.roots[0].clone(), "owner", ann(), at(6)),
            )
            .await
            .unwrap();
        foreign
    }

    /// Ann is editor of project 42, and the Admins group owns folder 7:
    /// each is found by its id and as the same fact, as written.
    #[tokio::test]
    async fn a_relationship_is_found_by_its_id_and_as_the_same_fact() {
        let (_db, store, acme) = fixture().await;
        let editor = holds(object("project", "42"), "editor", ann(), at(0));
        let owners = holds(
            object("folder", "7"),
            "owner",
            RelationSubject::Group(GroupId::new()),
            at(1),
        );
        let inside = under(object("project", "42"), object("folder", "7"), at(2));
        for written in [&editor, &owners, &inside] {
            store.save(&acme, written).await.unwrap();
        }

        for written in [&editor, &owners, &inside] {
            let by_id = store
                .find_by_id(&acme, written.id())
                .await
                .unwrap()
                .unwrap();
            let same = store
                .find_same(&acme, written.object(), written.link())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(by_id.link(), written.link());
            assert_eq!(same.id(), written.id());
        }
    }

    /// A fact nobody wrote, and an id nobody has, find nothing.
    #[tokio::test]
    async fn an_unknown_relationship_is_not_found() {
        let (_db, store, acme) = fixture().await;
        let editor = holds(object("project", "42"), "editor", ann(), at(0));

        let by_id = store.find_by_id(&acme, editor.id()).await.unwrap();
        let same = store
            .find_same(&acme, editor.object(), editor.link())
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(same.is_none());
    }

    /// Saving the same object, relation and subject under a second record
    /// conflicts with the relationship already stored.
    #[tokio::test]
    async fn the_same_fact_twice_is_refused() {
        let (_db, store, acme) = fixture().await;
        let subject = ann();
        store
            .save(
                &acme,
                &holds(object("project", "42"), "editor", subject, at(0)),
            )
            .await
            .unwrap();

        let again = store
            .save(
                &acme,
                &holds(object("project", "42"), "editor", subject, at(1)),
            )
            .await;

        assert!(matches!(again, Err(DomainError::Conflict(_))));
    }

    /// A list is newest first, page by page, and narrowed to an object or
    /// to who holds a relation.
    #[tokio::test]
    async fn a_list_is_newest_first_and_narrowed_by_its_filter() {
        let (_db, store, acme) = fixture().await;
        let subject = ann();
        let [older, newer, other] = relationships_in_creation_order(&store, &acme, subject).await;

        let page_one = list_relationships(&store, &acme, &RelationshipFilter::All, &first(2)).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = list_relationships(&store, &acme, &RelationshipFilter::All, &after).await;
        let on_42 = list_relationships(
            &store,
            &acme,
            &RelationshipFilter::OnObject(object("project", "42")),
            &first(10),
        )
        .await;
        let held = list_relationships(
            &store,
            &acme,
            &RelationshipFilter::HeldBy(subject),
            &first(10),
        )
        .await;
        assert_eq!(ids(&page_one), [*other.id(), *newer.id()]);
        assert_eq!(ids(&page_two), [*older.id()]);
        assert_eq!(ids(&on_42), [*other.id(), *older.id()]);
        assert_eq!(ids(&held), [*newer.id(), *older.id()]);
    }

    /// A document sits in a folder, which sits in a drive: an access check
    /// on the document reads what is held on all three, up to the depth
    /// asked, and nothing held on another document.
    #[tokio::test]
    async fn the_chain_above_an_object_is_read_to_its_depth() {
        let (_db, store, acme) = fixture().await;
        let (doc, folder, drive) = (
            object("doc", "1"),
            object("folder", "2"),
            object("drive", "3"),
        );
        let written = [
            under(doc.clone(), folder.clone(), at(0)),
            under(folder.clone(), drive.clone(), at(1)),
            holds(drive.clone(), "owner", ann(), at(2)),
            holds(object("doc", "9"), "owner", ann(), at(3)),
        ];
        for relationship in &written {
            store.save(&acme, relationship).await.unwrap();
        }

        let deep = store.find_chain(&acme, &doc, 8).await.unwrap();
        let shallow = store.find_chain(&acme, &doc, 1).await.unwrap();

        assert_eq!(deep.len(), 3);
        assert_eq!(shallow.len(), 2);
    }

    /// Two objects share a cyclic ancestry. A batch returns each relationship
    /// once, respects depth, and excludes another tenant and unrelated objects.
    #[tokio::test]
    async fn ancestry_batches_preserve_depth_and_tenant_boundaries() {
        let (_db, store, acme) = fixture().await;
        let ancestry = ancestry();
        let foreign = save_ancestry(&store, &acme, &ancestry).await;
        let Ancestry { roots, written } = ancestry;

        let deep = store.find_chains(&acme, &roots, 8).await.unwrap();
        let shallow = store.find_chains(&acme, &roots, 0).await.unwrap();

        assert_eq!(
            deep.iter().map(|row| *row.id()).collect::<Vec<_>>(),
            written.iter().map(|row| *row.id()).collect::<Vec<_>>()
        );
        assert_eq!(shallow.len(), 2);
        assert!(store.find_chains(&acme, &[], 8).await.unwrap().is_empty());
        assert_eq!(
            store.find_chains(&foreign, &roots, 8).await.unwrap().len(),
            1
        );
    }

    /// Deleting Ann's saved editor relation removes it from the scoped lookup.
    #[tokio::test]
    async fn a_removed_relationship_is_gone() {
        let (_db, store, acme) = fixture().await;
        let editor = holds(object("project", "42"), "editor", ann(), at(0));
        store.save(&acme, &editor).await.unwrap();

        store.delete(&acme, editor.id()).await.unwrap();

        assert!(
            store
                .find_by_id(&acme, editor.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Globex cannot find Acme's relationship by ID, through its ancestry
    /// chain or in the relationship list.
    #[tokio::test]
    async fn another_tenants_relationships_are_invisible() {
        let (_db, store, acme) = fixture().await;
        let editor = holds(object("project", "42"), "editor", ann(), at(0));
        store.save(&acme, &editor).await.unwrap();
        let globex = tenant();

        let by_id = store.find_by_id(&globex, editor.id()).await.unwrap();
        let chain = store.find_chain(&globex, editor.object(), 8).await.unwrap();
        let listed = store
            .list(&globex, &RelationshipFilter::All, &first(10))
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(chain.is_empty());
        assert!(listed.items.is_empty());
    }

    /// A row altered to place an object under itself is refused as corrupt
    /// storage when read.
    #[tokio::test]
    async fn an_object_under_itself_is_refused() {
        let (db, store, acme) = fixture().await;
        let inside = under(object("doc", "1"), object("folder", "2"), at(0));
        store.save(&acme, &inside).await.unwrap();
        db.tamper(
            "ALTER TABLE relationships DROP CONSTRAINT relationships_not_under_itself; \
             UPDATE relationships SET parent_type = 'doc', parent_key = '1'",
        )
        .await;

        let read = store.find_by_id(&acme, inside.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
