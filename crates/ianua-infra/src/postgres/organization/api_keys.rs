//! Organization API keys, kept in the platform database.
//!
//! Only a key's hash is kept, beside the prefix a leaked key is recognised
//! by. A list first reads the ids of its page, then reads those rows
//! through the one by-ids query, as every read of a key does.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::organization::{OrgApiKeySortField, OrgApiKeyStore};
use ianua_domain::domains::organization::access::api_key::OrgApiKey;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgApiKeyId, OrganizationId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{ApiKeyColumns, ApiKeyRecord};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of organization API keys.
pub struct PgOrgApiKeyStore {
    databases: Arc<Databases>,
}

impl PgOrgApiKeyStore {
    /// A store keeping API keys in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The records of the keys `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<ApiKeyRecord>, sqlx::Error> {
    sqlx::query_file_as!(ApiKeyRecord, "queries/org_api_keys/by_ids.sql", ids)
        .fetch_all(connection)
        .await
}

fn rebuilt_all(records: Vec<ApiKeyRecord>) -> Result<Vec<OrgApiKey>, DomainError> {
    records
        .into_iter()
        .map(ApiKeyRecord::into_api_key)
        .collect()
}

impl SortColumns for OrgApiKeySortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Name => "name",
            Self::LastUsedAt => "last_used_at",
            Self::ExpiresAt => "expires_at",
        }
    }

    fn nullable(self) -> Nullable {
        match self {
            Self::CreatedAt | Self::Name => Nullable::Never,
            Self::LastUsedAt | Self::ExpiresAt => Nullable::Maybe,
        }
    }
}

#[async_trait]
impl OrgApiKeyStore for PgOrgApiKeyStore {
    async fn list_by_org(
        &self,
        organization_id: &OrganizationId,
        sort: &SortOrder<OrgApiKeySortField>,
        page: &PageRequest,
    ) -> Result<Page<OrgApiKey>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed = PageQuery::ids("id", "org_api_keys")
            .filter("organization_id = ?", *organization_id.as_uuid());
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids = listed.fetch(&keyset, &mut *connection).await?;
            let records = records_of(connection, &ids).await?;
            Ok(in_page_order(&ids, records, |record| record.id))
        })
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn list_minted_through(
        &self,
        organization_id: &OrganizationId,
        parent: &OrgApiKeyId,
    ) -> Result<Vec<OrgApiKey>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ApiKeyRecord,
                "queries/org_api_keys/minted_through.sql",
                organization_id.as_uuid(),
                parent.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        rebuilt_all(records)
    }

    async fn find_by_id(&self, id: &OrgApiKeyId) -> Result<Option<OrgApiKey>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            records_of(connection, &ids).await
        })
        .await?;
        records
            .into_iter()
            .next()
            .map(ApiKeyRecord::into_api_key)
            .transpose()
    }

    async fn save(&self, key: &OrgApiKey) -> Result<(), DomainError> {
        let columns = ApiKeyColumns::of(key);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_api_keys/save.sql",
                columns.id,
                columns.organization_id,
                columns.name,
                columns.key_prefix,
                columns.key_hash,
                columns.scopes.as_slice(),
                columns.created_by,
                columns.parent_key_id,
                columns.expires_at,
                columns.last_used_at,
                columns.status,
                columns.created_at,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_domain::domains::organization::access::api_key::{
        MintedThrough, OrgApiKeyRow, OrgApiKeyStatus,
    };
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{Expiry, OrgUserId};

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{org_api_key_row, organization_row};

    struct Fixture {
        db: TestDb,
        store: PgOrgApiKeyStore,
        organization: OrganizationId,
        ann: OrgUserId,
    }

    /// A fresh database holding Acme, the store on it, and the member said
    /// to make Acme's keys.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = an_organization(&db, "acme").await;
        let store = PgOrgApiKeyStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            organization,
            ann: OrgUserId::new(),
        }
    }

    /// Saves an organization under `slug` through its store.
    async fn an_organization(db: &TestDb, slug: &str) -> OrganizationId {
        let organization = Organization::reconstitute(organization_row(slug, slug)).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        *organization.id()
    }

    fn key(row: OrgApiKeyRow) -> OrgApiKey {
        OrgApiKey::reconstitute(row).unwrap()
    }

    fn named(db: &Fixture, name: &str) -> OrgApiKey {
        key(org_api_key_row(db.organization, db.ann, name))
    }

    fn minted_through(db: &Fixture, name: &str, parent: &OrgApiKey) -> OrgApiKey {
        key(OrgApiKeyRow {
            minted_through: MintedThrough::Key(*parent.id()),
            ..org_api_key_row(db.organization, db.ann, name)
        })
    }

    async fn save_all(store: &PgOrgApiKeyStore, keys: &[&OrgApiKey]) {
        for key in keys {
            store.save(key).await.unwrap();
        }
    }

    fn by(field: OrgApiKeySortField) -> SortOrder<OrgApiKeySortField> {
        SortOrder::single(Sort::ascending(field))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn names(keys: &[OrgApiKey]) -> Vec<&str> {
        keys.iter().map(|key| key.name().as_str()).collect()
    }

    /// Ann makes a CI key: it is found by its id as it was saved.
    #[tokio::test]
    async fn a_saved_key_is_found_by_its_id() {
        let db = fixture().await;
        let made = named(&db, "ci");

        db.store.save(&made).await.unwrap();

        let found = db.store.find_by_id(made.id()).await.unwrap().unwrap();
        assert_eq!(found.organization_id(), made.organization_id());
        assert_eq!(found.key_prefix(), made.key_prefix());
        assert_eq!(found.key_hash(), made.key_hash());
        assert_eq!(found.scopes(), made.scopes());
        assert_eq!(found.created_by(), made.created_by());
        assert_eq!(found.minted_through(), MintedThrough::Session);
        assert_eq!(found.expires_at(), made.expires_at());
        assert_eq!(found.created_at(), made.created_at());
    }

    /// An id no key has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_key_is_not_found() {
        let db = fixture().await;

        let found = db.store.find_by_id(&OrgApiKeyId::new()).await.unwrap();

        assert!(found.is_none());
    }

    /// The key is used and then revoked: saving again keeps when it was
    /// last used and that it no longer works.
    #[tokio::test]
    async fn saving_again_keeps_its_use_and_revocation() {
        let db = fixture().await;
        let made = named(&db, "ci");
        db.store.save(&made).await.unwrap();
        let revoked = key(OrgApiKeyRow {
            id: *made.id(),
            last_used_at: Some(at(7)),
            status: OrgApiKeyStatus::Revoked,
            ..org_api_key_row(db.organization, db.ann, "ci")
        });

        db.store.save(&revoked).await.unwrap();

        let found = db.store.find_by_id(made.id()).await.unwrap().unwrap();
        assert!(found.is_revoked());
        assert_eq!(found.last_used_at(), Some(at(7)));
    }

    /// Revoking a leaked key finds every key minted through it, at any
    /// depth, and none minted through another key.
    #[tokio::test]
    async fn the_keys_minted_through_a_key_are_found_at_any_depth() {
        let db = fixture().await;
        let leaked = named(&db, "leaked");
        let child = minted_through(&db, "child", &leaked);
        let grandchild = key(OrgApiKeyRow {
            minted_through: MintedThrough::Key(*child.id()),
            created_at: at(1),
            ..org_api_key_row(db.organization, db.ann, "grandchild")
        });
        let other = named(&db, "other");
        let unrelated = minted_through(&db, "unrelated", &other);
        save_all(
            &db.store,
            &[&leaked, &child, &grandchild, &other, &unrelated],
        )
        .await;

        let minted = db
            .store
            .list_minted_through(&db.organization, leaked.id())
            .await
            .unwrap();

        assert_eq!(names(&minted), ["child", "grandchild"]);
    }

    /// Acme pages through its keys by name, each page after the last, and
    /// sees no other organization's key.
    #[tokio::test]
    async fn an_organizations_keys_are_read_page_by_page() {
        let db = fixture().await;
        let globex = an_organization(&db.db, "globex").await;
        let theirs = key(org_api_key_row(globex, db.ann, "theirs"));
        save_all(
            &db.store,
            &[
                &named(&db, "c-key"),
                &named(&db, "a-key"),
                &named(&db, "b-key"),
                &theirs,
            ],
        )
        .await;
        let order = by(OrgApiKeySortField::Name);

        let page_one = db
            .store
            .list_by_org(&db.organization, &order, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = db
            .store
            .list_by_org(&db.organization, &order, &after)
            .await
            .unwrap();

        assert_eq!(names(&page_one.items), ["a-key", "b-key"]);
        assert_eq!(names(&page_two.items), ["c-key"]);
        assert!(!page_two.has_next());
    }

    /// A list by last use pages past the keys never used, which come last,
    /// without skipping or repeating one.
    #[tokio::test]
    async fn a_list_by_last_use_pages_past_the_keys_never_used() {
        let db = fixture().await;
        let used = key(OrgApiKeyRow {
            last_used_at: Some(at(3)),
            ..org_api_key_row(db.organization, db.ann, "used")
        });
        save_all(
            &db.store,
            &[&named(&db, "never-one"), &used, &named(&db, "never-two")],
        )
        .await;
        let order = by(OrgApiKeySortField::LastUsedAt);

        let page_one = db
            .store
            .list_by_org(&db.organization, &order, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = db
            .store
            .list_by_org(&db.organization, &order, &after)
            .await
            .unwrap();

        assert_eq!(page_one.items.len() + page_two.items.len(), 3);
        assert_eq!(names(&page_one.items)[0], "used");
        assert!(!page_two.has_next());
    }

    /// A list by expiry and one by creation each read every key once.
    #[tokio::test]
    async fn a_list_by_expiry_or_creation_reads_every_key() {
        let db = fixture().await;
        let expiring = key(OrgApiKeyRow {
            expires_at: Expiry::At(at(500)),
            ..org_api_key_row(db.organization, db.ann, "expiring")
        });
        save_all(&db.store, &[&named(&db, "forever"), &expiring]).await;

        let by_expiry = db
            .store
            .list_by_org(
                &db.organization,
                &by(OrgApiKeySortField::ExpiresAt),
                &first(10),
            )
            .await
            .unwrap();
        let by_creation = db
            .store
            .list_by_org(
                &db.organization,
                &by(OrgApiKeySortField::CreatedAt),
                &first(10),
            )
            .await
            .unwrap();

        assert_eq!(names(&by_expiry.items), ["expiring", "forever"]);
        assert_eq!(by_creation.items.len(), 2);
    }

    /// Reading an API key whose stored name was made blank returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_key_is_refused() {
        let db = fixture().await;
        let made = named(&db, "ci");
        db.store.save(&made).await.unwrap();
        db.db.tamper("UPDATE org_api_keys SET name = ''").await;

        let read = db.store.find_by_id(made.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
