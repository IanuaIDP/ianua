//! A tenant's API keys, and the sweep across every tenant that deletes the
//! expired ones: the two stores of `ports/oauth/api_keys.rs`, sharing one
//! mapping.
//!
//! Only a key's hash is kept, beside the prefix it is recognised by. A
//! revoked key is deleted. An edit or a use writes only its own columns in
//! one `UPDATE .. WHERE id`, so neither brings back a key revoked
//! meanwhile, and a use never undoes an edit.
//!
//! The sweep is a background delete, not a lookup that must be one indexed
//! query, so it deletes the expired keys of the tenants in the platform
//! database in one statement, as platform work, and those of each tenant
//! with a database of its own in that database, all at once. No
//! platform-wide claim is kept.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::{ApiKeySortField, ApiKeyStore, CrossTenantApiKeyStore, UseRecorded};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::clients::api_key::ApiKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ApiKeyId, CountryCode, IpAddress, Label, TenantId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{
    ApiKeyColumns, ApiKeyRecord, ExpiredKeyRecord, countries_column, paused_column,
    seen_countries_column,
};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::oauth::scopes::scopes_column;

/// The constraint that keeps a key prefix to one key of a tenant.
const PREFIX_KEY: &str = "api_keys_key_prefix_key";

/// Reports a prefix collision using the API-key store's conflict vocabulary.
fn ensure_prefix_available(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-another-api-key-of-the-tenant",
            "another API key of the tenant has this prefix"
        ))),
    }
}

/// The Postgres store of tenant API keys.
pub struct PgApiKeyStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgApiKeyStore {}

impl PgApiKeyStore {
    /// A store keeping API keys in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The records of the keys of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<ApiKeyRecord>, sqlx::Error> {
    sqlx::query_file_as!(ApiKeyRecord, "queries/api_keys/by_ids.sql", tenant, ids)
        .fetch_all(connection)
        .await
}

fn rebuilt_all(records: Vec<ApiKeyRecord>) -> Result<Vec<ApiKey<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(ApiKeyRecord::into_api_key)
        .collect()
}

impl SortColumns for ApiKeySortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Name => "name",
            Self::ExpiresAt => "expires_at",
            Self::LastUsedAt => "last_used_at",
        }
    }

    fn nullable(self) -> Nullable {
        match self {
            Self::CreatedAt | Self::Name => Nullable::Never,
            Self::ExpiresAt | Self::LastUsedAt => Nullable::Maybe,
        }
    }
}

#[async_trait]
impl ApiKeyStore for PgApiKeyStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ApiKeyId,
    ) -> Result<Option<ApiKey<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ApiKeySortField>,
        page: &PageRequest,
    ) -> Result<Page<ApiKey<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let tenant = *tenant_id.as_uuid();
        let listed = PageQuery::ids("id", "api_keys").filter("tenant_id = ?", tenant);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, &tenant, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ApiKeyColumns::of(key)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/api_keys/insert.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.key_prefix,
                    columns.key_hash,
                    columns.scopes.as_slice(),
                    columns.created_by,
                    columns.expires_at,
                    columns.last_used_at,
                    columns.last_used_ip,
                    columns.created_at,
                    columns.paused_at,
                    columns.seen_countries.as_slice(),
                )
                .execute(connection)
                .await;
                unique_on(attempt, PREFIX_KEY)
            },
        )
        .await?;
        ensure_prefix_available(written)
    }

    async fn update(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let scopes = scopes_column(key.scopes());
        let updated = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/api_keys/update.sql",
                    tenant_id.as_uuid(),
                    key.id().as_uuid(),
                    key.name().as_str(),
                    scopes.as_slice(),
                    paused_column(key.standing())
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(updated.rows_affected() == 1)
    }

    async fn record_use(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
        read_countries: &[CountryCode],
    ) -> Result<UseRecorded, DomainError> {
        let used = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let countries = seen_countries_column(key);
                let read = countries_column(read_countries);
                sqlx::query_file!(
                    "queries/api_keys/record_use.sql",
                    tenant_id.as_uuid(),
                    key.id().as_uuid(),
                    key.last_used_at(),
                    key.last_used_ip().map(IpAddress::as_str),
                    countries.as_slice(),
                    read.as_slice()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        Ok(match (used.written, used.kept) {
            (true, _) => UseRecorded::Written,
            (false, true) => UseRecorded::Overtaken,
            (false, false) => UseRecorded::Gone,
        })
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ApiKeyId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/api_keys/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

/// The Postgres sweep of expired API keys across every tenant.
pub struct PgCrossTenantApiKeyStore {
    databases: Arc<Databases>,
}

impl PgCrossTenantApiKeyStore {
    /// A sweep deleting expired keys from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Deletes the expired keys of every tenant in the platform database.
    async fn shared(&self, now: OffsetDateTime) -> Result<Vec<ExpiredKeyRecord>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(ExpiredKeyRecord, "queries/api_keys/delete_expired.sql", now)
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// Deletes the expired keys of `tenant`, in its own database.
    async fn own(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
    ) -> Result<Vec<ExpiredKeyRecord>, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_as!(
                    ExpiredKeyRecord,
                    "queries/api_keys/delete_expired_of_tenant.sql",
                    tenant.as_uuid(),
                    now
                )
                .fetch_all(connection)
                .await
            },
        )
        .await
    }
}

#[async_trait]
impl CrossTenantApiKeyStore for PgCrossTenantApiKeyStore {
    async fn delete_expired(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<(TenantId, ApiKeyId, Label)>, DomainError> {
        let own_databases = self.databases.with_own_database();
        let (shared, own) = futures_util::try_join!(
            self.shared(now),
            try_join_all(
                own_databases
                    .into_iter()
                    .map(|tenant| self.own(tenant, now))
            )
        )?;
        shared
            .into_iter()
            .chain(own.into_iter().flatten())
            .map(ExpiredKeyRecord::into_expired)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_domain::domains::oauth::clients::api_key::ApiKeyRow;
    use ianua_domain::types::{ActorRef, Expiry, OrgUserId, UserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::oauth::{api_key_row, scopes};

    /// A fresh database, the store on it, and one tenant to keep keys in.
    async fn fixture() -> (TestDb, PgApiKeyStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgApiKeyStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    fn key(row: ApiKeyRow) -> ApiKey<ResolvedTenant> {
        ApiKey::reconstitute(row).unwrap()
    }

    fn anns(name: &str) -> ApiKey<ResolvedTenant> {
        key(api_key_row(name, ActorRef::User(UserId::new())))
    }

    fn expiring(name: &str, at_seconds: i64) -> ApiKey<ResolvedTenant> {
        key(ApiKeyRow {
            expires_at: Expiry::At(at(at_seconds)),
            ..api_key_row(name, ActorRef::User(UserId::new()))
        })
    }

    fn names(page: &Page<ApiKey<ResolvedTenant>>) -> Vec<&str> {
        page.items.iter().map(|key| key.name().as_str()).collect()
    }

    /// A key a member of the organization made is found by its id, with who
    /// made it and everything it was made with.
    #[tokio::test]
    async fn a_kept_key_is_found_by_its_id() {
        let (_db, store, tenant) = fixture().await;
        let made = key(ApiKeyRow {
            expires_at: Expiry::At(at(100)),
            ..api_key_row("ci", ActorRef::OrgUser(OrgUserId::new()))
        });

        store.insert(&tenant, &made).await.unwrap();

        let found = store.find_by_id(&tenant, made.id()).await.unwrap().unwrap();
        assert_eq!(found.name(), made.name());
        assert_eq!(found.key_prefix(), made.key_prefix());
        assert_eq!(found.key_hash(), made.key_hash());
        assert_eq!(found.scopes(), made.scopes());
        assert_eq!(
            found.created_by().audit_label(),
            made.created_by().audit_label()
        );
        assert_eq!(found.expires_at(), Expiry::At(at(100)));
        assert_eq!(found.created_at(), at(0));
    }

    /// Unknown API-key IDs return nothing, and another tenant cannot find or list
    /// the stored key.
    #[tokio::test]
    async fn a_key_is_found_only_by_its_tenant() {
        let (_db, store, acme) = fixture().await;
        let made = anns("ci");
        store.insert(&acme, &made).await.unwrap();
        let globex = tenant();
        let order = SortOrder::single(Sort::ascending(ApiKeySortField::Name));

        let unknown = store.find_by_id(&acme, &ApiKeyId::new()).await.unwrap();
        let theirs = store.find_by_id(&globex, made.id()).await.unwrap();
        let listed = store
            .list_all(
                &globex,
                &order,
                &PageRequest::first(Limit::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
        assert!(listed.items.is_empty());
    }

    /// Inserting another API key with the same tenant and prefix returns a
    /// conflict.
    #[tokio::test]
    async fn a_prefix_another_key_has_is_refused() {
        let (_db, store, tenant) = fixture().await;
        store.insert(&tenant, &anns("ci")).await.unwrap();

        let second = store.insert(&tenant, &anns("ci")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// The tenant's keys are read page by page by name, and by expiry with
    /// the keys that never expire last.
    #[tokio::test]
    async fn keys_are_listed_page_by_page() {
        let (_db, store, tenant) = fixture().await;
        for made in [anns("cid"), expiring("ann", 50), expiring("bob", 20)] {
            store.insert(&tenant, &made).await.unwrap();
        }
        let by_name = SortOrder::single(Sort::ascending(ApiKeySortField::Name));
        let by_expiry = SortOrder::single(Sort::ascending(ApiKeySortField::ExpiresAt));
        let two = PageRequest::first(Limit::new(2).unwrap());

        let page_one = store.list_all(&tenant, &by_name, &two).await.unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = store.list_all(&tenant, &by_name, &after).await.unwrap();
        let expiry_one = store.list_all(&tenant, &by_expiry, &two).await.unwrap();
        let after = PageRequest::new(expiry_one.next.clone(), Limit::new(2).unwrap());
        let expiry_two = store.list_all(&tenant, &by_expiry, &after).await.unwrap();

        assert_eq!(names(&page_one), ["ann", "bob"]);
        assert_eq!(names(&page_two), ["cid"]);
        assert!(!page_two.has_next());
        assert_eq!(names(&expiry_one), ["bob", "ann"]);
        assert_eq!(names(&expiry_two), ["cid"]);
    }

    /// An edit writes the new name and scopes, and a use writes when and
    /// from where, each leaving the other as stored.
    #[tokio::test]
    async fn an_edit_and_a_use_each_write_their_own_columns() {
        let (_db, store, tenant) = fixture().await;
        let made = anns("ci");
        store.insert(&tenant, &made).await.unwrap();
        let row = api_key_row("ci", made.created_by().clone());
        let edited = key(ApiKeyRow {
            id: *made.id(),
            name: Label::new("api_key_name", "deploy").unwrap(),
            scopes: scopes(&["idp:routing:view", "idp:users:view"]),
            ..api_key_row("ci", made.created_by().clone())
        });
        let used = key(ApiKeyRow {
            id: *made.id(),
            last_used_at: Some(at(9)),
            last_used_ip: Some(IpAddress::new("203.0.113.7").unwrap()),
            ..row
        });

        let renamed = store.update(&tenant, &edited).await.unwrap();
        let stamped = store.record_use(&tenant, &used, &[]).await.unwrap();

        assert!(renamed);
        assert_eq!(stamped, UseRecorded::Written);
        let found = store.find_by_id(&tenant, made.id()).await.unwrap().unwrap();
        assert_eq!(found.name().as_str(), "deploy");
        assert_eq!(found.scopes(), edited.scopes());
        assert_eq!(found.last_used_at(), Some(at(9)));
        assert_eq!(
            found.last_used_ip().map(IpAddress::as_str),
            Some("203.0.113.7")
        );
    }

    /// Two uses with Ann's key from Brazil both read it knowing only
    /// Germany. The first writes Brazil; the second finds the key's
    /// countries changed since it read them and writes nothing, so Brazil
    /// is noted once.
    #[tokio::test]
    async fn a_use_whose_countries_changed_since_it_read_them_writes_nothing() {
        let (_db, store, tenant) = fixture().await;
        let made = anns("ci");
        store.insert(&tenant, &made).await.unwrap();
        let germany = vec![CountryCode::new("DE").unwrap()];
        let then_brazil = vec![
            CountryCode::new("DE").unwrap(),
            CountryCode::new("BR").unwrap(),
        ];
        let used_in = |countries: &[CountryCode]| {
            key(ApiKeyRow {
                id: *made.id(),
                seen_countries: countries.to_vec(),
                ..api_key_row("ci", made.created_by().clone())
            })
        };
        store
            .record_use(&tenant, &used_in(&germany), &[])
            .await
            .unwrap();

        let first = store
            .record_use(&tenant, &used_in(&then_brazil), &germany)
            .await
            .unwrap();
        let second = store
            .record_use(&tenant, &used_in(&then_brazil), &germany)
            .await
            .unwrap();

        assert_eq!(first, UseRecorded::Written);
        assert_eq!(second, UseRecorded::Overtaken);
        let found = store.find_by_id(&tenant, made.id()).await.unwrap().unwrap();
        assert_eq!(found.seen_countries(), then_brazil.as_slice());
    }

    /// Updating or recording use of a deleted API key returns false and leaves
    /// the key absent.
    #[tokio::test]
    async fn a_revoked_key_stays_gone() {
        let (_db, store, tenant) = fixture().await;
        let made = anns("ci");
        store.insert(&tenant, &made).await.unwrap();

        store.delete(&tenant, made.id()).await.unwrap();
        let renamed = store.update(&tenant, &made).await.unwrap();
        let stamped = store.record_use(&tenant, &made, &[]).await.unwrap();

        assert!(!renamed);
        assert_eq!(stamped, UseRecorded::Gone);
        assert!(
            store
                .find_by_id(&tenant, made.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The sweep deletes every tenant's keys that expired by then, naming
    /// each with its tenant, and leaves the rest.
    #[tokio::test]
    async fn the_sweep_deletes_every_tenants_expired_keys() {
        let (db, store, acme) = fixture().await;
        let globex = tenant();
        let old = expiring("old", 10);
        let theirs = expiring("theirs", 20);
        store.insert(&acme, &old).await.unwrap();
        store.insert(&acme, &expiring("later", 500)).await.unwrap();
        store.insert(&acme, &anns("never")).await.unwrap();
        store.insert(&globex, &theirs).await.unwrap();
        let sweep = PgCrossTenantApiKeyStore::new(Arc::clone(&db.databases));

        let mut deleted = sweep.delete_expired(at(100)).await.unwrap();
        deleted.sort_by(|a, b| a.2.as_str().cmp(b.2.as_str()));

        let named: Vec<(TenantId, ApiKeyId, &str)> = deleted
            .iter()
            .map(|(tenant, id, name)| (*tenant, *id, name.as_str()))
            .collect();
        assert_eq!(
            named,
            [(*acme, *old.id(), "old"), (*globex, *theirs.id(), "theirs")]
        );
        assert!(store.find_by_id(&acme, old.id()).await.unwrap().is_none());
    }

    /// The expiry sweep removes keys from both the shared database and a
    /// registered tenant database, leaving the dedicated tenant's key absent.
    #[tokio::test]
    async fn the_sweep_reaches_a_tenant_with_its_own_database() {
        let (db, store, acme) = fixture().await;
        let own = TestDb::fresh().await;
        let apart = tenant();
        db.databases.register(*apart, own.as_dedicated());
        let shared_key = expiring("shared", 10);
        let apart_key = expiring("apart", 10);
        store.insert(&acme, &shared_key).await.unwrap();
        store.insert(&apart, &apart_key).await.unwrap();
        let sweep = PgCrossTenantApiKeyStore::new(Arc::clone(&db.databases));

        let deleted = sweep.delete_expired(at(100)).await.unwrap();

        assert_eq!(deleted.len(), 2);
        assert!(
            deleted
                .iter()
                .any(|(tenant, id, _)| tenant == &*apart && id == apart_key.id())
        );
        assert!(
            store
                .find_by_id(&apart, apart_key.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Reading an API key whose stored scope names no permission returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_key_is_refused() {
        let (db, store, tenant) = fixture().await;
        let made = anns("ci");
        store.insert(&tenant, &made).await.unwrap();
        db.tamper("UPDATE api_keys SET scopes = ARRAY['projects:read']")
            .await;

        let read = store.find_by_id(&tenant, made.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
