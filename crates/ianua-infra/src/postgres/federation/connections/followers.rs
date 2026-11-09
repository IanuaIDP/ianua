//! The SAML connections, across every tenant, that follow the address
//! their provider publishes its metadata at.
//!
//! The tenants in the platform database are read in one query, and each
//! tenant with a database of its own in another, all at once. Each read
//! seeks past the cursor in the one order, by tenant then connection, so
//! the pages read from every database merge into one page of that order.

mod record;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::listing::{Keyset, Page, PageRequest, SortOrder};
use ianua_app::ports::federation::{
    MetadataFollower, MetadataFollowerSortField, MetadataFollowers,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use uuid::Uuid;

use self::record::FollowerRecord;
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long the read of every database may take together.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

type FollowerOrder = SortOrder<MetadataFollowerSortField>;

/// The Postgres finder of connections following a metadata address.
pub struct PgMetadataFollowers {
    databases: Arc<Databases>,
}

impl PgMetadataFollowers {
    /// A finder reading connections from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The followers of the page `keyset` asks for in the database of
    /// `scope`: every tenant of the platform database, or one tenant of its
    /// own.
    async fn read(
        &self,
        scope: RowScope,
        keyset: &Keyset<'_, FollowerOrder>,
    ) -> Result<Vec<FollowerRecord>, DomainError> {
        let listed = PageQuery::ids("id", "federation_connections").keep("follows_metadata");
        let listed = match scope {
            RowScope::Tenant(tenant) => listed.filter("tenant_id = ?", *tenant.as_uuid()),
            RowScope::Platform | RowScope::Unscoped => listed,
        };
        scoped(&self.databases, scope, async |connection| {
            let ids = listed.fetch(keyset, &mut *connection).await?;
            sqlx::query_file_as!(
                FollowerRecord,
                "queries/federation_connections/followers_by_ids.sql",
                &ids
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// The followers of the page `keyset` asks for in every database, in
    /// its order.
    async fn read_everywhere(
        &self,
        keyset: &Keyset<'_, FollowerOrder>,
    ) -> Result<Vec<MetadataFollower>, DomainError> {
        let own: Vec<TenantId> = self.databases.with_own_database();
        let (shared, own) = futures_util::try_join!(
            self.read(RowScope::Platform, keyset),
            try_join_all(
                own.into_iter()
                    .map(|tenant| self.read(RowScope::Tenant(tenant), keyset))
            )
        )?;
        let mut followers: Vec<MetadataFollower> = shared
            .into_iter()
            .chain(own.into_iter().flatten())
            .map(FollowerRecord::into_follower)
            .collect();
        followers.sort_by_key(order_of);
        followers.truncate(usize::try_from(keyset.fetch()).unwrap_or(usize::MAX));
        Ok(followers)
    }
}

/// Where `follower` sorts: by tenant, then by connection.
fn order_of(follower: &MetadataFollower) -> (Uuid, Uuid) {
    (
        *follower.tenant_id.as_uuid(),
        *follower.connection_id.as_uuid(),
    )
}

impl SortColumns for MetadataFollowerSortField {
    fn column(self) -> &'static str {
        match self {
            Self::Tenant => "tenant_id",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl MetadataFollowers for PgMetadataFollowers {
    async fn list_following(
        &self,
        page: &PageRequest,
    ) -> Result<Page<MetadataFollower>, DomainError> {
        let order = FollowerOrder::default();
        let keyset = page.keyset(&order)?;
        let followers = tokio::time::timeout(ANSWER_WITHIN, self.read_everywhere(&keyset))
            .await
            .map_err(DomainError::infra)??;
        Ok(keyset.seal(followers))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::federation::ConnectionStore;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::federation::connection::{ConnectionConfig, FederatedIdpConnection};
    use ianua_domain::types::ConnectionId;

    use super::*;
    use crate::postgres::federation::PgConnectionStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::federation::{
        connection_row, oidc_config, saml_config, saml_config_following,
    };

    /// A fresh database, and the finder on it.
    async fn fixture() -> (TestDb, PgMetadataFollowers) {
        let db = TestDb::fresh().await;
        let followers = PgMetadataFollowers::new(Arc::clone(&db.databases));
        (db, followers)
    }

    /// Saves a connection reached through `config` in `tenant`.
    async fn a_connection(
        db: &TestDb,
        tenant: &ScopedTenant,
        config: ConnectionConfig,
    ) -> ConnectionId {
        let connection =
            FederatedIdpConnection::reconstitute(connection_row("Okta", config)).unwrap();
        PgConnectionStore::new(Arc::clone(&db.databases))
            .save(tenant, &connection)
            .await
            .unwrap();
        *connection.id()
    }

    fn following() -> ConnectionConfig {
        saml_config_following("https://acme.okta.com/app/metadata")
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    /// Acme and Globex each have a connection following its provider's
    /// metadata, beside ones typed in by hand and over OIDC: only the two
    /// following are found, by tenant then connection.
    #[tokio::test]
    async fn only_connections_following_an_address_are_found_in_every_tenant() {
        let (db, followers) = fixture().await;
        let (acme, globex) = (tenant(), tenant());
        let acme_follows = a_connection(&db, &acme, following()).await;
        let globex_follows = a_connection(&db, &globex, following()).await;
        a_connection(&db, &acme, saml_config()).await;
        a_connection(&db, &globex, oidc_config()).await;

        let page = followers.list_following(&first(10)).await.unwrap();

        let mut expected = vec![
            MetadataFollower {
                tenant_id: *acme,
                connection_id: acme_follows,
            },
            MetadataFollower {
                tenant_id: *globex,
                connection_id: globex_follows,
            },
        ];
        expected.sort_by_key(order_of);
        assert_eq!(page.items, expected);
        assert!(!page.has_next());
    }

    /// Three followers read two at a time: the second page follows the
    /// first, and nothing follows the second.
    #[tokio::test]
    async fn followers_are_read_page_by_page() {
        let (db, followers) = fixture().await;
        for _ in 0..3 {
            a_connection(&db, &tenant(), following()).await;
        }

        let page_one = followers.list_following(&first(2)).await.unwrap();
        let page_two = followers
            .list_following(&PageRequest::new(
                page_one.next.clone(),
                Limit::new(2).unwrap(),
            ))
            .await
            .unwrap();

        assert_eq!(page_one.items.len(), 2);
        assert_eq!(page_two.items.len(), 1);
        assert!(!page_two.has_next());
        assert!(order_of(&page_one.items[1]) < order_of(&page_two.items[0]));
    }

    /// With no connection following an address, the page is empty.
    #[tokio::test]
    async fn nothing_followed_finds_nothing() {
        let (db, followers) = fixture().await;
        a_connection(&db, &tenant(), saml_config()).await;

        let page = followers.list_following(&first(10)).await.unwrap();

        assert!(page.items.is_empty());
    }
}
