//! A tenant's OAuth clients, each table row under row-level security.
//!
//! Only the hashes of a client's secrets are kept, and of a self-registered
//! client's registration access token. A list first reads the ids of its
//! page, filtered and ordered in SQL, then reads those rows through the one
//! by-ids query, as every read of a client by id does.

mod credential;
mod record;
mod settings;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::{OAuthClientSortField, OAuthClientStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ClientId, OAuthClientId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{OAuthClientColumns, OAuthClientRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a public client id to one client of a tenant.
const CLIENT_ID_KEY: &str = "oauth_clients_client_id_key";

/// Reports a public client-ID collision using the client store's conflict vocabulary.
fn ensure_client_id_available(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-another-client-of-the-tenant-already",
            "another client of the tenant already has this client id"
        ))),
    }
}

/// The Postgres OAuth client store.
pub struct PgOAuthClientStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgOAuthClientStore {}

impl PgOAuthClientStore {
    /// A store keeping OAuth clients in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The records of the clients of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<OAuthClientRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        OAuthClientRecord,
        "queries/oauth_clients/by_ids.sql",
        tenant,
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt_all(
    records: Vec<OAuthClientRecord>,
) -> Result<Vec<OAuthClient<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(OAuthClientRecord::into_client)
        .collect()
}

/// The ids of a page of the clients of `tenant`, of `status` when given.
fn listed(tenant: Uuid, status: Option<OAuthClientStatus>) -> PageQuery<'static> {
    let query = PageQuery::ids("id", "oauth_clients").filter("tenant_id = ?", tenant);
    match status {
        None => query,
        Some(status) => query.filter("status = ?", status.word()),
    }
}

impl SortColumns for OAuthClientSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Name => "name",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl OAuthClientStore for PgOAuthClientStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &OAuthClientId,
    ) -> Result<Option<OAuthClient<ResolvedTenant>>, DomainError> {
        Ok(self
            .find_by_ids(tenant_id, std::slice::from_ref(id))
            .await?
            .into_iter()
            .next())
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[OAuthClientId],
    ) -> Result<Vec<OAuthClient<ResolvedTenant>>, DomainError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        rebuilt_all(records)
    }

    async fn find_by_client_id_value(
        &self,
        tenant_id: &ScopedTenant,
        client_id: &ClientId,
    ) -> Result<Option<OAuthClient<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    OAuthClientRecord,
                    "queries/oauth_clients/by_client_id.sql",
                    tenant_id.as_uuid(),
                    client_id.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(OAuthClientRecord::into_client).transpose()
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<OAuthClientStatus>,
        sort: &SortOrder<OAuthClientSortField>,
        page: &PageRequest,
    ) -> Result<Page<OAuthClient<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let tenant = *tenant_id.as_uuid();
        let query = listed(tenant, status);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = query.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, &tenant, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        client: &OAuthClient<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = OAuthClientColumns::of(client)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/oauth_clients/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.client_id_value,
                    columns.credential,
                    columns.name,
                    columns.redirect_uris.as_slice(),
                    columns.post_logout_redirect_uris.as_slice(),
                    columns.grant_types.as_slice(),
                    columns.scopes.as_slice(),
                    columns.settings,
                    columns.registration_token_hash,
                    columns.admitted_with_id,
                    columns.status,
                    columns.created_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, CLIENT_ID_KEY)
            },
        )
        .await?;
        ensure_client_id_available(written)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::oauth::InitialAccessTokenStore;
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClientRow};
    use ianua_domain::domains::oauth::clients::registration::{
        ClientManagement, InitialAccessToken,
    };
    use ianua_domain::types::{Label, TokenHash};

    use super::*;
    use crate::postgres::oauth::PgInitialAccessTokenStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::oauth::{initial_access_token_row, oauth_client_row};

    const CODE: &[GrantType] = &[GrantType::AuthorizationCode, GrantType::RefreshToken];

    /// A fresh database, the store on it, and one tenant to keep clients in.
    async fn fixture() -> (TestDb, PgOAuthClientStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgOAuthClientStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    fn client(row: OAuthClientRow) -> OAuthClient<ResolvedTenant> {
        OAuthClient::reconstitute(row).unwrap()
    }

    fn named(name: &str) -> OAuthClient<ResolvedTenant> {
        client(oauth_client_row(name, CODE))
    }

    async fn save_all(
        store: &PgOAuthClientStore,
        tenant: &ScopedTenant,
        clients: &[&OAuthClient<ResolvedTenant>],
    ) {
        for client in clients {
            store.save(tenant, client).await.unwrap();
        }
    }

    fn by(field: OAuthClientSortField) -> SortOrder<OAuthClientSortField> {
        SortOrder::single(Sort::ascending(field))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn names(page: &Page<OAuthClient<ResolvedTenant>>) -> Vec<&str> {
        page.items
            .iter()
            .map(|client| client.name().as_str())
            .collect()
    }

    /// The portal's client is found by its id and by its public client id,
    /// with everything it was saved with.
    #[tokio::test]
    async fn a_saved_client_is_found_by_id_and_by_client_id() {
        let (_db, store, tenant) = fixture().await;
        let portal = named("portal");

        store.save(&tenant, &portal).await.unwrap();

        let by_id = store
            .find_by_id(&tenant, portal.id())
            .await
            .unwrap()
            .unwrap();
        let by_value = store
            .find_by_client_id_value(&tenant, portal.client_id_value())
            .await
            .unwrap()
            .unwrap();
        for found in [&by_id, &by_value] {
            assert_eq!(found.id(), portal.id());
            assert_eq!(found.credential(), portal.credential());
            assert_eq!(found.redirect_uris(), portal.redirect_uris());
            assert_eq!(
                found.post_logout_redirect_uris(),
                portal.post_logout_redirect_uris()
            );
            assert_eq!(found.grant_types(), portal.grant_types());
            assert_eq!(found.scopes(), portal.scopes());
            assert_eq!(found.settings(), portal.settings());
            assert_eq!(found.management(), &ClientManagement::ByAdmins);
            assert_eq!(found.created_at(), at(0));
        }
    }

    /// An id or client id nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_client_is_not_found() {
        let (_db, store, tenant) = fixture().await;

        let by_id = store
            .find_by_id(&tenant, &OAuthClientId::new())
            .await
            .unwrap();
        let by_value = store
            .find_by_client_id_value(&tenant, &ClientId::new("client_nobody").unwrap())
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(by_value.is_none());
    }

    /// A batch returns only the requested tenant's clients, once each,
    /// omitting unknown ids and accepting an empty request.
    #[tokio::test]
    async fn client_batches_keep_the_tenant_boundary() {
        let (_db, store, acme) = fixture().await;
        let portal = named("portal");
        let second = named("second");
        let foreign = named("foreign");
        let globex = tenant();
        save_all(&store, &acme, &[&portal, &second]).await;
        store.save(&globex, &foreign).await.unwrap();
        let ids = [
            *second.id(),
            *portal.id(),
            *portal.id(),
            *foreign.id(),
            OAuthClientId::new(),
        ];

        let found = store.find_by_ids(&acme, &ids).await.unwrap();

        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|client| client.id() == portal.id()));
        assert!(found.iter().any(|client| client.id() == second.id()));
        assert!(store.find_by_ids(&acme, &[]).await.unwrap().is_empty());
    }

    /// Saving another client with the same tenant and public client ID returns a
    /// conflict.
    #[tokio::test]
    async fn a_client_id_another_client_has_is_refused() {
        let (_db, store, tenant) = fixture().await;
        let portal = named("portal");
        store.save(&tenant, &portal).await.unwrap();
        let copy = client(OAuthClientRow {
            client_id_value: portal.client_id_value().clone(),
            ..oauth_client_row("copy", CODE)
        });

        let second = store.save(&tenant, &copy).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Another tenant finds no client by its internal ID, public client ID or
    /// client listing.
    #[tokio::test]
    async fn another_tenants_clients_are_invisible() {
        let (_db, store, acme) = fixture().await;
        let portal = named("portal");
        store.save(&acme, &portal).await.unwrap();
        let globex = tenant();

        let by_id = store.find_by_id(&globex, portal.id()).await.unwrap();
        let by_value = store
            .find_by_client_id_value(&globex, portal.client_id_value())
            .await
            .unwrap();
        let listed = store
            .list_all(&globex, None, &by(OAuthClientSortField::Name), &first(10))
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(by_value.is_none());
        assert!(listed.items.is_empty());
    }

    /// The tenant's clients are read page by page by name: each page follows
    /// the last, and the last says nothing follows.
    #[tokio::test]
    async fn clients_are_listed_page_by_page() {
        let (_db, store, tenant) = fixture().await;
        save_all(
            &store,
            &tenant,
            &[&named("cid"), &named("ann"), &named("bob")],
        )
        .await;
        let order = by(OAuthClientSortField::Name);

        let page_one = store
            .list_all(&tenant, None, &order, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = store.list_all(&tenant, None, &order, &after).await.unwrap();

        assert_eq!(names(&page_one), ["ann", "bob"]);
        assert_eq!(names(&page_two), ["cid"]);
        assert!(!page_two.has_next());
    }

    /// A list narrows to one status, and sorted by status pages by the word
    /// it is stored as.
    #[tokio::test]
    async fn clients_are_listed_by_status() {
        let (_db, store, tenant) = fixture().await;
        let revoked = client(OAuthClientRow {
            status: OAuthClientStatus::Revoked,
            ..oauth_client_row("old", CODE)
        });
        save_all(&store, &tenant, &[&named("new"), &revoked]).await;
        let order = by(OAuthClientSortField::Status);

        let only_revoked = store
            .list_all(
                &tenant,
                Some(OAuthClientStatus::Revoked),
                &order,
                &first(10),
            )
            .await
            .unwrap();
        let page_one = store
            .list_all(&tenant, None, &order, &first(1))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(1).unwrap());
        let page_two = store.list_all(&tenant, None, &order, &after).await.unwrap();

        assert_eq!(names(&only_revoked), ["old"]);
        assert_eq!(names(&page_one), ["new"]);
        assert_eq!(names(&page_two), ["old"]);
    }

    /// An app that registered itself with an initial access token reads back
    /// as managing itself, with the token it was admitted with.
    #[tokio::test]
    async fn a_self_registered_client_keeps_who_manages_it() {
        let (db, store, tenant) = fixture().await;
        let token = InitialAccessToken::reconstitute(initial_access_token_row("mcp")).unwrap();
        PgInitialAccessTokenStore::new(Arc::clone(&db.databases))
            .save(&tenant, &token)
            .await
            .unwrap();
        let management = ClientManagement::ByItself {
            registration_token: TokenHash::from_stored("hash:registration".to_owned()),
            admitted_with: *token.id(),
        };
        let app = client(OAuthClientRow {
            management: management.clone(),
            ..oauth_client_row("mcp app", CODE)
        });

        store.save(&tenant, &app).await.unwrap();

        let found = store.find_by_id(&tenant, app.id()).await.unwrap().unwrap();
        assert_eq!(found.management(), &management);
    }

    /// The client is renamed and revoked: saving again keeps the new values
    /// and the time it was created.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let (_db, store, tenant) = fixture().await;
        let portal = named("portal");
        store.save(&tenant, &portal).await.unwrap();
        let changed = client(OAuthClientRow {
            id: *portal.id(),
            client_id_value: portal.client_id_value().clone(),
            name: Label::new("name", "old portal").unwrap(),
            status: OAuthClientStatus::Revoked,
            created_at: at(9),
            ..oauth_client_row("portal", CODE)
        });

        store.save(&tenant, &changed).await.unwrap();

        let found = store
            .find_by_id(&tenant, portal.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "old portal");
        assert_eq!(found.status(), OAuthClientStatus::Revoked);
        assert_eq!(found.created_at(), at(0));
    }

    /// Reading a code-flow client whose stored redirect list is empty returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_client_is_refused() {
        let (db, store, tenant) = fixture().await;
        let portal = named("portal");
        store.save(&tenant, &portal).await.unwrap();
        db.tamper("UPDATE oauth_clients SET redirect_uris = '{}'")
            .await;

        let read = store.find_by_id(&tenant, portal.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
