//! The authorization requests a tenant's clients push before sending the
//! browser on (RFC 9126), each row under row-level security.
//!
//! A request lives sixty seconds, so the tenant's expired ones are dropped
//! each time another is pushed, and the table holds about a minute of them.
//! Redeeming is one `UPDATE` that holds only while the request is unused,
//! so of two browsers with one `request_uri` only one gets a code.

mod parameters;
mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::PushedRequestStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::grants::pushed_request::PushedRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PushedRequestId;

use self::record::{PushedRequestRecord, parameters_column};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of pushed authorization requests.
pub struct PgPushedRequestStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgPushedRequestStore {}

impl PgPushedRequestStore {
    /// A store keeping pushed requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl PushedRequestStore for PgPushedRequestStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &PushedRequestId,
    ) -> Result<Option<PushedRequest<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PushedRequestRecord,
                    "queries/oauth_pushed_requests/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(PushedRequestRecord::into_request).transpose()
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        request: &PushedRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let parameters = parameters_column(request)?;
        let now = clock::now();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_pushed_requests/clear_expired.sql",
                    tenant_id.as_uuid(),
                    now
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query_file!(
                    "queries/oauth_pushed_requests/insert.sql",
                    request.id().as_uuid(),
                    tenant_id.as_uuid(),
                    request.client_id().as_uuid(),
                    parameters,
                    request.created_at(),
                    request.expires_at(),
                    request.usage().used_at(),
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn redeem(
        &self,
        tenant_id: &ScopedTenant,
        request: &PushedRequest<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let Some(used_at) = request.usage().used_at() else {
            return Err(DomainError::invalid(message!(
                "infra-only-a-request-just-used-is",
                "only a request just used is redeemed"
            )));
        };
        let redeemed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_pushed_requests/redeem.sql",
                    tenant_id.as_uuid(),
                    request.id().as_uuid(),
                    used_at
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(redeemed.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::grants::pushed_request::PushedRequestRow;
    use ianua_domain::types::Usage;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::oauth::{a_client, oauth_client_row, pushed_row};

    struct Fixture {
        db: TestDb,
        store: PgPushedRequestStore,
        tenant: ScopedTenant,
        client: OAuthClient<ResolvedTenant>,
    }

    /// A fresh database, the store on it, and a tenant with a client to
    /// push requests.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let client = a_client(
            &db,
            &tenant,
            oauth_client_row("portal", &[GrantType::AuthorizationCode]),
        )
        .await;
        Fixture {
            store: PgPushedRequestStore::new(Arc::clone(&db.databases)),
            db,
            tenant,
            client,
        }
    }

    fn request(row: PushedRequestRow) -> PushedRequest<ResolvedTenant> {
        PushedRequest::reconstitute(row).unwrap()
    }

    fn used(row: PushedRequestRow) -> PushedRequest<ResolvedTenant> {
        request(PushedRequestRow {
            usage: Usage::Used { at: at(5) },
            ..row
        })
    }

    /// A pushed request is found by its id with what was pushed.
    #[tokio::test]
    async fn a_pushed_request_is_found_by_its_id() {
        let db = fixture().await;
        let pushed = request(pushed_row(&db.client));

        db.store.insert(&db.tenant, &pushed).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, pushed.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.client_id(), db.client.id());
        assert_eq!(found.parameters(), pushed.parameters());
        assert_eq!(found.expires_at(), pushed.expires_at());
        assert_eq!(found.usage(), Usage::Unused);
    }

    /// Looking up an unknown pushed-request ID or another tenant's request
    /// returns nothing.
    #[tokio::test]
    async fn a_request_is_found_only_by_its_tenant() {
        let db = fixture().await;
        let pushed = request(pushed_row(&db.client));
        db.store.insert(&db.tenant, &pushed).await.unwrap();

        let unknown = db
            .store
            .find_by_id(&db.tenant, &PushedRequestId::new())
            .await
            .unwrap();
        let theirs = db.store.find_by_id(&tenant(), pushed.id()).await.unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
    }

    /// Redeeming a pushed request succeeds once; a second attempt returns false
    /// and the stored request retains its use time.
    #[tokio::test]
    async fn a_request_is_redeemed_once() {
        let db = fixture().await;
        let row = pushed_row(&db.client);
        let id = row.id;
        db.store
            .insert(&db.tenant, &request(pushed_row_with(id, &db.client)))
            .await
            .unwrap();
        let spent = used(row);

        let first = db.store.redeem(&db.tenant, &spent).await.unwrap();
        let second = db.store.redeem(&db.tenant, &spent).await.unwrap();

        assert!(first);
        assert!(!second);
        let found = db.store.find_by_id(&db.tenant, &id).await.unwrap().unwrap();
        assert_eq!(found.usage(), Usage::Used { at: at(5) });
    }

    /// A request whose minute is over is dropped once another is pushed.
    #[tokio::test]
    async fn an_expired_request_is_dropped_when_another_is_pushed() {
        let db = fixture().await;
        let old = request(pushed_row(&db.client));
        db.store.insert(&db.tenant, &old).await.unwrap();
        db.db
            .tamper(
                "UPDATE oauth_pushed_requests SET created_at = now() - interval '2 minutes', \
                 expires_at = now() - interval '1 minute'",
            )
            .await;

        db.store
            .insert(&db.tenant, &request(pushed_row(&db.client)))
            .await
            .unwrap();

        let found = db.store.find_by_id(&db.tenant, old.id()).await.unwrap();
        assert!(found.is_none());
    }

    /// Reading a stored pushed request with empty parameters returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_request_is_refused() {
        let db = fixture().await;
        let pushed = request(pushed_row(&db.client));
        db.store.insert(&db.tenant, &pushed).await.unwrap();
        db.db
            .tamper("UPDATE oauth_pushed_requests SET parameters = '{\"v\": 1, \"value\": {}}'")
            .await;

        let read = db.store.find_by_id(&db.tenant, pushed.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// The row of a request pushed by `client` under `id`.
    fn pushed_row_with(
        id: PushedRequestId,
        client: &OAuthClient<ResolvedTenant>,
    ) -> PushedRequestRow {
        PushedRequestRow {
            id,
            ..pushed_row(client)
        }
    }
}
