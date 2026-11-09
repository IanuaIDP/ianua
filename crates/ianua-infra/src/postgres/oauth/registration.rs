//! The initial access tokens a tenant hands out so apps may register
//! themselves as clients, each row under row-level security.
//!
//! Only a token's hash is kept. Spending a use is one `UPDATE` that holds
//! only while the stored token has exactly one use more and is unrevoked,
//! so of two registrations racing for the last use only one is admitted;
//! a save never writes the uses left, so it cannot give one back.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::InitialAccessTokenStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::clients::registration::InitialAccessToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{InitialAccessTokenId, TokenHash};

use self::record::{InitialAccessTokenColumns, InitialAccessTokenRecord, uses_column};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a token's hash to one token of a tenant.
const TOKEN_KEY: &str = "oauth_initial_access_tokens_token_key";

/// The Postgres store of initial access tokens.
pub struct PgInitialAccessTokenStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgInitialAccessTokenStore {}

impl PgInitialAccessTokenStore {
    /// A store keeping initial access tokens in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl InitialAccessTokenStore for PgInitialAccessTokenStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &InitialAccessTokenId,
    ) -> Result<Option<InitialAccessToken<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    InitialAccessTokenRecord,
                    "queries/oauth_initial_access_tokens/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(InitialAccessTokenRecord::into_token).transpose()
    }

    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<InitialAccessToken<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    InitialAccessTokenRecord,
                    "queries/oauth_initial_access_tokens/by_hash.sql",
                    tenant_id.as_uuid(),
                    token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(InitialAccessTokenRecord::into_token).transpose()
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<InitialAccessToken<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    InitialAccessTokenRecord,
                    "queries/oauth_initial_access_tokens/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(InitialAccessTokenRecord::into_token)
            .collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &InitialAccessToken<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = InitialAccessTokenColumns::of(token)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/oauth_initial_access_tokens/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.token_hash,
                    columns.uses_left,
                    columns.created_at,
                    columns.expires_at,
                    columns.revoked_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, TOKEN_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-initial-access-token-of-the",
                "another initial access token of the tenant has this hash"
            ))),
        }
    }

    async fn spend_use(
        &self,
        tenant_id: &ScopedTenant,
        token: &InitialAccessToken<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let uses_left = uses_column(token)?;
        let spent = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_initial_access_tokens/spend_use.sql",
                    tenant_id.as_uuid(),
                    token.id().as_uuid(),
                    uses_left
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(spent.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::registration::InitialAccessTokenRow;
    use ianua_domain::types::Revocation;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::oauth::initial_access_token_row;

    /// A fresh database, the store on it, and one tenant to keep tokens in.
    async fn fixture() -> (TestDb, PgInitialAccessTokenStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgInitialAccessTokenStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    fn token(row: InitialAccessTokenRow) -> InitialAccessToken<ResolvedTenant> {
        InitialAccessToken::reconstitute(row).unwrap()
    }

    fn with_uses(row: InitialAccessTokenRow, uses_left: u32) -> InitialAccessToken<ResolvedTenant> {
        token(InitialAccessTokenRow { uses_left, ..row })
    }

    /// A saved token is found by its id and by its hash, as it was saved.
    #[tokio::test]
    async fn a_saved_token_is_found_by_id_and_by_hash() {
        let (_db, store, tenant) = fixture().await;
        let mcp = token(initial_access_token_row("mcp"));

        store.save(&tenant, &mcp).await.unwrap();

        let by_id = store.find_by_id(&tenant, mcp.id()).await.unwrap().unwrap();
        let by_hash = store
            .find_by_hash(&tenant, mcp.token_hash())
            .await
            .unwrap()
            .unwrap();
        for found in [&by_id, &by_hash] {
            assert_eq!(found.id(), mcp.id());
            assert_eq!(found.name(), mcp.name());
            assert_eq!(found.uses_left(), mcp.uses_left());
            assert_eq!(found.expires_at(), mcp.expires_at());
            assert_eq!(found.revocation(), Revocation::InForce);
        }
    }

    /// An id or hash nobody has finds nothing, and another tenant finds
    /// none of this tenant's tokens.
    #[tokio::test]
    async fn a_token_is_found_only_by_its_tenant() {
        let (_db, store, acme) = fixture().await;
        let mcp = token(initial_access_token_row("mcp"));
        store.save(&acme, &mcp).await.unwrap();
        let globex = tenant();

        let unknown = store
            .find_by_id(&acme, &InitialAccessTokenId::new())
            .await
            .unwrap();
        let theirs = store.find_by_hash(&globex, mcp.token_hash()).await.unwrap();
        let listed = store.list_all(&globex).await.unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
        assert!(listed.is_empty());
    }

    /// Saving a second initial access token with the same tenant and hash
    /// returns a conflict.
    #[tokio::test]
    async fn a_hash_another_token_has_is_refused() {
        let (_db, store, tenant) = fixture().await;
        store
            .save(&tenant, &token(initial_access_token_row("mcp")))
            .await
            .unwrap();

        let second = store
            .save(&tenant, &token(initial_access_token_row("mcp")))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// The tenant's tokens are listed newest first, revoked ones too.
    #[tokio::test]
    async fn tokens_are_listed_newest_first() {
        let (_db, store, tenant) = fixture().await;
        let old = token(initial_access_token_row("old"));
        let new = token(InitialAccessTokenRow {
            created_at: at(10),
            expires_at: at(100),
            revocation: Revocation::Revoked { at: at(20) },
            ..initial_access_token_row("new")
        });
        store.save(&tenant, &old).await.unwrap();
        store.save(&tenant, &new).await.unwrap();

        let listed = store.list_all(&tenant).await.unwrap();

        let names: Vec<&str> = listed.iter().map(|token| token.name().as_str()).collect();
        assert_eq!(names, ["new", "old"]);
    }

    /// Revoking a token is kept, and a later save of an unrevoked copy
    /// does not bring it back, nor give back a use.
    #[tokio::test]
    async fn a_revocation_is_never_undone() {
        let (_db, store, tenant) = fixture().await;
        let kept = with_uses(initial_access_token_row("mcp"), 5);
        store.save(&tenant, &kept).await.unwrap();
        let revoked = token(InitialAccessTokenRow {
            revocation: Revocation::Revoked { at: at(5) },
            ..row_of(&kept)
        });
        store.save(&tenant, &revoked).await.unwrap();
        let stale = token(InitialAccessTokenRow {
            uses_left: 9,
            ..row_of(&kept)
        });

        store.save(&tenant, &stale).await.unwrap();

        let found = store.find_by_id(&tenant, kept.id()).await.unwrap().unwrap();
        assert_eq!(found.revocation(), Revocation::Revoked { at: at(5) });
        assert_eq!(found.uses_left(), 5);
    }

    /// The last token use can be spent once; a second spend returns false and
    /// the stored token has no uses left.
    #[tokio::test]
    async fn the_last_use_is_spent_once() {
        let (_db, store, tenant) = fixture().await;
        let one_left = with_uses(initial_access_token_row("mcp"), 1);
        store.save(&tenant, &one_left).await.unwrap();
        let spent = token(InitialAccessTokenRow {
            uses_left: 0,
            ..row_of(&one_left)
        });

        let first = store.spend_use(&tenant, &spent).await.unwrap();
        let second = store.spend_use(&tenant, &spent).await.unwrap();

        assert!(first);
        assert!(!second);
        let found = store
            .find_by_id(&tenant, one_left.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.uses_left(), 0);
    }

    /// An unrevoked copy cannot spend a use of a token stored as revoked.
    #[tokio::test]
    async fn a_revoked_token_spends_nothing() {
        let (_db, store, tenant) = fixture().await;
        let revoked = token(InitialAccessTokenRow {
            uses_left: 3,
            revocation: Revocation::Revoked { at: at(5) },
            ..initial_access_token_row("mcp")
        });
        store.save(&tenant, &revoked).await.unwrap();
        let spent = token(InitialAccessTokenRow {
            uses_left: 2,
            revocation: Revocation::InForce,
            ..row_of(&revoked)
        });

        let admitted = store.spend_use(&tenant, &spent).await.unwrap();

        assert!(!admitted);
    }

    /// Reading a stored initial access token with an empty name returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_token_is_refused() {
        let (db, store, tenant) = fixture().await;
        let mcp = token(initial_access_token_row("mcp"));
        store.save(&tenant, &mcp).await.unwrap();
        db.tamper("UPDATE oauth_initial_access_tokens SET name = ''")
            .await;

        let read = store.find_by_id(&tenant, mcp.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// The row a token was read from, to change one part of it.
    fn row_of(token: &InitialAccessToken<ResolvedTenant>) -> InitialAccessTokenRow {
        InitialAccessTokenRow {
            id: *token.id(),
            name: token.name().clone(),
            token_hash: token.token_hash().clone(),
            uses_left: token.uses_left(),
            created_at: token.created_at(),
            expires_at: token.expires_at(),
            revocation: token.revocation(),
        }
    }
}
