//! The client assertions each client of a tenant already used (RFC 7523
//! 3), kept until each would have expired anyway, under row-level
//! security.
//!
//! A use is one insert that does nothing for a `jti` the client used
//! before, so of two token requests racing one copied assertion exactly one
//! is told it was the first. The tenant's expired assertions are forgotten
//! as the next one is spent. The ledger reads no row back, so it has no
//! mapping of its own.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::AssertionReplayGuard;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OAuthClientId, TokenId};
use time::OffsetDateTime;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres ledger of client assertions already used.
pub struct PgAssertionReplayGuard {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAssertionReplayGuard {}

impl PgAssertionReplayGuard {
    /// A ledger keeping used assertions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AssertionReplayGuard for PgAssertionReplayGuard {
    async fn first_use(
        &self,
        tenant_id: &ScopedTenant,
        client: &OAuthClientId,
        jti: &TokenId,
        until: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let now = clock::now();
        let spent = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_client_assertions/clear_expired.sql",
                    tenant_id.as_uuid(),
                    now
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query_file_scalar!(
                    "queries/oauth_client_assertions/spend.sql",
                    tenant_id.as_uuid(),
                    client.as_uuid(),
                    jti.as_str(),
                    until
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        Ok(spent.is_some())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use time::Duration;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::oauth::{a_client, oauth_client_row};

    /// A fresh database, the ledger on it, and a tenant with a client that
    /// signs its own assertions.
    async fn fixture() -> (TestDb, PgAssertionReplayGuard, ScopedTenant, OAuthClientId) {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let client = a_client(
            &db,
            &tenant,
            oauth_client_row("billing", &[GrantType::ClientCredentials]),
        )
        .await;
        let guard = PgAssertionReplayGuard::new(Arc::clone(&db.databases));
        (db, guard, tenant, *client.id())
    }

    fn jti(value: &str) -> TokenId {
        TokenId::new(value).unwrap()
    }

    fn in_five_minutes() -> OffsetDateTime {
        clock::now().saturating_add(Duration::minutes(5))
    }

    /// The first time a client uses an assertion, this call records it.
    #[tokio::test]
    async fn a_fresh_assertion_is_a_first_use() {
        let (_db, guard, tenant, client) = fixture().await;

        let first = guard
            .first_use(&tenant, &client, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        assert!(first);
    }

    /// Reusing an assertion ID for the same client and tenant returns false.
    #[tokio::test]
    async fn a_replayed_assertion_is_refused() {
        let (_db, guard, tenant, client) = fixture().await;
        guard
            .first_use(&tenant, &client, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        let again = guard
            .first_use(&tenant, &client, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        assert!(!again);
    }

    /// The same `jti` from another client, or in another tenant, is that
    /// one's own first use.
    #[tokio::test]
    async fn another_client_or_tenant_uses_its_own_ids() {
        let (db, guard, acme, client) = fixture().await;
        let other = a_client(
            &db,
            &acme,
            oauth_client_row("reports", &[GrantType::ClientCredentials]),
        )
        .await;
        let globex = tenant();
        let theirs = a_client(
            &db,
            &globex,
            oauth_client_row("billing", &[GrantType::ClientCredentials]),
        )
        .await;
        guard
            .first_use(&acme, &client, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        let by_other = guard
            .first_use(&acme, other.id(), &jti("a-1"), in_five_minutes())
            .await
            .unwrap();
        let in_globex = guard
            .first_use(&globex, theirs.id(), &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        assert!(by_other);
        assert!(in_globex);
    }

    /// An assertion is forgotten once its expiry passed, when the next one
    /// is spent, so the ledger does not grow without end.
    #[tokio::test]
    async fn an_expired_assertion_is_forgotten() {
        let (db, guard, tenant, client) = fixture().await;
        guard
            .first_use(&tenant, &client, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();
        db.tamper("UPDATE oauth_client_assertions SET expires_at = now() - interval '1 minute'")
            .await;

        let spent_again = guard
            .first_use(&tenant, &client, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        assert!(spent_again);
    }
}
