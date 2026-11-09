//! The assertions each agent of a tenant already signed in with, kept
//! until each would have expired anyway, under row-level security.
//!
//! A use is one insert that does nothing for a `jti` the agent used
//! before, so of two sign-ins racing one captured assertion exactly one is
//! told it was the first. The tenant's expired assertions are forgotten as
//! the next one is spent. The ledger reads no row back, so it has no
//! mapping of its own.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::AgentAssertionReplayGuard;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, TokenId};
use time::OffsetDateTime;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres ledger of agent assertions already used.
pub struct PgAgentAssertionReplayGuard {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAgentAssertionReplayGuard {}

impl PgAgentAssertionReplayGuard {
    /// A ledger keeping used agent assertions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AgentAssertionReplayGuard for PgAgentAssertionReplayGuard {
    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        jti: &TokenId,
        expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let now = clock::now();
        let spent = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_assertions/clear_expired.sql",
                    tenant_id.as_uuid(),
                    now
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query_file_scalar!(
                    "queries/agent_assertions/spend.sql",
                    tenant_id.as_uuid(),
                    agent_id.as_uuid(),
                    jti.as_str(),
                    expires_at
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
    use ianua_domain::types::TenantId;
    use time::Duration;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::saved_agent;

    /// A fresh database, the ledger on it, one tenant and an agent of it.
    async fn fixture() -> (TestDb, PgAgentAssertionReplayGuard, ScopedTenant, AgentId) {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let agent = saved_agent(&db.databases, &tenant, "ledger").await;
        let guard = PgAgentAssertionReplayGuard::new(Arc::clone(&db.databases));
        (db, guard, tenant, agent)
    }

    fn jti(value: &str) -> TokenId {
        TokenId::new(value).unwrap()
    }

    fn in_five_minutes() -> OffsetDateTime {
        clock::now().saturating_add(Duration::minutes(5))
    }

    /// The first time an agent signs in with an assertion, this call
    /// records it.
    #[tokio::test]
    async fn a_fresh_assertion_is_a_first_use() {
        let (_db, guard, tenant, agent) = fixture().await;

        let first = guard
            .consume(&tenant, &agent, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        assert!(first);
    }

    /// Consuming the same assertion a second time returns false.
    #[tokio::test]
    async fn a_replayed_assertion_is_refused() {
        let (_db, guard, tenant, agent) = fixture().await;
        guard
            .consume(&tenant, &agent, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        let again = guard
            .consume(&tenant, &agent, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        assert!(!again);
    }

    /// Of two concurrent attempts to consume one assertion, exactly one
    /// reports that it was the first use.
    #[tokio::test]
    async fn two_racing_uses_let_exactly_one_in() {
        let (_db, guard, tenant, agent) = fixture().await;
        let id = jti("a-1");

        let (one, two) = tokio::join!(
            guard.consume(&tenant, &agent, &id, in_five_minutes()),
            guard.consume(&tenant, &agent, &id, in_five_minutes())
        );

        assert!(one.unwrap() ^ two.unwrap());
    }

    /// The same `jti` from another agent, or in another tenant, is that
    /// one's own first use.
    #[tokio::test]
    async fn another_agent_or_tenant_uses_its_own_ids() {
        let (db, guard, acme, agent) = fixture().await;
        let other = saved_agent(&db.databases, &acme, "other").await;
        let globex = ScopedTenant::for_background(TenantId::new());
        let theirs = saved_agent(&db.databases, &globex, "ledger").await;
        guard
            .consume(&acme, &agent, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        let by_other = guard
            .consume(&acme, &other, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();
        let in_globex = guard
            .consume(&globex, &theirs, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        assert!(by_other);
        assert!(in_globex);
    }

    /// An assertion is forgotten once its expiry passed, when the next one
    /// is spent, so the ledger does not grow without end.
    #[tokio::test]
    async fn an_expired_assertion_is_forgotten() {
        let (db, guard, tenant, agent) = fixture().await;
        guard
            .consume(&tenant, &agent, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();
        db.tamper("UPDATE agent_assertions SET expires_at = now() - interval '1 minute'")
            .await;

        let spent_again = guard
            .consume(&tenant, &agent, &jti("a-1"), in_five_minutes())
            .await
            .unwrap();

        assert!(spent_again);
    }
}
