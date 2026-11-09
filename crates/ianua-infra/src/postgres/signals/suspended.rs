//! The agents a tenant-wide stop suspended, read back from the agents
//! table by the time the stop stamped on each, under row-level security.
//!
//! The stop suspends every active agent in one statement; this reads them
//! back so each receiver hears of every one, oldest change first, in the
//! database the tenant lives in.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::signals::SuspendedAgents;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentId;
use time::OffsetDateTime;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The longest the read may take before it is given up.
const READ_AT_MOST: Duration = Duration::from_secs(10);

/// The Postgres read of the agents a stop suspended.
pub struct PgSuspendedAgents {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSuspendedAgents {}

impl PgSuspendedAgents {
    /// A read of the agents kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The ids `suspended_since` answers, without its time limit.
    async fn read(
        &self,
        tenant_id: &ScopedTenant,
        since: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<AgentId>, DomainError> {
        let ids = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/agents/suspended_since.sql",
                    tenant_id.as_uuid(),
                    since,
                    i64::from(limit.get())
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(ids.into_iter().map(AgentId::from_uuid).collect())
    }
}

#[async_trait]
impl SuspendedAgents for PgSuspendedAgents {
    async fn suspended_since(
        &self,
        tenant_id: &ScopedTenant,
        since: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<AgentId>, DomainError> {
        tokio::time::timeout(READ_AT_MOST, self.read(tenant_id, since, limit))
            .await
            .map_err(DomainError::infra)?
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::AgentStore;
    use ianua_domain::domains::agents::identity::agent::{AgentIdentity, AgentIdentityRow};
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::agents::PgAgentStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::agent_row;
    use crate::test_support::rows::at;

    struct Fixture {
        db: TestDb,
        read: PgSuspendedAgents,
        agents: PgAgentStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the read on it, and one tenant to keep agents of.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            read: PgSuspendedAgents::new(Arc::clone(&db.databases)),
            agents: PgAgentStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn most(limit: u32) -> NonZeroU32 {
        NonZeroU32::new(limit).unwrap()
    }

    impl Fixture {
        /// An agent named `name` in `status`, last changed `seconds` after
        /// the fixed moment, saved through the agent store.
        async fn saved(&self, name: &str, status: AgentStatus, seconds: i64) -> AgentId {
            let agent = AgentIdentity::reconstitute(AgentIdentityRow {
                status,
                updated_at: at(seconds),
                ..agent_row(name)
            })
            .unwrap();
            self.agents.save(&self.tenant, &agent).await.unwrap();
            *agent.id()
        }

        async fn since(&self, seconds: i64, limit: u32) -> Vec<AgentId> {
            self.read
                .suspended_since(&self.tenant, at(seconds), most(limit))
                .await
                .unwrap()
        }
    }

    /// The agents suspended at or after the moment are found, oldest change
    /// first; one suspended before it and one still active are not.
    #[tokio::test]
    async fn the_agents_suspended_since_a_moment_are_found_oldest_first() {
        let fx = fixture().await;
        let later = fx.saved("ledger", AgentStatus::Suspended, 20).await;
        let first = fx.saved("payroll", AgentStatus::Suspended, 10).await;
        fx.saved("archive", AgentStatus::Suspended, 5).await;
        fx.saved("billing", AgentStatus::Active, 30).await;

        let found = fx.since(10, 10).await;

        assert_eq!(found, [first, later]);
    }

    /// No more agents are read than the limit allows.
    #[tokio::test]
    async fn no_more_than_the_limit_are_read() {
        let fx = fixture().await;
        let first = fx.saved("payroll", AgentStatus::Suspended, 10).await;
        fx.saved("ledger", AgentStatus::Suspended, 20).await;

        let found = fx.since(0, 1).await;

        assert_eq!(found, [first]);
    }

    /// The agents a stop of every active agent suspends are the ones read
    /// back after it.
    #[tokio::test]
    async fn a_tenant_wide_stop_is_read_back() {
        let fx = fixture().await;
        let payroll = fx.saved("payroll", AgentStatus::Active, 0).await;
        let ledger = fx.saved("ledger", AgentStatus::Active, 0).await;
        fx.agents.suspend_every_active(&fx.tenant).await.unwrap();

        let mut found = fx.since(0, 10).await;

        found.sort_by_key(|id| *id.as_uuid());
        let mut stopped = vec![payroll, ledger];
        stopped.sort_by_key(|id| *id.as_uuid());
        assert_eq!(found, stopped);
    }

    /// Another tenant's suspended-agent lookup returns none of Acme's agents.
    #[tokio::test]
    async fn another_tenant_reads_none_of_acmes_agents() {
        let fx = fixture().await;
        fx.saved("payroll", AgentStatus::Suspended, 10).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let found = fx
            .read
            .suspended_since(&other, at(0), most(10))
            .await
            .unwrap();

        assert!(found.is_empty());
    }

    /// A suspended agent saved for a tenant with a dedicated database is
    /// found by reading that database directly.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_is_read_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let agent = AgentIdentity::reconstitute(AgentIdentityRow {
            status: AgentStatus::Suspended,
            updated_at: at(10),
            ..agent_row("payroll")
        })
        .unwrap();
        fx.agents.save(&apart, &agent).await.unwrap();

        let in_own = PgSuspendedAgents::new(Arc::clone(&own.databases));
        let found = in_own
            .suspended_since(&apart, at(0), most(10))
            .await
            .unwrap();

        assert_eq!(found, [*agent.id()]);
    }
}
