//! Whether an agent may act right now, read on every agent request so a
//! suspension, a revoke or a forced re-attestation takes effect on the
//! next one. An agent that is gone reads as revoked.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::AgentStandingCheck;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::identity::standing::AgentStanding;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentId;

use self::record::into_standing;
use crate::postgres::agents::identity::agents::records_of;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres check of an agent's standing.
pub struct PgAgentStandingCheck {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAgentStandingCheck {}

impl PgAgentStandingCheck {
    /// A check reading the agents in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AgentStandingCheck for PgAgentStandingCheck {
    async fn standing(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
    ) -> Result<AgentStanding, DomainError> {
        let ids = [*agent_id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        into_standing(records.into_iter().next(), clock::now())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::AgentStore;
    use ianua_domain::domains::agents::identity::agent::{
        AgentIdentity, AgentIdentityRow, Containment,
    };
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::agents::PgAgentStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::agent_row;
    use crate::test_support::rows::at;

    /// A fresh database, the check on it, one tenant and the agent store.
    async fn fixture() -> (TestDb, PgAgentStandingCheck, ScopedTenant, PgAgentStore) {
        let db = TestDb::fresh().await;
        let check = PgAgentStandingCheck::new(Arc::clone(&db.databases));
        let agents = PgAgentStore::new(Arc::clone(&db.databases));
        (
            db,
            check,
            ScopedTenant::for_background(TenantId::new()),
            agents,
        )
    }

    async fn saved(
        agents: &PgAgentStore,
        tenant: &ScopedTenant,
        row: AgentIdentityRow,
    ) -> AgentIdentity<ResolvedTenant> {
        let agent = AgentIdentity::reconstitute(row).unwrap();
        agents.save(tenant, &agent).await.unwrap();
        agent
    }

    /// Rows covering every standing returned by the check.
    fn standing_rows() -> [AgentIdentityRow; 4] {
        [
            agent_row("active"),
            AgentIdentityRow {
                status: AgentStatus::Suspended,
                ..agent_row("suspended")
            },
            AgentIdentityRow {
                status: AgentStatus::Revoked,
                ..agent_row("revoked")
            },
            AgentIdentityRow {
                containment: Containment::ReattestationRequired { since: at(5) },
                ..agent_row("held")
            },
        ]
    }

    /// An active agent may act; a suspended one, a revoked one and one held
    /// until it re-attests may not, each for its own reason.
    #[tokio::test]
    async fn the_standing_is_the_agents_own() {
        let (_db, check, tenant, agents) = fixture().await;
        let mut saved_agents = Vec::new();
        for row in standing_rows() {
            saved_agents.push(saved(&agents, &tenant, row).await);
        }

        let mut standings = Vec::new();
        for agent in &saved_agents {
            standings.push(check.standing(&tenant, agent.id()).await.unwrap());
        }

        assert_eq!(
            standings,
            [
                AgentStanding::Active,
                AgentStanding::Suspended,
                AgentStanding::Revoked,
                AgentStanding::MustReattest,
            ]
        );
    }

    /// Unknown agents and agents belonging to another tenant both read as
    /// revoked.
    #[tokio::test]
    async fn a_missing_or_foreign_agent_reads_as_revoked() {
        let (_db, check, tenant, agents) = fixture().await;
        let active = saved(&agents, &tenant, agent_row("active")).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let unknown = check.standing(&tenant, &AgentId::new()).await.unwrap();
        let foreign = check.standing(&other, active.id()).await.unwrap();

        assert_eq!(unknown, AgentStanding::Revoked);
        assert_eq!(foreign, AgentStanding::Revoked);
    }

    /// Checking the standing of an agent offered to its own owner returns a
    /// corruption error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_agent_is_refused() {
        let (db, check, tenant, agents) = fixture().await;
        let active = saved(&agents, &tenant, agent_row("active")).await;
        db.tamper(
            "UPDATE agents SET offered_to_kind = owner_kind, offered_to_id = owner_id, \
             offered_to_person = owner_person, offered_at = created_at, \
             offer_expires_at = created_at + interval '1 day'",
        )
        .await;

        let read = check.standing(&tenant, active.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
