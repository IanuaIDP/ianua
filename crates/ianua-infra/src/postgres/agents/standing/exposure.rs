//! The most sensitive data each agent of a tenant has touched, its mark,
//! each table row under row-level security.
//!
//! The mark is stored as the level's rank, so the check and the raise are
//! one statement that a concurrent request cannot split. Lowering it is one
//! statement too, and only while the mark is still the one the person saw
//! and the agent is still stopped.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::AgentExposureGate;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::identity::exposure_reset::ExposureReset;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentId;

use self::record::into_level;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres gate on what each agent's mark lets it reach.
pub struct PgAgentExposureGate {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAgentExposureGate {}

impl PgAgentExposureGate {
    /// A gate keeping marks in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AgentExposureGate for PgAgentExposureGate {
    async fn admit(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        class: DataClassLevel,
    ) -> Result<bool, DomainError> {
        let raised = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/agent_exposure/admit.sql",
                    tenant_id.as_uuid(),
                    agent_id.as_uuid(),
                    class.rank()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        Ok(raised.is_some())
    }

    async fn current(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
    ) -> Result<DataClassLevel, DomainError> {
        let rank = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/agent_exposure/current.sql",
                    tenant_id.as_uuid(),
                    agent_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        into_level(rank)
    }

    async fn reset(
        &self,
        tenant_id: &ScopedTenant,
        reset: &ExposureReset<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let lowered = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_exposure/reset.sql",
                    tenant_id.as_uuid(),
                    reset.agent_id().as_uuid(),
                    reset.previous().rank(),
                    reset.lowered_to().rank()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(lowered.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::AgentStore;
    use ianua_domain::domains::agents::identity::agent::{AgentIdentity, AgentIdentityRow};
    use ianua_domain::domains::agents::identity::control::AgentControl;
    use ianua_domain::domains::agents::identity::exposure_reset::LowerExposureParams;
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::{Label, TenantId};

    use super::*;
    use crate::postgres::agents::PgAgentStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::agent_row;

    /// A fresh database, the gate on it, one tenant, the agent store, and
    /// an active agent of the tenant.
    async fn fixture() -> (
        TestDb,
        PgAgentExposureGate,
        ScopedTenant,
        PgAgentStore,
        AgentIdentity<ResolvedTenant>,
    ) {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let agents = PgAgentStore::new(Arc::clone(&db.databases));
        let agent = AgentIdentity::reconstitute(agent_row("reader")).unwrap();
        agents.save(&tenant, &agent).await.unwrap();
        let gate = PgAgentExposureGate::new(Arc::clone(&db.databases));
        (db, gate, tenant, agents, agent)
    }

    /// `agent` as it would stand suspended, saved through the agent store.
    async fn suspended(
        agents: &PgAgentStore,
        tenant: &ScopedTenant,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> AgentIdentity<ResolvedTenant> {
        let stopped = AgentIdentity::reconstitute(AgentIdentityRow {
            id: *agent.id(),
            status: AgentStatus::Suspended,
            ..agent_row("reader")
        })
        .unwrap();
        agents.save(tenant, &stopped).await.unwrap();
        stopped
    }

    /// An agent administrator lowering `agent`'s mark from `from` to `to`.
    fn lowering(
        agent: &AgentIdentity<ResolvedTenant>,
        from: DataClassLevel,
        to: DataClassLevel,
    ) -> ExposureReset<ResolvedTenant> {
        let admin = anyone_holding(&[SystemPermission::Agents(AgentAction::Manage)]);
        ExposureReset::ordered(
            &AgentControl::new(admin),
            agent,
            LowerExposureParams {
                from,
                to,
                reason: Label::new("reason", "Its context was cleared").unwrap(),
            },
        )
        .unwrap()
    }

    /// An agent that has touched nothing is public. Reaching internal data
    /// raises its mark; data less sensitive than its mark is refused, and
    /// more sensitive data raises the mark again.
    #[tokio::test]
    async fn the_mark_only_rises_and_bars_less_sensitive_routes() {
        let (_db, gate, tenant, _agents, agent) = fixture().await;
        let id = agent.id();

        let untouched = gate.current(&tenant, id).await.unwrap();
        let internal = gate
            .admit(&tenant, id, DataClassLevel::Internal)
            .await
            .unwrap();
        let again = gate
            .admit(&tenant, id, DataClassLevel::Internal)
            .await
            .unwrap();
        let public = gate
            .admit(&tenant, id, DataClassLevel::Public)
            .await
            .unwrap();
        let restricted = gate
            .admit(&tenant, id, DataClassLevel::Restricted)
            .await
            .unwrap();

        assert_eq!(untouched, DataClassLevel::Public);
        assert!(internal && again && restricted);
        assert!(!public);
        assert_eq!(
            gate.current(&tenant, id).await.unwrap(),
            DataClassLevel::Restricted
        );
    }

    /// A stopped agent's mark is lowered by the person who saw it; a
    /// second reset from the mark they saw then finds it lowered already
    /// and changes nothing.
    #[tokio::test]
    async fn a_stopped_agents_mark_is_lowered_from_the_mark_seen() {
        let (_db, gate, tenant, agents, agent) = fixture().await;
        gate.admit(&tenant, agent.id(), DataClassLevel::Restricted)
            .await
            .unwrap();
        let stopped = suspended(&agents, &tenant, &agent).await;
        let reset = lowering(
            &stopped,
            DataClassLevel::Restricted,
            DataClassLevel::Internal,
        );

        let lowered = gate.reset(&tenant, &reset).await.unwrap();
        let repeated = gate.reset(&tenant, &reset).await.unwrap();

        assert!(lowered);
        assert!(!repeated);
        assert_eq!(
            gate.current(&tenant, agent.id()).await.unwrap(),
            DataClassLevel::Internal
        );
    }

    /// Resuming the agent after preparing a reset makes the reset return
    /// false and preserves its restricted exposure level.
    #[tokio::test]
    async fn a_resumed_agents_mark_is_not_lowered() {
        let (_db, gate, tenant, agents, agent) = fixture().await;
        gate.admit(&tenant, agent.id(), DataClassLevel::Restricted)
            .await
            .unwrap();
        let stopped = suspended(&agents, &tenant, &agent).await;
        let reset = lowering(&stopped, DataClassLevel::Restricted, DataClassLevel::Public);
        agents.save(&tenant, &agent).await.unwrap();

        let lowered = gate.reset(&tenant, &reset).await.unwrap();

        assert!(!lowered);
        assert_eq!(
            gate.current(&tenant, agent.id()).await.unwrap(),
            DataClassLevel::Restricted
        );
    }

    /// Another tenant's request does not read or raise this tenant's mark.
    #[tokio::test]
    async fn a_mark_is_kept_per_tenant() {
        let (_db, gate, tenant, _agents, agent) = fixture().await;
        gate.admit(&tenant, agent.id(), DataClassLevel::Restricted)
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let elsewhere = gate.current(&other, agent.id()).await.unwrap();

        assert_eq!(elsewhere, DataClassLevel::Public);
    }

    /// Recording exposure for an unknown agent returns an infrastructure error.
    #[tokio::test]
    async fn a_mark_for_an_unknown_agent_is_refused() {
        let (_db, gate, tenant, _agents, _agent) = fixture().await;

        let admitted = gate
            .admit(&tenant, &AgentId::new(), DataClassLevel::Internal)
            .await;

        assert!(matches!(admitted, Err(DomainError::Infrastructure(_))));
    }

    /// The mark of an agent of a tenant with a database of its own is kept
    /// there, and not in the platform database.
    #[tokio::test]
    async fn a_mark_of_a_tenant_with_its_own_database_is_kept_there() {
        let db = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        db.databases.register(*apart, own.as_dedicated());
        let agent = AgentIdentity::reconstitute(agent_row("reader")).unwrap();
        PgAgentStore::new(Arc::clone(&db.databases))
            .save(&apart, &agent)
            .await
            .unwrap();
        let gate = PgAgentExposureGate::new(Arc::clone(&db.databases));
        gate.admit(&apart, agent.id(), DataClassLevel::Confidential)
            .await
            .unwrap();

        let in_its_own = gate.current(&apart, agent.id()).await.unwrap();
        db.databases.deregister(&apart);
        let in_the_platform = gate.current(&apart, agent.id()).await.unwrap();

        assert_eq!(in_its_own, DataClassLevel::Confidential);
        assert_eq!(in_the_platform, DataClassLevel::Public);
    }
}
