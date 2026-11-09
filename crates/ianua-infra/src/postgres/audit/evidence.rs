//! An agent's audit records as a reviewer reads them: each with its place
//! and hashes in the tenant's chain, read in chain order through the index
//! of the records by actor.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::audit::EvidenceStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::evidence::EvidenceRecord;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentId;

use self::record::ChainedRecord;
use crate::postgres::audit::actors::AGENT;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of agents' evidence.
pub struct PgEvidenceStore {
    databases: Arc<Databases>,
}

impl PgEvidenceStore {
    /// A store reading evidence from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgEvidenceStore {}

#[async_trait]
impl EvidenceStore for PgEvidenceStore {
    async fn agent_records(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<EvidenceRecord>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChainedRecord,
                    "queries/audit_records/of_agent.sql",
                    tenant_id.as_uuid(),
                    AGENT,
                    agent.as_uuid(),
                    after_seq,
                    i64::from(limit)
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(ChainedRecord::into_evidence)
            .collect()
    }

    async fn records_of(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        seqs: &[i64],
    ) -> Result<Vec<i64>, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/audit_records/seqs_of_agent.sql",
                    tenant_id.as_uuid(),
                    AGENT,
                    agent.as_uuid(),
                    seqs
                )
                .fetch_all(connection)
                .await
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        agent_event, failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        agent: AgentId,
        store: PgEvidenceStore,
    }

    /// A fresh database, a tenant whose agent acted three times between
    /// two records of the platform's own, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let agent = AgentId::new();
        recorded(
            &db.databases,
            vec![
                failed_sign_in(*tenant, 1),
                agent_event(*tenant, agent, 2),
                agent_event(*tenant, agent, 3),
                failed_sign_in(*tenant, 4),
                agent_event(*tenant, agent, 5),
            ],
        )
        .await;
        let store = PgEvidenceStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            tenant,
            agent,
            store,
        }
    }

    fn seqs(records: &[EvidenceRecord]) -> Vec<i64> {
        records.iter().map(|record| record.seq).collect()
    }

    /// The agent's records are read in chain order, after a place and at
    /// most so many, each linked to the record before it in the chain.
    #[tokio::test]
    async fn an_agents_records_are_read_in_chain_order() {
        let db = fixture().await;

        let first = db
            .store
            .agent_records(&db.tenant, &db.agent, 0, 2)
            .await
            .unwrap();
        let rest = db
            .store
            .agent_records(&db.tenant, &db.agent, 3, 10)
            .await
            .unwrap();

        assert_eq!(seqs(&first), [2, 3]);
        assert_eq!(seqs(&rest), [5]);
        assert_eq!(first[1].prev_hash, first[0].entry_hash);
        assert_eq!(first[0].entry_hash.len(), 32);
        assert_eq!(first[0].occurred_at, at(2));
    }

    /// Of the places a reviewer cites, only those of the agent's own
    /// records are confirmed; a record of the platform's own, and one
    /// that does not exist, are not.
    #[tokio::test]
    async fn only_the_agents_own_places_are_confirmed() {
        let db = fixture().await;

        let found = db
            .store
            .records_of(&db.tenant, &db.agent, &[1, 2, 5, 99])
            .await
            .unwrap();

        assert_eq!(found, [2, 5]);
    }

    /// Reading an agent's evidence through another tenant returns no records.
    #[tokio::test]
    async fn another_tenant_reads_none_of_the_evidence() {
        let db = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());

        let read = db
            .store
            .agent_records(&other, &db.agent, 0, 10)
            .await
            .unwrap();

        assert!(read.is_empty());
    }

    /// Reading evidence rejects a stored record with an unknown event type
    /// as corrupt.
    #[tokio::test]
    async fn a_record_whose_event_type_is_unknown_is_refused() {
        let db = fixture().await;
        db.db
            .tamper(
                "SET session_replication_role = replica; \
                 UPDATE audit_records SET event_type = 'wizard.cast' WHERE seq = 2; \
                 SET session_replication_role = origin;",
            )
            .await;

        let read = db.store.agent_records(&db.tenant, &db.agent, 0, 10).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
