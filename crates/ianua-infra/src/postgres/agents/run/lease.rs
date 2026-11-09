//! The lease that keeps one worker driving an agent run, so a run delivered
//! twice is driven once at a time.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::agents::RunLease;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentRunId;

use crate::postgres::foundation::leases::{Leased, Leases};
use crate::postgres::foundation::pool::Databases;

/// This worker's leases on agent runs.
pub struct PgRunLease {
    databases: Arc<Databases>,
    leases: Leases,
}

impl PgRunLease {
    /// This worker's leases on runs in `databases`, each lasting `lasting`
    /// unless renewed.
    #[must_use]
    pub fn new(databases: Arc<Databases>, lasting: Duration) -> Self {
        Self {
            databases,
            leases: Leases::of(Leased::AgentRun, lasting),
        }
    }
}

#[async_trait]
impl RunLease for PgRunLease {
    async fn try_claim(&self, run_id: &AgentRunId) -> Result<bool, DomainError> {
        self.leases.claim(&self.databases, run_id.as_uuid()).await
    }

    async fn renew(&self, run_id: &AgentRunId) -> Result<bool, DomainError> {
        self.leases.renew(&self.databases, run_id.as_uuid()).await
    }

    async fn release(&self, run_id: &AgentRunId) {
        self.leases.release(&self.databases, run_id.as_uuid()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDb;

    const A_MINUTE: Duration = Duration::from_secs(60);

    fn worker(db: &TestDb, lasting: Duration) -> PgRunLease {
        PgRunLease::new(Arc::clone(&db.databases), lasting)
    }

    /// The first worker claims a run's lease; the second cannot claim it
    /// while that lease is held.
    #[tokio::test]
    async fn a_held_run_is_not_claimed_by_another_worker() {
        let db = TestDb::fresh().await;
        let (first, second) = (worker(&db, A_MINUTE), worker(&db, A_MINUTE));
        let run = AgentRunId::new();

        let won = first.try_claim(&run).await.unwrap();
        let lost = second.try_claim(&run).await.unwrap();

        assert!(won);
        assert!(!lost);
    }

    /// A worker that stopped leaves its lease to run out; the next worker
    /// takes the run over, and the first then finds it lost.
    #[tokio::test]
    async fn a_lapsed_lease_is_taken_over() {
        let db = TestDb::fresh().await;
        let stopped = worker(&db, Duration::ZERO);
        let next = worker(&db, A_MINUTE);
        let run = AgentRunId::new();
        stopped.try_claim(&run).await.unwrap();

        let taken = next.try_claim(&run).await.unwrap();
        let still_held = stopped.renew(&run).await.unwrap();

        assert!(taken);
        assert!(!still_held);
    }

    /// The holder renews its lease; once it lets go, another worker may
    /// claim the run.
    #[tokio::test]
    async fn a_released_run_is_free_again() {
        let db = TestDb::fresh().await;
        let (first, second) = (worker(&db, A_MINUTE), worker(&db, A_MINUTE));
        let run = AgentRunId::new();
        first.try_claim(&run).await.unwrap();

        let renewed = first.renew(&run).await.unwrap();
        first.release(&run).await;
        let claimed = second.try_claim(&run).await.unwrap();

        assert!(renewed);
        assert!(claimed);
    }
}
