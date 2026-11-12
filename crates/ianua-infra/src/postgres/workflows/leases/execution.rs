//! The lease that keeps one worker driving a workflow execution, so a
//! wake-up delivered twice drives it once.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::workflows::ExecutionLease;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::WorkflowExecutionId;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::workers::leases::{Leased, Leases};

/// This worker's leases on workflow executions.
pub struct PgExecutionLease {
    databases: Arc<Databases>,
    leases: Leases,
}

impl PgExecutionLease {
    /// This worker's leases on executions in `databases`, each lasting
    /// `lasting`: long enough to drive an execution to its next wait.
    #[must_use]
    pub fn new(databases: Arc<Databases>, lasting: Duration) -> Self {
        Self {
            databases,
            leases: Leases::of(Leased::WorkflowExecution, lasting),
        }
    }
}

#[async_trait]
impl ExecutionLease for PgExecutionLease {
    async fn try_claim(&self, id: &WorkflowExecutionId) -> Result<bool, DomainError> {
        self.leases.claim(&self.databases, id.as_uuid()).await
    }

    async fn release(&self, id: &WorkflowExecutionId) {
        self.leases.release(&self.databases, id.as_uuid()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDb;

    /// A second worker cannot claim a held execution lease but can claim it after
    /// the first worker releases it.
    #[tokio::test]
    async fn an_execution_is_driven_by_one_worker_at_a_time() {
        let db = TestDb::fresh().await;
        let lasting = Duration::from_secs(60);
        let first = PgExecutionLease::new(Arc::clone(&db.databases), lasting);
        let second = PgExecutionLease::new(Arc::clone(&db.databases), lasting);
        let execution = WorkflowExecutionId::new();
        first.try_claim(&execution).await.unwrap();

        let while_held = second.try_claim(&execution).await.unwrap();
        first.release(&execution).await;
        let after = second.try_claim(&execution).await.unwrap();

        assert!(!while_held);
        assert!(after);
    }
}
