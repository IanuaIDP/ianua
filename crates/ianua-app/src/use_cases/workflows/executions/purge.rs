//! Purge ended runs: remove every tenant's workflow runs once they ended
//! longer ago than the deployment keeps them for.
//!
//! A run holds what its steps read and made; what happened stays in the
//! audit trail, which keeps its records as long as the tenant's compliance
//! asks and is not touched here. So a run past its keeping is removed
//! without a record of its own, and its loop passes and the agent runs it
//! waited on let go of it with it. Runs still running or waiting on someone
//! are kept, however old, and so is a run another run started again from,
//! until that one is removed first.
//!
//! It runs on a schedule, outside any request, for nobody, so no one's
//! rights are asked. Running it late or twice removes nothing that should
//! stay: it looks at what ended long enough ago now.

use std::sync::Arc;

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::workflows::execution::retention::RunsKept;
use ianua_domain::shared::clock;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::ports::workflows::WorkflowExecutionStore;
use crate::services::tenant_batches::{PurgeReport, TenantBatches};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`PurgeEndedRunsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PurgeEndedRunsPorts {
    /// Removes the runs that ended before a moment.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Every tenant, whose runs are purged in turn.
    pub tenants: Arc<dyn TenantStore>,
}

/// Removes the ended runs past their keeping, tenant by tenant.
pub struct PurgeEndedRunsUseCase {
    ports: PurgeEndedRunsPorts,
    kept: RunsKept,
}

impl PurgeEndedRunsUseCase {
    /// A sweep over `ports`, keeping ended runs for `kept`.
    #[must_use]
    pub fn new(ports: PurgeEndedRunsPorts, kept: RunsKept) -> Self {
        Self { ports, kept }
    }

    /// Removes `tenant`'s runs that ended before `cutoff`, or `None` when
    /// that failed: the next round tries that tenant again.
    async fn purged(&self, tenant: &Tenant, cutoff: OffsetDateTime) -> Option<u64> {
        let scoped = ScopedTenant::for_background(*tenant.id());
        match self
            .ports
            .executions
            .purge_ended_before(&scoped, cutoff)
            .await
        {
            Ok(removed) => Some(removed),
            Err(error) => {
                tracing::warn!(tenant_id = %tenant.id(), %error, "workflow runs not purged");
                None
            }
        }
    }
}

impl Command for PurgeEndedRunsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<PurgeReport, AppError>;

    /// Removes every tenant's runs ended longer ago than the deployment
    /// keeps them for, and says how many went. Records nothing: a run's
    /// start and end stay in the audit trail. One tenant whose runs cannot
    /// be removed does not stop the others.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the tenants cannot be listed.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        (): (),
    ) -> Result<PurgeReport, AppError> {
        let cutoff = self.kept.since(clock::now());
        let mut report = PurgeReport {
            removed: 0,
            unpurged: 0,
        };
        let mut tenants = TenantBatches::over(self.ports.tenants.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                report = report.counting(self.purged(tenant, cutoff).await);
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::execution::retention::RUNS_KEPT_DAYS;
    use time::Duration;

    use super::*;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant};
    use crate::test_support::workflows::FakeWorkflowExecutionStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// A sweep over `executions` and `tenants`, keeping runs ninety days.
    fn purge(
        executions: Arc<FakeWorkflowExecutionStore>,
        tenants: FakeTenantStore,
    ) -> PurgeEndedRunsUseCase {
        PurgeEndedRunsUseCase::new(
            PurgeEndedRunsPorts {
                executions,
                tenants: Arc::new(tenants),
            },
            RunsKept::default(),
        )
    }

    /// The cutoff the sweep hands the store for Acme is ninety days back
    /// from now.
    #[test]
    fn each_tenant_is_purged_up_to_the_cutoff() {
        let acme = test_tenant("acme", "acme.example.com");
        let acme_id = *acme.id();
        let executions = Arc::new(FakeWorkflowExecutionStore::empty());
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let use_case = purge(executions.clone(), FakeTenantStore::holding(acme));

        let report = block_on(use_case.execute(&(), &auditor, ())).unwrap();

        assert_eq!(report.unpurged, 0);
        let cut = executions.purged_before(acme_id).unwrap();
        let expected = clock::now() - Duration::days(i64::from(RUNS_KEPT_DAYS));
        assert!((expected - cut).abs() < Duration::MINUTE);
    }
}
