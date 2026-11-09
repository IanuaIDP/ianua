//! Purge ended evaluations: remove every tenant's evaluations once they
//! ended longer ago than the domain keeps them for.
//!
//! An evaluation is for its workflow's authors to read back, and for its
//! publishing gate, which reads only the newest. Its start and end stay in
//! the audit trail, so one past its keeping is removed without a record of
//! its own. Evaluations still running are kept, however old: their looks,
//! or the sweep of overdue ones, end them first.
//!
//! It runs on a schedule, outside any request, for nobody. Running it late
//! or twice removes nothing that should stay.

use std::sync::Arc;

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::workflows::evaluation::run::EVALUATIONS_KEPT_DAYS;
use ianua_domain::shared::clock;
use time::{Duration, OffsetDateTime};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::ports::workflows::EvaluationStore;
use crate::services::tenant_batches::{PurgeReport, TenantBatches};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`PurgeEndedUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PurgeEndedPorts {
    /// Keeps the evaluations.
    pub evaluations: Arc<dyn EvaluationStore>,
    /// Lists the tenants whose evaluations are purged.
    pub tenants: Arc<dyn TenantStore>,
}

/// Removes every tenant's evaluations past their keeping.
pub struct PurgeEndedUseCase {
    ports: PurgeEndedPorts,
}

impl PurgeEndedUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PurgeEndedPorts) -> Self {
        Self { ports }
    }

    /// Removes `tenant`'s evaluations that ended before `cutoff` and
    /// returns how many went; `None` when they could not be removed.
    async fn purged(&self, tenant: &Tenant, cutoff: OffsetDateTime) -> Option<u64> {
        let scoped = ScopedTenant::for_background(*tenant.id());
        match self
            .ports
            .evaluations
            .purge_ended_before(&scoped, cutoff)
            .await
        {
            Ok(removed) => Some(removed),
            Err(error) => {
                tracing::warn!(tenant_id = %tenant.id(), %error, "evaluations not purged");
                None
            }
        }
    }
}

impl Command for PurgeEndedUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<PurgeReport, AppError>;

    /// Removes every tenant's evaluations that ended longer ago than the
    /// domain keeps them for, and returns how many went.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the tenant list cannot be read.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        (): (),
    ) -> Result<PurgeReport, AppError> {
        let cutoff = clock::now().saturating_sub(Duration::days(EVALUATIONS_KEPT_DAYS));
        let mut report = PurgeReport::default();
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
    use ianua_domain::domains::workflows::evaluation::set::PublishGate;

    use super::*;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::workflows::{
        FakeEvaluationStore, draft_by, evaluation_of, parcel_case, person, set_for, tidy_step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An evaluation that ended two months ago goes; one still running from
    /// as long ago, and one that ended today, stay.
    #[test]
    fn only_evaluations_ended_past_their_keeping_go() {
        let ann = person("ann@corp.test");
        let draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
        let set = set_for(&draft, &ann, vec![parcel_case("late")], PublishGate::Off);
        let long_ago = clock::now().saturating_sub(Duration::days(60));
        let (old, stuck) = {
            let _then = clock::freeze(long_ago);
            let mut old = evaluation_of(&set, &draft, &ann);
            old.give_up().unwrap();
            (old, evaluation_of(&set, &draft, &ann))
        };
        let mut recent = evaluation_of(&set, &draft, &ann);
        recent.give_up().unwrap();
        let evaluations = Arc::new(FakeEvaluationStore::holding(&old));
        for kept in [&stuck, &recent] {
            block_on(evaluations.insert(&test_ctx().tenant(), kept)).unwrap();
        }
        let use_case = PurgeEndedUseCase::new(PurgeEndedPorts {
            evaluations: evaluations.clone(),
            tenants: Arc::new(FakeTenantStore::holding_all(vec![test_tenant_for_ctx()])),
        });

        let report = block_on(use_case.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            (),
        ))
        .unwrap();

        assert_eq!(report.removed, 1);
        assert!(evaluations.stored(old.id()).is_none());
        assert!(evaluations.stored(stuck.id()).is_some());
        assert!(evaluations.stored(recent.id()).is_some());
    }
}
