//! Purge ended trials: remove every tenant's trials once they ended longer
//! ago than the domain keeps them for.
//!
//! A trial is for its person to read back, and nothing else reads it; its
//! start stays in the audit trail. So a trial past its keeping is removed
//! without a record of its own. Trials still running are kept, however old:
//! their job ends them.
//!
//! It runs on a schedule, outside any request, for nobody, so no one's
//! rights are asked. Running it late or twice removes nothing that should
//! stay: it looks at what ended long enough ago now.

use std::sync::Arc;

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::workflows::sandbox::trial::TRIAL_KEPT_HOURS;
use ianua_domain::shared::clock;
use time::{Duration, OffsetDateTime};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::ports::workflows::SandboxTrialStore;
use crate::services::tenant_batches::{PurgeReport, TenantBatches};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`PurgeEndedTrialsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PurgeEndedTrialsPorts {
    /// Keeps the trials.
    pub trials: Arc<dyn SandboxTrialStore>,
    /// Lists the tenants whose trials are purged.
    pub tenants: Arc<dyn TenantStore>,
}

/// Removes every tenant's trials past their keeping.
pub struct PurgeEndedTrialsUseCase {
    ports: PurgeEndedTrialsPorts,
}

impl PurgeEndedTrialsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PurgeEndedTrialsPorts) -> Self {
        Self { ports }
    }

    /// Removes `tenant`'s trials that ended before `cutoff` and returns how
    /// many went. A failure is logged and answered with `None`: the tenant
    /// is purged again next time, and the others still are now.
    async fn purged(&self, tenant: &Tenant, cutoff: OffsetDateTime) -> Option<u64> {
        let scoped = ScopedTenant::for_background(*tenant.id());
        match self.ports.trials.purge_ended_before(&scoped, cutoff).await {
            Ok(removed) => Some(removed),
            Err(error) => {
                tracing::warn!(tenant_id = %tenant.id(), %error, "trials not purged");
                None
            }
        }
    }
}

impl Command for PurgeEndedTrialsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<PurgeReport, AppError>;

    /// Removes every tenant's trials that ended longer ago than the domain
    /// keeps them for, and returns how many went.
    ///
    /// One tenant whose trials cannot be removed does not stop the others;
    /// it is counted as unpurged and tried again next time. Records
    /// nothing: removing old trials is housekeeping, not a change anyone
    /// made.
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
        let cutoff = clock::now().saturating_sub(Duration::hours(TRIAL_KEPT_HOURS));
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
    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
    use ianua_domain::domains::workflows::sandbox::trial::SandboxTrial;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::workflows::{
        FakeSandboxTrialStore, built_version_of, managing, person, python_sandbox,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A trial of Tess's, started now.
    fn started() -> SandboxTrial<ResolvedTenant> {
        let mut sandbox = python_sandbox();
        let version = built_version_of(&mut sandbox);
        sandbox
            .try_version(
                &managing(&person("tess@corp.test")),
                &version,
                FlowData::null(),
            )
            .unwrap()
    }

    /// Ends a trial while the clock still reads the time its result was produced.
    fn settled_at(trial: &mut SandboxTrial<ResolvedTenant>, at: OffsetDateTime) {
        let _then = clock::freeze(at);
        trial
            .settle(CodeOutcome::Failed(CodeFailure::TimedOut))
            .unwrap();
    }

    /// Purging removes a trial that ended two days ago, while retaining a recent
    /// ended trial and an equally old trial still running.
    #[test]
    fn only_trials_ended_past_their_keeping_go() {
        let trials = Arc::new(FakeSandboxTrialStore::empty());
        let tenant = test_ctx().tenant();
        let two_days_ago = clock::now().saturating_sub(Duration::days(2));
        let (mut old, stuck) = {
            let _then = clock::freeze(two_days_ago);
            (started(), started())
        };
        settled_at(&mut old, two_days_ago);
        let mut recent = started();
        recent
            .settle(CodeOutcome::Succeeded(FlowData::null()))
            .unwrap();
        for trial in [&old, &stuck, &recent] {
            block_on(trials.insert(&tenant, trial)).unwrap();
        }
        let use_case = PurgeEndedTrialsUseCase::new(PurgeEndedTrialsPorts {
            trials: trials.clone(),
            tenants: Arc::new(FakeTenantStore::holding_all(vec![test_tenant_for_ctx()])),
        });

        let report = block_on(use_case.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            (),
        ))
        .unwrap();

        assert_eq!(report.removed, 1);
        assert!(trials.stored(old.id()).is_none());
        assert!(trials.stored(stuck.id()).is_some());
        assert!(trials.stored(recent.id()).is_some());
    }
}
