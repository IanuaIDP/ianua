//! The job that runs one step of a deleted tenant's teardown: queued for
//! each step as it becomes ready, once per tenant and step, and run through
//! [`RunStepUseCase`]. A step that failed on its last try fails the
//! teardown through [`FailStepUseCase`].

use ianua_domain::domains::tenant::teardown::TeardownStep;

use crate::use_cases::scheduling::{StepJobHandler, StepJobs};
use crate::use_cases::tenant::teardown::fail::FailStepUseCase;
use crate::use_cases::tenant::teardown::run::RunStepUseCase;

/// The job type that runs one step of a tenant's teardown.
pub const TEARDOWN_STEP_JOB: &str = "tenant.teardown_step";

/// Where teardown step jobs are queued, and how many tries each gets.
pub type TeardownSteps = StepJobs<TeardownStep>;

/// Runs teardown step jobs.
pub type TeardownStepHandler = StepJobHandler<TeardownStep, RunStepUseCase, FailStepUseCase>;

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Arc;

    use ianua_domain::domains::scheduling::job::ScheduledJob;
    use ianua_domain::domains::scheduling::job_type::JobType;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::teardown::TenantTeardown;
    use ianua_domain::shared::model::steps::RunOutcome;

    use super::*;
    use crate::ports::scheduling::{JobClaim, JobQueue as _};
    use crate::ports::tenant::TenantTeardownStore as _;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{
        FakeTenantDatabaseProvisioner, FakeTenantStore, FakeTenantTeardownStore,
        test_tenant_deleted_apart,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::scheduling::{Handled, JobHandler as _};
    use crate::use_cases::tenant::teardown::{FailStepPorts, RunStepPorts};

    /// Claims the queued step with one tenant slot and a one-minute lease.
    fn claimed_step(queue: &FakeJobQueue) -> ScheduledJob {
        let types = [JobType::new(TEARDOWN_STEP_JOB).unwrap()];
        let claim = JobClaim {
            job_types: &types,
            limit: NonZeroU32::MIN,
            per_tenant: NonZeroU32::MIN,
            lease: time::Duration::MINUTE,
        };
        block_on(queue.claim(&claim)).unwrap().remove(0)
    }

    /// Keeps a teardown whose data and audit trail are already removed.
    fn ready_for_database(tenant: &Tenant) -> Arc<FakeTenantTeardownStore> {
        let teardowns = Arc::new(FakeTenantTeardownStore::empty());
        let mut teardown = TenantTeardown::begin(tenant).unwrap();
        teardown.finish(TeardownStep::Data).unwrap();
        teardown.finish(TeardownStep::AuditTrail).unwrap();
        block_on(teardowns.save(&teardown)).unwrap();
        teardowns
    }

    /// Removing a deleted tenant's database fails on the step's last try.
    /// The job ends, and the teardown fails rather than being tried for
    /// ever.
    #[test]
    fn a_step_failing_its_last_try_fails_the_teardown() {
        let tenant = test_tenant_deleted_apart();
        let tenant_id = *tenant.id();
        let teardowns = ready_for_database(&tenant);
        let tenants = Arc::new(FakeTenantStore::holding(tenant));
        let queue = Arc::new(FakeJobQueue::new());
        let steps = TeardownSteps::new(TEARDOWN_STEP_JOB, queue.clone(), NonZeroU32::MIN);
        block_on(steps.queue(tenant_id, TeardownStep::Database)).unwrap();
        let job = claimed_step(&queue);
        let run = RunStepUseCase::new(RunStepPorts {
            teardowns: teardowns.clone(),
            tenants,
            databases: Arc::new(FakeTenantDatabaseProvisioner::failing(1)),
            steps,
            ..RunStepPorts::fakes()
        });
        let fail = FailStepUseCase::new(FailStepPorts {
            teardowns: teardowns.clone(),
            ..FailStepPorts::fakes()
        });
        let handler = TeardownStepHandler::new(
            TEARDOWN_STEP_JOB,
            Arc::new(run),
            Arc::new(fail),
            queue.clone(),
        )
        .unwrap();

        let handled =
            block_on(handler.handle(&job, &test_auditor(Arc::new(FakeEventDispatcher::new()))))
                .unwrap();

        assert_eq!(handled, Handled::Done);
        assert_eq!(
            teardowns.of(&tenant_id).unwrap().outcome(),
            RunOutcome::Failed
        );
    }
}
