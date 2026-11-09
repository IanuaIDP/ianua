//! The job that runs one step of a tenant's setup: queued for each step as
//! it becomes ready, once per tenant and step, and run through
//! [`RunStepUseCase`]. A step that failed on its last try fails the
//! setup through [`FailStepUseCase`].

use ianua_domain::domains::tenant::setup::SetupStep;

use crate::use_cases::scheduling::{StepJobHandler, StepJobs};
use crate::use_cases::tenant::setup::fail::FailStepUseCase;
use crate::use_cases::tenant::setup::run::RunStepUseCase;

/// The job type that runs one step of a tenant's setup.
pub const SETUP_STEP_JOB: &str = "tenant.setup_step";

/// Where setup step jobs are queued, and how many tries each gets.
pub type SetupSteps = StepJobs<SetupStep>;

/// Runs setup step jobs.
pub type SetupStepHandler = StepJobHandler<SetupStep, RunStepUseCase, FailStepUseCase>;

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Arc;

    use ianua_domain::domains::scheduling::job::ScheduledJob;
    use ianua_domain::domains::scheduling::job_status::JobStatus;
    use ianua_domain::domains::scheduling::job_type::JobType;
    use ianua_domain::domains::tenant::setup::TenantSetup;
    use ianua_domain::shared::model::steps::RunOutcome;

    use super::*;
    use crate::ports::scheduling::{JobClaim, JobQueue as _};
    use crate::ports::tenant::TenantSetupStore as _;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{
        FakeTenantDatabaseProvisioner, FakeTenantSetupStore, FakeTenantStore, test_tenant_apart,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::scheduling::{Handled, JobHandler as _};
    use crate::use_cases::tenant::setup::{FailStepPorts, RunStepPorts};

    /// Claims the queued step with one tenant slot and a one-minute lease.
    fn claimed_step(queue: &FakeJobQueue) -> ScheduledJob {
        let types = [JobType::new(SETUP_STEP_JOB).unwrap()];
        let claim = JobClaim {
            job_types: &types,
            limit: NonZeroU32::MIN,
            per_tenant: NonZeroU32::MIN,
            lease: time::Duration::MINUTE,
        };
        block_on(queue.claim(&claim)).unwrap().remove(0)
    }

    /// The database of a tenant apart fails on the step's last try. The
    /// job ends, and the setup fails rather than being tried for ever.
    #[test]
    fn a_step_failing_its_last_try_fails_the_setup() {
        let tenant = test_tenant_apart();
        let tenant_id = *tenant.id();
        let setups = Arc::new(FakeTenantSetupStore::empty());
        block_on(setups.save(&TenantSetup::begin(&tenant).unwrap())).unwrap();
        let tenants = Arc::new(FakeTenantStore::holding(tenant));
        let queue = Arc::new(FakeJobQueue::new());
        let steps = SetupSteps::new(SETUP_STEP_JOB, queue.clone(), NonZeroU32::MIN);
        block_on(steps.queue(tenant_id, SetupStep::Database)).unwrap();
        let job = claimed_step(&queue);
        let run = RunStepUseCase::new(RunStepPorts {
            setups: setups.clone(),
            tenants: tenants.clone(),
            databases: Arc::new(FakeTenantDatabaseProvisioner::failing(1)),
            steps,
            ..RunStepPorts::fakes()
        });
        let fail = FailStepUseCase::new(FailStepPorts {
            setups: setups.clone(),
            tenants,
            ..FailStepPorts::fakes()
        });
        let handler =
            SetupStepHandler::new(SETUP_STEP_JOB, Arc::new(run), Arc::new(fail), queue.clone())
                .unwrap();

        let handled =
            block_on(handler.handle(&job, &test_auditor(Arc::new(FakeEventDispatcher::new()))))
                .unwrap();

        assert_eq!(handled, Handled::Done);
        assert_eq!(setups.of(&tenant_id).unwrap().outcome(), RunOutcome::Failed);
    }

    /// Acme's database step was taken by a worker that crashed; once its
    /// hold ran out the job was given up. The platform hands the step out
    /// again, and the new job makes the database. The given-up job is
    /// superseded, not dead, so Bob the operator does not find it among the
    /// dead; the new one completed.
    #[test]
    fn a_step_done_after_a_crash_supersedes_the_job_given_up_on_it() {
        let tenant = test_tenant_apart();
        let tenant_id = *tenant.id();
        let setups = Arc::new(FakeTenantSetupStore::empty());
        block_on(setups.save(&TenantSetup::begin(&tenant).unwrap())).unwrap();
        let tenants = Arc::new(FakeTenantStore::holding(tenant));
        let queue = Arc::new(FakeJobQueue::new());
        let steps = SetupSteps::new(SETUP_STEP_JOB, queue.clone(), NonZeroU32::MIN);
        block_on(steps.queue(tenant_id, SetupStep::Database)).unwrap();
        let crashed = claimed_step(&queue);
        queue.lapse_leases();
        assert!(
            block_on(queue.claim(&JobClaim {
                job_types: &[JobType::new(SETUP_STEP_JOB).unwrap()],
                limit: NonZeroU32::MIN,
                per_tenant: NonZeroU32::MIN,
                lease: time::Duration::MINUTE,
            }))
            .unwrap()
            .is_empty()
        );
        block_on(steps.queue(tenant_id, SetupStep::Database)).unwrap();
        let again = claimed_step(&queue);
        let run = RunStepUseCase::new(RunStepPorts {
            setups: setups.clone(),
            tenants: tenants.clone(),
            steps,
            ..RunStepPorts::fakes()
        });
        let fail = FailStepUseCase::new(FailStepPorts {
            setups,
            tenants,
            ..FailStepPorts::fakes()
        });
        let handler =
            SetupStepHandler::new(SETUP_STEP_JOB, Arc::new(run), Arc::new(fail), queue.clone())
                .unwrap();

        let handled =
            block_on(handler.handle(&again, &test_auditor(Arc::new(FakeEventDispatcher::new()))))
                .unwrap();

        assert_eq!(handled, Handled::Done);
        let first = block_on(queue.find(crashed.id())).unwrap().unwrap();
        assert_eq!(first.status(), JobStatus::Superseded);
    }
}
