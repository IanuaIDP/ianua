//! Reconcile: pick up work left half-done. An agent run left started with
//! no worker driving it, a new tenant whose setup never began or stalled, a
//! deleted tenant whose teardown never began or stalled, and a clone left
//! copying, each for longer than they ever take, is handed out again: the
//! run and the clone get their job queued again, and the setup's and the
//! teardown's ready steps are queued again, each begun first if need be.
//!
//! Each is safe to hand out twice. A job queued again under its key adds
//! nothing while one waits, and the run and the clone are claimed before
//! they are worked on. Nothing is announced again: the record would say a
//! tenant was provisioned or deleted twice, and its watchers would be told
//! twice. A setup or teardown that failed waits for an operator and is not
//! handed out.

use std::num::NonZeroU32;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::{Enqueued, StalledWork};
use crate::ports::tenant::{TenantSetupStore, TenantStore, TenantTeardownStore};
use crate::use_case::Command;
use crate::use_cases::agents::runs::RunDrives;
use crate::use_cases::tenant::clones::CloneRuns;
use crate::use_cases::tenant::setup::{SetupStart, SetupSteps};
use crate::use_cases::tenant::teardown::{TeardownStart, TeardownSteps};

/// How long work may stand before it counts as left, and how much of each
/// kind one round picks up.
#[derive(Debug, Clone, Copy)]
pub struct ReconcileSettings {
    /// How long a run, a setup, a teardown or a copying clone may stand
    /// before it is handed out again. Longer than any of them takes.
    pub stale_after: Duration,
    /// The most of each kind one round picks up.
    pub batch: NonZeroU32,
}

/// The ports [`ReconcileUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReconcilePorts {
    /// Finds the work left half-done.
    pub stalled: Arc<dyn StalledWork>,
    /// Tenants, to begin a new one's setup or a deleted one's teardown.
    pub tenants: Arc<dyn TenantStore>,
    /// The new tenants' setups.
    pub setups: Arc<dyn TenantSetupStore>,
    /// The deleted tenants' teardowns.
    pub teardowns: Arc<dyn TenantTeardownStore>,
    /// Queues the job that drives a run.
    pub run_drives: RunDrives,
    /// Queues the job that copies a clone.
    pub clone_runs: CloneRuns,
    /// Queues the jobs that run a setup's steps.
    pub setup_steps: SetupSteps,
    /// Queues the jobs that run a teardown's steps.
    pub teardown_steps: TeardownSteps,
}

/// What one round handed out again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Runs whose drive job was queued again.
    pub runs: u32,
    /// Setup steps queued again.
    pub setup_steps: u32,
    /// Teardown steps queued again.
    pub teardown_steps: u32,
    /// Clones whose copy job was queued again.
    pub clones: u32,
}

/// Hands out again the work left half-done.
///
/// It runs as a sweep: no one calls it, so it takes no caller.
pub struct ReconcileUseCase {
    ports: ReconcilePorts,
    settings: ReconcileSettings,
}

impl ReconcileUseCase {
    /// A sweep over `ports`, as `settings` say.
    #[must_use]
    pub fn new(ports: ReconcilePorts, settings: ReconcileSettings) -> Self {
        Self { ports, settings }
    }

    /// Queues the drive job of every run left started before `before`.
    async fn runs(&self, before: OffsetDateTime) -> Result<u32, AppError> {
        let runs = self
            .ports
            .stalled
            .runs_without_lease(before, self.settings.batch)
            .await
            .or_internal()?;
        let mut queued = 0u32;
        for run in runs {
            let enqueued = self
                .ports
                .run_drives
                .queue(run.tenant_id, run.run_id)
                .await?;
            queued = queued.saturating_add(counted(enqueued));
        }
        Ok(queued)
    }

    /// Queues the copy job of every clone left copying since before
    /// `before`.
    async fn clones(&self, before: OffsetDateTime) -> Result<u32, AppError> {
        let clones = self
            .ports
            .stalled
            .clones_copying(before, self.settings.batch)
            .await
            .or_internal()?;
        let mut queued = 0u32;
        for clone in clones {
            let enqueued = self
                .ports
                .clone_runs
                .queue(clone.clone_id, clone.target)
                .await?;
            queued = queued.saturating_add(counted(enqueued));
        }
        Ok(queued)
    }

    /// Queues again the ready steps of every setup that never began or
    /// stood unchanged since before `before`, beginning it first if need
    /// be.
    async fn setups(&self, before: OffsetDateTime) -> Result<u32, AppError> {
        let tenants = self
            .ports
            .stalled
            .setups_left(before, self.settings.batch)
            .await
            .or_internal()?;
        let start = SetupStart {
            setups: self.ports.setups.as_ref(),
            tenants: self.ports.tenants.as_ref(),
            steps: &self.ports.setup_steps,
        };
        let mut queued = 0u32;
        for tenant_id in tenants {
            queued = queued.saturating_add(start.queued(tenant_id).await?.queued);
        }
        Ok(queued)
    }

    /// Queues again the ready steps of every teardown that never began or
    /// stood unchanged since before `before`, beginning it first if need
    /// be.
    async fn teardowns(&self, before: OffsetDateTime) -> Result<u32, AppError> {
        let tenants = self
            .ports
            .stalled
            .teardowns_left(before, self.settings.batch)
            .await
            .or_internal()?;
        let start = TeardownStart {
            teardowns: self.ports.teardowns.as_ref(),
            tenants: self.ports.tenants.as_ref(),
            steps: &self.ports.teardown_steps,
        };
        let mut queued = 0u32;
        for tenant_id in tenants {
            queued = queued.saturating_add(start.queued(tenant_id).await?.queued);
        }
        Ok(queued)
    }
}

impl Command for ReconcileUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<ReconcileReport, AppError>;

    /// Hands out again, as of `now`, each run, setup, teardown and clone
    /// left standing longer than the settings allow, at most a batch of
    /// each. Records nothing: the work handed out records what it does.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the stalled work cannot be read, a store
    ///   cannot be read or written, or a job cannot be queued. The next
    ///   round picks up what this one did not.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<ReconcileReport, AppError> {
        let before = now - self.settings.stale_after;
        Ok(ReconcileReport {
            runs: self.runs(before).await?,
            setup_steps: self.setups(before).await?,
            teardown_steps: self.teardowns(before).await?,
            clones: self.clones(before).await?,
        })
    }
}

/// One when the job was queued now, none when one was waiting already.
fn counted(enqueued: Enqueued) -> u32 {
    match enqueued {
        Enqueued::Queued => 1,
        Enqueued::AlreadyQueued => 0,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::setup::{SetupStep, TenantSetup};
    use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};
    use ianua_domain::domains::tenant::teardown::{TeardownStep, TenantTeardown};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{AgentRunId, TenantCloneId, TenantId, UntrustedText};

    use super::*;
    use crate::ports::scheduling::{StalledClone, StalledRun};
    use crate::test_support::scheduling::{FakeJobQueue, FakeStalledWork};
    use crate::test_support::tenant::{
        FakeTenantSetupStore, FakeTenantStore, FakeTenantTeardownStore, clone_runs, setup_steps,
        teardown_steps, tenant_for_ctx_standing, test_tenant_deleted, test_tenant_for_ctx,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::agents::runs::DRIVE_RUN_JOB;
    use crate::use_cases::tenant::clones::RUN_CLONE_JOB;
    use crate::use_cases::tenant::setup::SETUP_STEP_JOB;
    use crate::use_cases::tenant::teardown::TEARDOWN_STEP_JOB;

    struct Setup {
        uc: ReconcileUseCase,
        queue: Arc<FakeJobQueue>,
        stalled: Arc<FakeStalledWork>,
        setups: Arc<FakeTenantSetupStore>,
        teardowns: Arc<FakeTenantTeardownStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// Reclaims at most ten records of each kind after thirty minutes.
    fn sweep_settings() -> ReconcileSettings {
        ReconcileSettings {
            stale_after: Duration::minutes(30),
            batch: NonZeroU32::new(10).unwrap(),
        }
    }

    /// Exposes stalled records and the queues the reconciliation sweep fills.
    fn setup(stalled: FakeStalledWork, tenants: Vec<Tenant>) -> Setup {
        let queue = Arc::new(FakeJobQueue::new());
        let stalled = Arc::new(stalled);
        let setups = Arc::new(FakeTenantSetupStore::empty());
        let teardowns = Arc::new(FakeTenantTeardownStore::empty());
        let uc = ReconcileUseCase::new(
            ReconcilePorts {
                stalled: stalled.clone(),
                tenants: Arc::new(FakeTenantStore::holding_all(tenants)),
                setups: setups.clone(),
                teardowns: teardowns.clone(),
                run_drives: RunDrives {
                    queue: queue.clone(),
                    attempts: NonZeroU32::MIN,
                },
                clone_runs: clone_runs(queue.clone()),
                setup_steps: setup_steps(queue.clone()),
                teardown_steps: teardown_steps(queue.clone()),
            },
            sweep_settings(),
        );
        Setup {
            uc,
            queue,
            stalled,
            setups,
            teardowns,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn reconcile(setup: &Setup, now: OffsetDateTime) -> ReconcileReport {
        block_on(
            setup
                .uc
                .execute(&(), &test_auditor(setup.audit.clone()), now),
        )
        .unwrap()
    }

    /// A worker died driving Acme's run, and the run's start event was
    /// lost with it. The sweep queues the run's drive job again.
    #[test]
    fn a_run_nobody_drives_has_its_job_queued_again() {
        let run = StalledRun {
            tenant_id: TenantId::new(),
            run_id: AgentRunId::new(),
        };
        let setup = setup(FakeStalledWork::with_runs(vec![run]), Vec::new());

        let report = reconcile(&setup, clock::now());

        assert_eq!(report.runs, 1);
        assert_eq!(setup.queue.jobs_of(DRIVE_RUN_JOB).len(), 1);
    }

    /// A clone into staging stands copying with nobody copying it. Its copy
    /// job is queued again; a second round, while that job waits, adds
    /// nothing.
    #[test]
    fn a_clone_left_copying_has_its_job_queued_once() {
        let clone = StalledClone {
            clone_id: TenantCloneId::new(),
            target: TenantId::new(),
        };
        let setup = setup(FakeStalledWork::with_clones(vec![clone]), Vec::new());

        let first = reconcile(&setup, clock::now());
        let second = reconcile(&setup, clock::now());

        assert_eq!((first.clones, second.clones), (1, 0));
        assert_eq!(setup.queue.jobs_of(RUN_CLONE_JOB).len(), 1);
    }

    /// A tenant whose setup never began gets a setup and three queued steps
    /// from the sweep, without another provisioning audit record.
    #[test]
    fn a_tenant_never_set_up_has_its_setup_begun() {
        let tenant = test_tenant_for_ctx();
        let id = *tenant.id();
        let setup = setup(FakeStalledWork::with_setups(vec![id]), vec![tenant]);

        let report = reconcile(&setup, clock::now());

        assert_eq!(report.setup_steps, 3);
        assert!(setup.setups.of(&id).is_some());
        assert_eq!(setup.queue.jobs_of(SETUP_STEP_JOB).len(), 3);
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A setup whose step jobs were lost with a stopped worker has them
    /// queued again; a second round, while they wait, adds nothing.
    #[test]
    fn a_stalled_setup_has_its_steps_queued_once() {
        let tenant = test_tenant_for_ctx();
        let id = *tenant.id();
        let setup = setup(FakeStalledWork::with_setups(vec![id]), vec![tenant.clone()]);
        block_on(setup.setups.save(&TenantSetup::begin(&tenant).unwrap())).unwrap();

        let first = reconcile(&setup, clock::now());
        let second = reconcile(&setup, clock::now());

        assert_eq!((first.setup_steps, second.setup_steps), (3, 0));
        assert_eq!(setup.queue.jobs_of(SETUP_STEP_JOB).len(), 3);
    }

    /// Failed setups and tenants already active are left alone by the sweep,
    /// with no setup jobs queued and no audit records added.
    #[test]
    fn a_setup_failed_or_a_tenant_moved_on_is_left_alone() {
        let failing = test_tenant_for_ctx();
        let moved_on = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let ids = vec![*failing.id(), *moved_on.id()];
        let setup = setup(
            FakeStalledWork::with_setups(ids),
            vec![failing.clone(), moved_on],
        );
        let mut failed = TenantSetup::begin(&failing).unwrap();
        failed
            .fail(
                SetupStep::SigningKey,
                UntrustedText::record("no key service"),
            )
            .unwrap();
        block_on(setup.setups.save(&failed)).unwrap();

        let report = reconcile(&setup, clock::now());

        assert_eq!(report.setup_steps, 0);
        assert!(setup.queue.jobs_of(SETUP_STEP_JOB).is_empty());
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A deleted tenant whose teardown never began gets a teardown and its
    /// first queued step, without another deletion audit record.
    #[test]
    fn a_deleted_tenant_never_torn_down_has_its_teardown_begun() {
        let tenant = test_tenant_deleted();
        let id = *tenant.id();
        let setup = setup(FakeStalledWork::with_teardowns(vec![id]), vec![tenant]);

        let report = reconcile(&setup, clock::now());

        assert_eq!(report.teardown_steps, 1);
        assert!(setup.teardowns.of(&id).is_some());
        assert_eq!(setup.queue.jobs_of(TEARDOWN_STEP_JOB).len(), 1);
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A teardown whose step job was lost has that step queued again; a
    /// second round, while it waits, adds nothing.
    #[test]
    fn a_stalled_teardown_has_its_step_queued_once() {
        let tenant = test_tenant_deleted();
        let id = *tenant.id();
        let setup = setup(
            FakeStalledWork::with_teardowns(vec![id]),
            vec![tenant.clone()],
        );
        block_on(
            setup
                .teardowns
                .save(&TenantTeardown::begin(&tenant).unwrap()),
        )
        .unwrap();

        let first = reconcile(&setup, clock::now());
        let second = reconcile(&setup, clock::now());

        assert_eq!((first.teardown_steps, second.teardown_steps), (1, 0));
        assert_eq!(setup.queue.jobs_of(TEARDOWN_STEP_JOB).len(), 1);
    }

    /// A teardown that ended since it was found queues nothing.
    #[test]
    fn a_teardown_that_ended_is_left_alone() {
        let tenant = test_tenant_deleted();
        let id = *tenant.id();
        let setup = setup(
            FakeStalledWork::with_teardowns(vec![id]),
            vec![tenant.clone()],
        );
        let mut teardown = TenantTeardown::begin(&tenant).unwrap();
        teardown.finish(TeardownStep::Data).unwrap();
        block_on(setup.teardowns.save(&teardown)).unwrap();

        let report = reconcile(&setup, clock::now());

        assert_eq!(report.teardown_steps, 0);
        assert!(setup.queue.jobs_of(TEARDOWN_STEP_JOB).is_empty());
    }

    /// With thirty minutes allowed, a round at noon asks for work left
    /// since before half past eleven.
    #[test]
    fn work_counts_as_left_only_past_the_allowed_age() {
        let setup = setup(FakeStalledWork::default(), Vec::new());
        let now = clock::now();

        reconcile(&setup, now);

        assert!(
            setup
                .stalled
                .cutoffs()
                .iter()
                .all(|cutoff| *cutoff == now - Duration::minutes(30))
        );
    }
}
