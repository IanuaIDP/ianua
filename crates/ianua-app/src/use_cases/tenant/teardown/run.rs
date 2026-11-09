//! Running one step of a deleted tenant's teardown.
//!
//! A step's work (removing data and files, moving the audit trail,
//! removing a database) runs first, on its own: each is safe to run again. Then, in
//! one unit, the step is marked done, the steps that became ready are
//! queued and the records are kept, so a step done and its successors
//! queued are never parted. A step not ready, because it is done already
//! or the teardown failed, is left as it is.
//!
//! The data and the audit trail steps run as parallel jobs, so both may
//! finish at the same moment. The teardown is saved only over the version
//! the unit read, so the second to save is refused rather than undoing the
//! first one's mark, and is recorded again at once over the teardown read
//! afresh. Its work is not run again.

use std::sync::Arc;

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::teardown::{TeardownStep, TenantTeardown};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::model::steps::RunOutcome;
use ianua_domain::types::TenantId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::AuditTrailMover;
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::{
    TeardownVersion, TenantDataPurger, TenantDatabaseProvisioner, TenantFilePurger,
    TenantMemoryPurger, TenantStore, TenantTeardownStore,
};
use crate::services::fresh_reads::tried_on_fresh_reads;
use crate::services::kept_together::kept_together;
use crate::services::lookup::existing_tenant;
use crate::use_case::Command;
use crate::use_cases::scheduling::StepRequest;
use crate::use_cases::tenant::teardown::job::TeardownSteps;
use crate::use_cases::tenant::teardown::lookup::existing_teardown;

/// The ports [`RunStepUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RunStepPorts {
    /// Loads and saves removal progress after each completed step.
    pub teardowns: Arc<dyn TenantTeardownStore>,
    /// The tenants, read for their residency.
    pub tenants: Arc<dyn TenantStore>,
    /// Removes a tenant's data.
    pub purger: Arc<dyn TenantDataPurger>,
    /// Removes a tenant's files.
    pub files: Arc<dyn TenantFilePurger>,
    /// Deletes the memories' texts, wherever they are kept.
    pub memories: Arc<dyn TenantMemoryPurger>,
    /// Moves a tenant's audit trail to the platform's database.
    pub trails: Arc<dyn AuditTrailMover>,
    /// Removes a tenant's own database.
    pub databases: Arc<dyn TenantDatabaseProvisioner>,
    /// Keeps a step done, its successors and its records together.
    pub unit: Arc<dyn UnitOfWork>,
    /// Where the next steps are queued.
    pub steps: TeardownSteps,
}

/// Runs one step of a deleted tenant's teardown.
///
/// The job processor runs it, for nobody, so its caller is `()`.
pub struct RunStepUseCase {
    ports: RunStepPorts,
}

impl RunStepUseCase {
    /// A runner over `ports`.
    #[must_use]
    pub fn new(ports: RunStepPorts) -> Self {
        Self { ports }
    }

    /// The step's work, done before the unit opens.
    async fn work(&self, tenant: &Tenant, step: TeardownStep) -> Result<(), AppError> {
        match step {
            TeardownStep::Data => self.purge(tenant.id()).await,
            TeardownStep::AuditTrail => self.ports.trails.move_to_platform(tenant.id()).await,
            TeardownStep::Database => {
                self.ports
                    .databases
                    .teardown(
                        tenant.id(),
                        tenant.organization_id(),
                        tenant.residency().isolation(),
                    )
                    .await
            }
        }
        .or_internal()
    }

    /// The tenant's rows and then its files removed. Both are safe to run
    /// again, so a retry after either failed finishes the step.
    async fn purge(&self, tenant: &TenantId) -> Result<(), DomainError> {
        self.ports.purger.purge(tenant).await?;
        self.ports.memories.purge(tenant).await?;
        self.ports.files.purge(tenant).await
    }

    /// Reads the teardown afresh and, while the step is still ready,
    /// records it done in one unit. A step no longer ready is left as it
    /// is, and the teardown answered as it stands.
    ///
    /// # Errors
    ///
    /// `AppError::Conflict` when another step saved the teardown since this
    /// read; the unit kept nothing.
    async fn recorded_afresh(
        &self,
        request: StepRequest<TeardownStep>,
        auditor: &RequestAuditor,
    ) -> Result<TenantTeardown, AppError> {
        let teardown = existing_teardown(self.ports.teardowns.as_ref(), &request.tenant_id).await?;
        if !teardown.ready().contains(&request.step) {
            return Ok(teardown);
        }
        let unit = self.ports.unit.as_ref();
        kept_together(unit, self.recorded(teardown, request.step, auditor)).await
    }

    /// In one unit: the step done, the teardown saved while it is as it was
    /// read, the steps it readied queued, and the records kept.
    async fn recorded(
        &self,
        mut teardown: TenantTeardown,
        step: TeardownStep,
        auditor: &RequestAuditor,
    ) -> Result<TenantTeardown, AppError> {
        let read = TeardownVersion::of(&teardown);
        teardown.finish(step).map_err(AppError::from_domain)?;
        self.ports
            .teardowns
            .save_unchanged_since(&teardown, read)
            .await
            .map_err(AppError::from_domain)?;
        self.ports
            .steps
            .queue_each(*teardown.tenant_id(), teardown.ready())
            .await?;
        auditor
            .dispatch(&teardown.take_events())
            .await
            .or_internal()?;
        Ok(teardown)
    }
}

impl Command for RunStepUseCase {
    type Caller = ();
    type Input = StepRequest<TeardownStep>;
    type Output = Result<RunOutcome, AppError>;

    /// Runs `request`'s step when it is ready, and answers how the
    /// teardown stands after. A step that lost its race to save the
    /// teardown is recorded again at once over the teardown read afresh.
    /// The last step records `tenant.torn_down`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant or its teardown is gone.
    /// - `AppError::Conflict` when the teardown kept changing under every
    ///   try. The job tries the step again.
    /// - `AppError::Internal` when the step's work, a store, the queue or
    ///   the audit fails. The job tries the step again.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: StepRequest<TeardownStep>,
    ) -> Result<RunOutcome, AppError> {
        let teardown = existing_teardown(self.ports.teardowns.as_ref(), &request.tenant_id).await?;
        if !teardown.ready().contains(&request.step) {
            return Ok(teardown.outcome());
        }
        let tenant = existing_tenant(self.ports.tenants.as_ref(), &request.tenant_id).await?;
        self.work(&tenant, request.step).await?;
        let auditor = &auditor.with_tenant(request.tenant_id);
        let teardown = tried_on_fresh_reads(move || self.recorded_afresh(request, auditor)).await?;
        Ok(teardown.outcome())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::teardown::TenantTeardownRow;

    use super::*;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{
        FakeAuditTrailMover, FakeTenantDatabaseProvisioner, FakeTenantPurger, FakeTenantStore,
        FakeTenantTeardownStore, teardown_steps, test_tenant_deleted, test_tenant_deleted_apart,
    };
    use crate::test_support::{FakeEventDispatcher, PassThroughUnitOfWork, block_on, test_auditor};
    use crate::use_cases::tenant::teardown::TEARDOWN_STEP_JOB;

    struct Bench {
        run: RunStepUseCase,
        tenant_id: TenantId,
        teardowns: Arc<FakeTenantTeardownStore>,
        purger: Arc<FakeTenantPurger>,
        files: Arc<FakeTenantPurger>,
        trails: Arc<FakeAuditTrailMover>,
        databases: Arc<FakeTenantDatabaseProvisioner>,
        queue: Arc<FakeJobQueue>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// Keeps the removal plan before any step has completed.
    fn begun_teardown(tenant: &Tenant) -> Arc<FakeTenantTeardownStore> {
        let teardowns = Arc::new(FakeTenantTeardownStore::empty());
        block_on(teardowns.save(&TenantTeardown::begin(tenant).unwrap())).unwrap();
        teardowns
    }

    /// Runs removal steps against the saved tenant and observable resource stores.
    fn bench_for(tenant: Tenant, databases: FakeTenantDatabaseProvisioner) -> Bench {
        let tenant_id = *tenant.id();
        let teardowns = begun_teardown(&tenant);
        let tenants = Arc::new(FakeTenantStore::holding(tenant));
        let purger = Arc::new(FakeTenantPurger::default());
        let files = Arc::new(FakeTenantPurger::default());
        let trails = Arc::new(FakeAuditTrailMover::default());
        let databases = Arc::new(databases);
        let queue = Arc::new(FakeJobQueue::new());
        let run = RunStepUseCase::new(RunStepPorts {
            teardowns: teardowns.clone(),
            tenants,
            purger: purger.clone(),
            files: files.clone(),
            memories: crate::test_support::Fake::fake(),
            trails: trails.clone(),
            databases: databases.clone(),
            unit: Arc::new(PassThroughUnitOfWork),
            steps: teardown_steps(queue.clone()),
        });
        Bench {
            run,
            tenant_id,
            teardowns,
            purger,
            files,
            trails,
            databases,
            queue,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    impl Bench {
        fn run(&self, step: TeardownStep) -> Result<RunOutcome, AppError> {
            let request = StepRequest {
                tenant_id: self.tenant_id,
                step,
            };
            block_on(
                self.run
                    .execute(&(), &test_auditor(self.audit.clone()), request),
            )
        }

        fn teardown(&self) -> TenantTeardown {
            self.teardowns.of(&self.tenant_id).unwrap()
        }

        fn database_queued(&self) -> bool {
            self.queue
                .jobs_of(TEARDOWN_STEP_JOB)
                .iter()
                .any(|job| job.payload().contains("\"database\""))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// A tenant on the platform's database has its data and its files
    /// removed, and that ends its teardown, on record.
    #[test]
    fn removing_a_shared_tenants_data_ends_its_teardown() {
        let bench = bench_for(
            test_tenant_deleted(),
            FakeTenantDatabaseProvisioner::working(),
        );

        let outcome = bench.run(TeardownStep::Data).unwrap();

        assert_eq!(outcome, RunOutcome::Done);
        assert_eq!(bench.purger.purged(), [bench.tenant_id]);
        assert_eq!(bench.files.purged(), [bench.tenant_id]);
        assert_eq!(bench.recorded(), ["tenant.torn_down"]);
    }

    /// A tenant apart has its data removed and its trail moved, and only
    /// then is its database queued for removal.
    #[test]
    fn a_tenant_apart_has_its_database_queued_once_its_trail_is_moved() {
        let bench = bench_for(
            test_tenant_deleted_apart(),
            FakeTenantDatabaseProvisioner::working(),
        );

        bench.run(TeardownStep::Data).unwrap();
        let database_before_trail = bench.database_queued();
        bench.run(TeardownStep::AuditTrail).unwrap();

        assert!(!database_before_trail);
        assert_eq!(bench.trails.moved(), [bench.tenant_id]);
        assert!(bench.database_queued());
    }

    /// The database goes last, and the teardown is done after it.
    #[test]
    fn removing_the_database_ends_a_tenant_aparts_teardown() {
        let bench = bench_for(
            test_tenant_deleted_apart(),
            FakeTenantDatabaseProvisioner::working(),
        );
        bench.run(TeardownStep::Data).unwrap();
        bench.run(TeardownStep::AuditTrail).unwrap();

        let outcome = bench.run(TeardownStep::Database).unwrap();

        assert_eq!(outcome, RunOutcome::Done);
        assert_eq!(bench.databases.torn_down(), [bench.tenant_id]);
        assert_eq!(bench.recorded(), ["tenant.torn_down"]);
    }

    /// A database-removal step delivered before its prerequisites leaves the
    /// teardown running. No database is removed and no event is recorded.
    #[test]
    fn a_step_not_ready_does_nothing() {
        let bench = bench_for(
            test_tenant_deleted_apart(),
            FakeTenantDatabaseProvisioner::working(),
        );

        let outcome = bench.run(TeardownStep::Database).unwrap();

        assert_eq!(outcome, RunOutcome::Running);
        assert!(bench.databases.torn_down().is_empty());
        assert!(bench.recorded().is_empty());
    }

    /// The audit-trail step finishes while the data step is saving. Retrying
    /// with the current teardown preserves both completions and queues database
    /// removal once, without repeating the data purge.
    #[test]
    fn two_steps_finishing_at_once_both_count() {
        let bench = bench_for(
            test_tenant_deleted_apart(),
            FakeTenantDatabaseProvisioner::working(),
        );
        bench.teardowns.changes_before_next_save(|row| {
            let mut teardown = TenantTeardown::reconstitute(row).unwrap();
            teardown.finish(TeardownStep::AuditTrail).unwrap();
            TenantTeardownRow::from(&teardown)
        });

        bench.run(TeardownStep::Data).unwrap();

        let done = bench.teardown().done().to_vec();
        assert!(done.contains(&TeardownStep::Data));
        assert!(done.contains(&TeardownStep::AuditTrail));
        let databases_queued = bench
            .queue
            .jobs_of(TEARDOWN_STEP_JOB)
            .iter()
            .filter(|job| job.payload().contains("\"database\""))
            .count();
        assert_eq!(databases_queued, 1);
        assert_eq!(bench.purger.purged(), [bench.tenant_id]);
    }

    /// A database host that did not answer is an error, so the job tries
    /// the step again, and the teardown stays as it was until it works.
    #[test]
    fn a_failed_removal_is_tried_again() {
        let bench = bench_for(
            test_tenant_deleted_apart(),
            FakeTenantDatabaseProvisioner::failing(1),
        );
        bench.run(TeardownStep::Data).unwrap();
        bench.run(TeardownStep::AuditTrail).unwrap();

        let first = bench.run(TeardownStep::Database);
        bench.run(TeardownStep::Database).unwrap();

        assert!(matches!(first, Err(AppError::Internal(_))));
        assert_eq!(bench.teardown().outcome(), RunOutcome::Done);
    }
}
