//! Running one step of a tenant's setup.
//!
//! A step's slow work (making a database, generating a key) runs first, on
//! its own. Then, in one unit, what the step made is saved, the step is
//! marked done, the steps that became ready are queued and the records are
//! kept, so a step done and its successors queued are never parted. A step
//! not ready, because it is done already or the setup failed, is left as
//! it is: a retry that finds its work done finishes nothing twice.
//!
//! The first steps run as parallel jobs, so two may finish at the same
//! moment. The setup is saved only over the version the unit read, so the
//! second to save is refused rather than undoing the first one's mark. Its
//! unit rolls back whole, and the step is recorded again at once over the
//! setup read afresh, with what its slow work made still in hand: the same
//! key saved again, the starting roles not yet held made again. Waiting for
//! the job's retry would hold the tenant provisioning for minutes.

use std::sync::Arc;

use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::role::starting::{StartingRole, StartingRolesGrant};
use ianua_domain::domains::crypto::assertion_key::{AssertionKey, AssertionKeySet};
use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKey, SigningKeySet};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::setup::{SetupStep, TenantSetup};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::{Raises as _, RaisesComplete as _};
use ianua_domain::shared::model::steps::RunOutcome;
use ianua_domain::types::{ActedBy, Label, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::RoleStore;
use crate::ports::crypto::{AssertionKeyStore, KeyGenerator, SigningKeyStore};
use crate::ports::provisioning::{SetupProgressObserver, StepOutcome};
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::{
    ProvisionDatabaseRequest, SetupVersion, TenantDatabaseProvisioner, TenantSetupStore,
    TenantStore,
};
use crate::services::fresh_reads::tried_on_fresh_reads;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::{generated_assertion_key, generated_signing_key};
use crate::use_cases::scheduling::StepRequest;
use crate::use_cases::tenant::setup::job::SetupSteps;
use crate::use_cases::tenant::setup::lookup::{progress_of, setup_and_tenant};

/// The ports [`RunStepUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RunStepPorts {
    /// Loads and saves provisioning progress after each completed step.
    pub setups: Arc<dyn TenantSetupStore>,
    /// The tenants, read for their residency and activated last.
    pub tenants: Arc<dyn TenantStore>,
    /// Makes a tenant's own database.
    pub databases: Arc<dyn TenantDatabaseProvisioner>,
    /// The tenants' signing keys.
    pub keys: Arc<dyn SigningKeyStore>,
    /// The tenants' assertion keys.
    pub assertion_keys: Arc<dyn AssertionKeyStore>,
    /// Makes a signing key or an assertion key.
    pub key_generator: Arc<dyn KeyGenerator>,
    /// The tenants' roles.
    pub roles: Arc<dyn RoleStore>,
    /// Told of each step that ended.
    pub progress: Arc<dyn SetupProgressObserver>,
    /// Keeps a step's results, its successors and its records together.
    pub unit: Arc<dyn UnitOfWork>,
    /// Where the next steps are queued.
    pub steps: SetupSteps,
}

/// What a step's slow work made, before it is saved. It is kept until the
/// step is recorded, so a unit that lost its race saves the same again.
enum Made {
    /// Nothing to save: the work is done outside, or saved as it is applied.
    Nothing,
    /// The tenant's first signing key.
    Key(SigningKey),
    /// The tenant's first assertion key.
    AssertionKey(AssertionKey),
}

/// A step whose slow work is done, with what it made.
struct Worked {
    request: StepRequest<SetupStep>,
    made: Made,
}

/// How recording a step over the setup read afresh ended.
enum Recorded {
    /// The step is done, in the setup as it was saved.
    Done(TenantSetup),
    /// The setup no longer had the step ready: another try finished it, or
    /// the setup failed meanwhile. Nothing was saved.
    Left(TenantSetup),
}

/// Runs one step of a tenant's setup.
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

    /// The step's slow work, done before the unit opens.
    async fn worked(
        &self,
        tenant: &Tenant,
        request: StepRequest<SetupStep>,
    ) -> Result<Worked, AppError> {
        let made = self.made(tenant, request.step).await?;
        Ok(Worked { request, made })
    }

    /// What the step's slow work makes.
    async fn made(&self, tenant: &Tenant, step: SetupStep) -> Result<Made, AppError> {
        match step {
            SetupStep::Database => {
                let request = ProvisionDatabaseRequest::for_residency(tenant.residency().clone());
                self.ports
                    .databases
                    .provision(tenant.id(), tenant.organization_id(), &request)
                    .await
                    .or_internal()?;
                Ok(Made::Nothing)
            }
            SetupStep::SigningKey => self.first_key(tenant.id()).await,
            SetupStep::AssertionKey => self.first_assertion_key(tenant.id()).await,
            SetupStep::StartingRoles | SetupStep::Activate => Ok(Made::Nothing),
        }
    }

    /// A fresh assertion key, unless the tenant has its assertion keys
    /// already.
    async fn first_assertion_key(&self, tenant_id: &TenantId) -> Result<Made, AppError> {
        let scoped = ScopedTenant::for_background(*tenant_id);
        let keys = self.ports.assertion_keys.as_ref();
        if keys.find(&scoped).await.or_internal()?.is_some() {
            return Ok(Made::Nothing);
        }
        let key = generated_assertion_key(self.ports.key_generator.as_ref()).await?;
        Ok(Made::AssertionKey(key))
    }

    /// A fresh key, unless the tenant has its key set already.
    async fn first_key(&self, tenant_id: &TenantId) -> Result<Made, AppError> {
        let scoped = ScopedTenant::for_background(*tenant_id);
        if self.ports.keys.find(&scoped).await.or_internal()?.is_some() {
            return Ok(Made::Nothing);
        }
        let key = generated_signing_key(
            self.ports.key_generator.as_ref(),
            SigningAlgorithm::FOR_NEW_TENANTS,
        )
        .await?;
        Ok(Made::Key(key))
    }

    /// Saves what the step made, and answers its records.
    async fn applied(
        &self,
        tenant: &mut Tenant,
        setup: &TenantSetup,
        worked: &Worked,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let scoped = ScopedTenant::for_background(*tenant.id());
        match (worked.request.step, &worked.made) {
            (SetupStep::SigningKey, Made::Key(key)) => {
                self.saved_signing_key(&scoped, key.clone()).await
            }
            (SetupStep::AssertionKey, Made::AssertionKey(key)) => {
                self.saved_assertion_key(&scoped, key.clone()).await
            }
            (SetupStep::StartingRoles, _) => {
                let grant = setup
                    .starting_roles_grant()
                    .map_err(AppError::from_domain)?;
                self.starting_roles(&scoped, &grant).await
            }
            (SetupStep::Activate, _) => self.activated(tenant).await,
            (SetupStep::Database | SetupStep::SigningKey | SetupStep::AssertionKey, _) => {
                Ok(Vec::new())
            }
        }
    }

    /// Saves the tenant's first signing key, and answers what it raised.
    async fn saved_signing_key(
        &self,
        tenant: &ScopedTenant,
        key: SigningKey,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let mut key_set = SigningKeySet::<ResolvedTenant>::new(key);
        self.ports.keys.save(tenant, &key_set).await.or_internal()?;
        Ok(key_set.take_events(tenant))
    }

    /// Saves the tenant's first assertion key, and answers what it raised.
    async fn saved_assertion_key(
        &self,
        tenant: &ScopedTenant,
        key: AssertionKey,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let mut keys = AssertionKeySet::<ResolvedTenant>::new(key);
        self.ports
            .assertion_keys
            .save(tenant, &keys)
            .await
            .or_internal()?;
        Ok(keys.take_events(tenant))
    }

    /// Activates the tenant, and answers what it raised.
    async fn activated(&self, tenant: &mut Tenant) -> Result<Vec<DomainEvent>, AppError> {
        tenant
            .activate(ActedBy::Platform)
            .map_err(AppError::from_domain)?;
        self.ports.tenants.save(tenant).await.or_internal()?;
        Ok(tenant.take_events())
    }

    /// Makes each starting role the tenant does not have yet.
    async fn starting_roles(
        &self,
        tenant: &ScopedTenant,
        grant: &StartingRolesGrant,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let mut events = Vec::new();
        for kind in StartingRole::ALL {
            let name = Label::new("name", kind.name()).or_internal()?;
            let held = self
                .ports
                .roles
                .find_by_name(tenant, &name)
                .await
                .or_internal()?;
            if held.is_some() {
                continue;
            }
            let mut role =
                Role::<ResolvedTenant>::starting(kind, grant).map_err(AppError::from_domain)?;
            self.ports.roles.save(tenant, &role).await.or_internal()?;
            events.extend(role.take_events(tenant));
        }
        Ok(events)
    }

    /// Reads the setup and its tenant afresh and, while the step is still
    /// ready, records it in one unit.
    ///
    /// # Errors
    ///
    /// `AppError::Conflict` when another step saved the setup since this
    /// read; the unit kept nothing.
    async fn recorded_afresh(
        &self,
        worked: &Worked,
        auditor: &RequestAuditor,
    ) -> Result<Recorded, AppError> {
        let (setup, tenant) = setup_and_tenant(
            self.ports.setups.as_ref(),
            self.ports.tenants.as_ref(),
            &worked.request.tenant_id,
        )
        .await?;
        if !setup.ready().contains(&worked.request.step) {
            return Ok(Recorded::Left(setup));
        }
        let unit = self.ports.unit.as_ref();
        let setup = kept_together(unit, self.recorded(tenant, setup, worked, auditor)).await?;
        Ok(Recorded::Done(setup))
    }

    /// In one unit: what the step made saved, the step done, the steps it
    /// readied queued, and the records kept. The setup is saved only while
    /// it is as it was read.
    async fn recorded(
        &self,
        mut tenant: Tenant,
        mut setup: TenantSetup,
        worked: &Worked,
        auditor: &RequestAuditor,
    ) -> Result<TenantSetup, AppError> {
        let read = SetupVersion::of(&setup);
        let events = self.applied(&mut tenant, &setup, worked).await?;
        setup
            .finish(worked.request.step)
            .map_err(AppError::from_domain)?;
        self.ports
            .setups
            .save_unchanged_since(&setup, read)
            .await
            .map_err(AppError::from_domain)?;
        self.ports
            .steps
            .queue_each(*tenant.id(), setup.ready())
            .await?;
        auditor.dispatch(&events).await.or_internal()?;
        Ok(setup)
    }
}

impl Command for RunStepUseCase {
    type Caller = ();
    type Input = StepRequest<SetupStep>;
    type Output = Result<RunOutcome, AppError>;

    /// Runs `request`'s step when it is ready, and answers how the setup
    /// stands after. Records what the step raised: the signing key made,
    /// the assertion key made, the starting roles made, the tenant
    /// activated.
    ///
    /// A step that lost its race to save the setup is recorded again at
    /// once over the setup read afresh.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant or its setup is gone.
    /// - `AppError::Conflict` when the setup kept changing under every try.
    ///   The job tries the step again.
    /// - `AppError::Internal` when the step's work, a store, the queue or
    ///   the audit fails. The job tries the step again.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: StepRequest<SetupStep>,
    ) -> Result<RunOutcome, AppError> {
        let (setup, tenant) = setup_and_tenant(
            self.ports.setups.as_ref(),
            self.ports.tenants.as_ref(),
            &request.tenant_id,
        )
        .await?;
        if !setup.ready().contains(&request.step) {
            return Ok(setup.outcome());
        }
        let worked = &self.worked(&tenant, request).await?;
        let auditor = &auditor.with_tenant(request.tenant_id);
        let recorded = tried_on_fresh_reads(move || self.recorded_afresh(worked, auditor)).await?;
        let setup = match recorded {
            Recorded::Left(setup) => return Ok(setup.outcome()),
            Recorded::Done(setup) => setup,
        };
        let organization_id = *tenant.organization_id();
        let progress = progress_of(&setup, organization_id, request.step, StepOutcome::Done);
        self.ports.progress.on_progress(&progress).await;
        Ok(setup.outcome())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::setup::TenantSetupRow;
    use ianua_domain::domains::tenant::status::TenantStatus;

    use super::*;
    use crate::ports::crypto::AssertionSigningKeys as _;
    use crate::test_support::authorization::FakeRoleStore;
    use crate::test_support::crypto::{
        FakeAssertionKeyStore, FakeKeyGenerator, FakeSigningKeyStore,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{
        FakeTenantDatabaseProvisioner, FakeTenantSetupStore, FakeTenantStore,
        RecordingSetupProgress, setup_steps, test_tenant, test_tenant_apart,
    };
    use crate::test_support::{FakeEventDispatcher, PassThroughUnitOfWork, block_on, test_auditor};
    use crate::use_cases::tenant::setup::SETUP_STEP_JOB;

    struct Bench {
        run: RunStepUseCase,
        tenant_id: TenantId,
        tenants: Arc<FakeTenantStore>,
        setups: Arc<FakeTenantSetupStore>,
        keys: Arc<FakeSigningKeyStore>,
        assertion_keys: Arc<FakeAssertionKeyStore>,
        roles: Arc<FakeRoleStore>,
        databases: Arc<FakeTenantDatabaseProvisioner>,
        progress: Arc<RecordingSetupProgress>,
        queue: Arc<FakeJobQueue>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// The tenant and records its provisioning steps fill.
    struct ProvisionedRecords {
        tenants: Arc<FakeTenantStore>,
        setups: Arc<FakeTenantSetupStore>,
        keys: Arc<FakeSigningKeyStore>,
        assertion_keys: Arc<FakeAssertionKeyStore>,
        roles: Arc<FakeRoleStore>,
    }

    impl ProvisionedRecords {
        /// Begins setup with no keys or roles created yet.
        fn beginning(tenant: Tenant) -> Self {
            let setups = Arc::new(FakeTenantSetupStore::empty());
            block_on(setups.save(&TenantSetup::begin(&tenant).unwrap())).unwrap();
            Self {
                tenants: Arc::new(FakeTenantStore::holding(tenant)),
                setups,
                keys: Arc::new(FakeSigningKeyStore::empty()),
                assertion_keys: Arc::new(FakeAssertionKeyStore::empty()),
                roles: Arc::new(FakeRoleStore::empty()),
            }
        }
    }

    /// Runs provisioning against an unstarted setup and observable resource stores.
    fn bench_for(tenant: Tenant, databases: FakeTenantDatabaseProvisioner) -> Bench {
        let tenant_id = *tenant.id();
        let records = ProvisionedRecords::beginning(tenant);
        let databases = Arc::new(databases);
        let progress = Arc::new(RecordingSetupProgress::default());
        let queue = Arc::new(FakeJobQueue::new());
        let run = RunStepUseCase::new(RunStepPorts {
            setups: records.setups.clone(),
            tenants: records.tenants.clone(),
            databases: databases.clone(),
            keys: records.keys.clone(),
            assertion_keys: records.assertion_keys.clone(),
            key_generator: Arc::new(FakeKeyGenerator::new()),
            roles: records.roles.clone(),
            progress: progress.clone(),
            unit: Arc::new(PassThroughUnitOfWork),
            steps: setup_steps(queue.clone()),
        });
        Bench {
            run,
            tenant_id,
            tenants: records.tenants,
            setups: records.setups,
            keys: records.keys,
            assertion_keys: records.assertion_keys,
            roles: records.roles,
            databases,
            progress,
            queue,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn bench() -> Bench {
        bench_for(
            test_tenant("acme", "acme.com"),
            FakeTenantDatabaseProvisioner::working(),
        )
    }

    impl Bench {
        fn run(&self, step: SetupStep) -> Result<RunOutcome, AppError> {
            let request = StepRequest {
                tenant_id: self.tenant_id,
                step,
            };
            block_on(
                self.run
                    .execute(&(), &test_auditor(self.audit.clone()), request),
            )
        }

        fn setup(&self) -> TenantSetup {
            self.setups.of(&self.tenant_id).unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// The signing key step makes the tenant's first key, signing with
    /// RS256, records it, and tells the setup's watchers.
    #[test]
    fn the_key_step_makes_the_first_key() {
        let bench = bench();

        bench.run(SetupStep::SigningKey).unwrap();

        let scoped = ScopedTenant::for_background(bench.tenant_id);
        let key_set = block_on(bench.keys.find(&scoped)).unwrap().unwrap();
        assert_eq!(key_set.keys().len(), 1);
        assert_eq!(key_set.keys()[0].algorithm(), SigningAlgorithm::Rs256);
        assert_eq!(bench.setup().done(), [SetupStep::SigningKey]);
        assert_eq!(bench.recorded(), ["crypto.key_created"]);
        assert_eq!(bench.progress.told()[0].step_outcome, StepOutcome::Done);
    }

    /// The assertion key step makes the tenant's first assertion key,
    /// signing with ES256, which the gateway can sign with, and records it.
    #[test]
    fn the_assertion_key_step_makes_the_first_assertion_key() {
        let bench = bench();

        bench.run(SetupStep::AssertionKey).unwrap();

        let scoped = ScopedTenant::for_background(bench.tenant_id);
        let keys = block_on(bench.assertion_keys.find(&scoped))
            .unwrap()
            .unwrap();
        let signing = block_on(bench.assertion_keys.signing(&scoped)).unwrap();
        assert_eq!(keys.keys().len(), 1);
        assert_eq!(keys.keys()[0].algorithm(), AssertionKey::ALGORITHM);
        assert!(signing.is_some());
        assert_eq!(bench.setup().done(), [SetupStep::AssertionKey]);
        assert_eq!(bench.recorded(), ["crypto.assertion_key_created"]);
    }

    /// Running the assertion-key step with a key already stored leaves the
    /// tenant with one assertion key.
    #[test]
    fn a_retried_assertion_key_step_makes_no_second_key() {
        let bench = bench();
        let scoped = ScopedTenant::for_background(bench.tenant_id);
        let first = block_on(generated_assertion_key(&FakeKeyGenerator::new())).unwrap();
        block_on(
            bench
                .assertion_keys
                .save(&scoped, &AssertionKeySet::new(first)),
        )
        .unwrap();

        bench.run(SetupStep::AssertionKey).unwrap();

        let keys = block_on(bench.assertion_keys.find(&scoped))
            .unwrap()
            .unwrap();
        assert_eq!(keys.keys().len(), 1);
    }

    /// The starting roles step makes Admin and Member, and makes neither
    /// again when a retry finds one already there.
    #[test]
    fn the_roles_step_makes_each_starting_role_once() {
        let bench = bench();
        let scoped = ScopedTenant::for_background(bench.tenant_id);
        let grant = TenantSetup::begin(&test_tenant("other", "other.com"))
            .unwrap()
            .starting_roles_grant()
            .unwrap();
        let admin = Role::<ResolvedTenant>::starting(StartingRole::Admin, &grant).unwrap();
        block_on(bench.roles.save(&scoped, &admin)).unwrap();

        bench.run(SetupStep::StartingRoles).unwrap();

        let names: Vec<String> = bench
            .roles
            .stored(bench.tenant_id)
            .iter()
            .map(|role| role.name().as_str().to_owned())
            .collect();
        assert_eq!(names, ["Admin", "Member"]);
        assert_eq!(bench.recorded(), ["authorization.role_created"]);
    }

    /// Once its keys and roles are made, the tenant is activated, the setup
    /// is done, and the activation is on record.
    #[test]
    fn activation_finishes_the_setup() {
        let bench = bench();
        bench.run(SetupStep::SigningKey).unwrap();
        bench.run(SetupStep::AssertionKey).unwrap();
        bench.run(SetupStep::StartingRoles).unwrap();

        let outcome = bench.run(SetupStep::Activate).unwrap();

        assert_eq!(outcome, RunOutcome::Done);
        let tenant = block_on(bench.tenants.find_by_id(&bench.tenant_id))
            .unwrap()
            .unwrap();
        assert_eq!(tenant.status(), TenantStatus::Active);
        assert!(
            bench
                .recorded()
                .contains(&"tenant.status_changed".to_owned())
        );
    }

    /// An activation step delivered before its prerequisites leaves setup
    /// running and the tenant provisioning, with no event recorded.
    #[test]
    fn a_step_not_ready_does_nothing() {
        let bench = bench();

        let outcome = bench.run(SetupStep::Activate).unwrap();

        assert_eq!(outcome, RunOutcome::Running);
        let tenant = block_on(bench.tenants.find_by_id(&bench.tenant_id))
            .unwrap()
            .unwrap();
        assert_eq!(tenant.status(), TenantStatus::Provisioning);
        assert!(bench.recorded().is_empty());
    }

    /// A tenant with a schema of its own gets its database made first; its
    /// keys and its roles are queued once it is there.
    #[test]
    fn a_tenant_apart_gets_its_database_then_its_key_and_roles_queued() {
        let bench = bench_for(
            test_tenant_apart(),
            FakeTenantDatabaseProvisioner::working(),
        );

        bench.run(SetupStep::Database).unwrap();

        assert_eq!(bench.databases.made().len(), 1);
        let queued: Vec<String> = bench
            .queue
            .jobs_of(SETUP_STEP_JOB)
            .iter()
            .map(|job| job.payload().to_owned())
            .collect();
        assert_eq!(queued.len(), 3);
        assert!(queued.iter().any(|payload| payload.contains("signing_key")));
        assert!(
            queued
                .iter()
                .any(|payload| payload.contains("assertion_key"))
        );
        assert!(
            queued
                .iter()
                .any(|payload| payload.contains("starting_roles"))
        );
    }

    /// The setup of `row`, with `step` marked done as another step's job
    /// saves it.
    fn finished_in(row: TenantSetupRow, step: SetupStep) -> TenantSetupRow {
        let mut setup = TenantSetup::reconstitute(row).unwrap();
        setup.finish(step).unwrap();
        TenantSetupRow::from(&setup)
    }

    fn activations_queued(bench: &Bench) -> usize {
        bench
            .queue
            .jobs_of(SETUP_STEP_JOB)
            .iter()
            .filter(|job| job.payload().contains("\"activate\""))
            .count()
    }

    /// An assertion-key step finishes while the signing-key step is saving.
    /// Retrying with the current setup preserves both completions and the
    /// starting roles, makes activation ready and queues it once.
    #[test]
    fn two_steps_finishing_at_once_both_count() {
        let bench = bench();
        bench.run(SetupStep::StartingRoles).unwrap();
        bench
            .setups
            .changes_before_next_save(|row| finished_in(row, SetupStep::AssertionKey));

        bench.run(SetupStep::SigningKey).unwrap();

        let done = bench.setup().done().to_vec();
        assert!(done.contains(&SetupStep::StartingRoles));
        assert!(done.contains(&SetupStep::AssertionKey));
        assert!(done.contains(&SetupStep::SigningKey));
        assert_eq!(bench.setup().ready(), [SetupStep::Activate]);
        assert_eq!(activations_queued(&bench), 1);
    }

    /// The step recorded again after losing its race saves the key its
    /// slow work made, once, and records it once.
    #[test]
    fn a_step_recorded_again_saves_its_key_once() {
        let bench = bench();
        bench
            .setups
            .changes_before_next_save(|row| finished_in(row, SetupStep::StartingRoles));

        bench.run(SetupStep::SigningKey).unwrap();

        let scoped = ScopedTenant::for_background(bench.tenant_id);
        let key_set = block_on(bench.keys.find(&scoped)).unwrap().unwrap();
        assert_eq!(key_set.keys().len(), 1);
        assert_eq!(bench.recorded(), ["crypto.key_created"]);
    }

    /// The step whose race was lost to a try of the same step, which
    /// finished it, finishes nothing twice: the reloaded setup has it done
    /// already, and nothing more is saved or recorded.
    #[test]
    fn a_step_another_try_finished_meanwhile_is_left() {
        let bench = bench();
        bench
            .setups
            .changes_before_next_save(|row| finished_in(row, SetupStep::SigningKey));

        bench.run(SetupStep::SigningKey).unwrap();

        assert_eq!(bench.setup().done(), [SetupStep::SigningKey]);
        assert!(bench.recorded().is_empty());
        assert!(bench.progress.told().is_empty());
    }

    /// A database that did not come up is an error, so the job tries the
    /// step again, and the setup stays as it was.
    #[test]
    fn a_failed_database_is_tried_again() {
        let bench = bench_for(
            test_tenant_apart(),
            FakeTenantDatabaseProvisioner::failing(1),
        );

        let first = bench.run(SetupStep::Database);
        bench.run(SetupStep::Database).unwrap();

        assert!(matches!(first, Err(AppError::Internal(_))));
        assert_eq!(bench.setup().done(), [SetupStep::Database]);
    }
}
