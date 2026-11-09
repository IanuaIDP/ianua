//! Failing a tenant's setup at a step whose tries are spent: the setup
//! stops, the failure goes on record for the operators, and the setup's
//! watchers are told.

use std::sync::Arc;

use ianua_domain::domains::tenant::setup::{SetupStep, TenantSetup};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::model::steps::RunOutcome;
use ianua_domain::types::{OrganizationId, UntrustedText};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::provisioning::{SetupProgressObserver, StepOutcome};
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::{SetupVersion, TenantSetupStore, TenantStore};
use crate::services::fresh_reads::tried_on_fresh_reads;
use crate::services::kept_together::kept_together;
use crate::use_case::Command;
use crate::use_cases::scheduling::{StepFailure, StepRequest};
use crate::use_cases::tenant::setup::lookup::{progress_of, setup_and_tenant};

/// The ports [`FailStepUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct FailStepPorts {
    /// Loads and saves the terminal failure of a provisioning step.
    pub setups: Arc<dyn TenantSetupStore>,
    /// The tenants, read for the organization that watches them.
    pub tenants: Arc<dyn TenantStore>,
    /// Told of the step that failed.
    pub progress: Arc<dyn SetupProgressObserver>,
    /// Keeps the failure and its record together.
    pub unit: Arc<dyn UnitOfWork>,
}

/// Fails a tenant's setup at a step whose tries are spent.
pub struct FailStepUseCase {
    ports: FailStepPorts,
}

/// How failing a step over the setup read afresh ended.
enum Failed {
    /// The setup failed at the step, as it was saved, and the organization
    /// that watches it.
    Now(TenantSetup, OrganizationId),
    /// The step was no longer ready: done, or the setup failed already.
    /// Nothing was saved.
    Left(TenantSetup),
}

impl FailStepUseCase {
    /// A use case over `ports`.
    #[must_use]
    pub fn new(ports: FailStepPorts) -> Self {
        Self { ports }
    }

    /// Reads the setup afresh and, while the step is still ready, fails it
    /// there for `why` in one unit.
    ///
    /// # Errors
    ///
    /// `AppError::Conflict` when a step saved the setup since this read;
    /// the unit kept nothing.
    async fn failed_afresh(
        &self,
        request: StepRequest<SetupStep>,
        why: &UntrustedText,
        auditor: &RequestAuditor,
    ) -> Result<Failed, AppError> {
        let (mut setup, tenant) = setup_and_tenant(
            self.ports.setups.as_ref(),
            self.ports.tenants.as_ref(),
            &request.tenant_id,
        )
        .await?;
        if !setup.ready().contains(&request.step) {
            return Ok(Failed::Left(setup));
        }
        let read = SetupVersion::of(&setup);
        setup
            .fail(request.step, why.clone())
            .map_err(AppError::from_domain)?;
        let unit = self.ports.unit.as_ref();
        let setup = kept_together(unit, self.recorded(setup, read, auditor)).await?;
        Ok(Failed::Now(setup, *tenant.organization_id()))
    }

    /// In one unit: the failed setup saved, while it is as it was read, and
    /// its record kept.
    async fn recorded(
        &self,
        mut setup: TenantSetup,
        read: SetupVersion,
        auditor: &RequestAuditor,
    ) -> Result<TenantSetup, AppError> {
        self.ports
            .setups
            .save_unchanged_since(&setup, read)
            .await
            .map_err(AppError::from_domain)?;
        auditor.dispatch(&setup.take_events()).await.or_internal()?;
        Ok(setup)
    }
}

impl Command for FailStepUseCase {
    type Caller = ();
    type Input = StepFailure<SetupStep>;
    type Output = Result<RunOutcome, AppError>;

    /// Fails the setup at `failure`'s step for its reason, and answers how
    /// the setup stands. A step no longer ready, because it is done or the
    /// setup failed already, is left as it is. A failure that lost its race
    /// to a sibling step's save is kept again at once over the setup read
    /// afresh, so it neither undoes that step's mark nor is undone by it.
    /// Records `tenant.infra_failed`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant or its setup is gone.
    /// - `AppError::Conflict` when the setup kept changing under every try.
    /// - `AppError::Internal` when a store or the audit fails.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        failure: StepFailure<SetupStep>,
    ) -> Result<RunOutcome, AppError> {
        let StepFailure { request, why } = failure;
        let why = &why;
        let auditor = &auditor.with_tenant(request.tenant_id);
        let failed =
            tried_on_fresh_reads(move || self.failed_afresh(request, why, auditor)).await?;
        let (setup, organization_id) = match failed {
            Failed::Left(setup) => return Ok(setup.outcome()),
            Failed::Now(setup, organization_id) => (setup, organization_id),
        };
        let progress = progress_of(&setup, organization_id, request.step, StepOutcome::Failed);
        self.ports.progress.on_progress(&progress).await;
        Ok(setup.outcome())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::setup::TenantSetupRow;

    use super::*;
    use crate::test_support::tenant::{
        FakeTenantSetupStore, FakeTenantStore, RecordingSetupProgress, test_tenant,
        test_tenant_apart,
    };
    use crate::test_support::{FakeEventDispatcher, PassThroughUnitOfWork, block_on, test_auditor};

    /// Arranges a sibling completion between reading and saving the failure.
    fn records_finishing_a_sibling(tenant: &Tenant) -> Arc<FakeTenantSetupStore> {
        let records = Arc::new(FakeTenantSetupStore::empty());
        block_on(records.save(&TenantSetup::begin(tenant).unwrap())).unwrap();
        records.changes_before_next_save(|row| {
            let mut setup = TenantSetup::reconstitute(row).unwrap();
            setup.finish(SetupStep::StartingRoles).unwrap();
            TenantSetupRow::from(&setup)
        });
        records
    }

    /// A step whose tries are spent fails the setup, goes on record for
    /// the operators with its reason, and tells the watchers it failed.
    #[test]
    fn a_step_out_of_tries_fails_the_setup() {
        let tenant = test_tenant_apart();
        let tenant_id = *tenant.id();
        let setups = Arc::new(FakeTenantSetupStore::empty());
        block_on(setups.save(&TenantSetup::begin(&tenant).unwrap())).unwrap();
        let progress = Arc::new(RecordingSetupProgress::default());
        let audit = Arc::new(FakeEventDispatcher::new());
        let fail = FailStepUseCase::new(FailStepPorts {
            setups: setups.clone(),
            tenants: Arc::new(FakeTenantStore::holding(tenant)),
            progress: progress.clone(),
            unit: Arc::new(PassThroughUnitOfWork),
        });
        let failure = StepFailure {
            request: StepRequest {
                tenant_id,
                step: SetupStep::Database,
            },
            why: UntrustedText::record("the database host did not answer"),
        };

        let outcome = block_on(fail.execute(&(), &test_auditor(audit.clone()), failure)).unwrap();

        assert_eq!(outcome, RunOutcome::Failed);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["tenant.infra_failed"]
        );
        let told = progress.told();
        assert_eq!(told[0].step_outcome, StepOutcome::Failed);
        assert!(told[0].failure_reason.is_some());
    }

    /// Starting roles finish while a signing-key failure is being saved.
    /// Retrying with the current setup preserves the completed roles and
    /// the failed key step, with one failure event.
    #[test]
    fn a_failure_racing_a_finished_step_keeps_both() {
        let tenant = test_tenant("acme", "acme.com");
        let tenant_id = *tenant.id();
        let setups = records_finishing_a_sibling(&tenant);
        let audit = Arc::new(FakeEventDispatcher::new());
        let fail = FailStepUseCase::new(FailStepPorts {
            setups: setups.clone(),
            tenants: Arc::new(FakeTenantStore::holding(tenant)),
            progress: Arc::new(RecordingSetupProgress::default()),
            unit: Arc::new(PassThroughUnitOfWork),
        });
        let failure = StepFailure {
            request: StepRequest {
                tenant_id,
                step: SetupStep::SigningKey,
            },
            why: UntrustedText::record("the key service did not answer"),
        };

        let outcome = block_on(fail.execute(&(), &test_auditor(audit.clone()), failure)).unwrap();

        let setup = setups.of(&tenant_id).unwrap();
        assert_eq!(outcome, RunOutcome::Failed);
        assert_eq!(setup.done(), [SetupStep::StartingRoles]);
        assert_eq!(
            setup.failure().map(|(step, _)| step),
            Some(SetupStep::SigningKey)
        );
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["tenant.infra_failed"]
        );
    }
}
