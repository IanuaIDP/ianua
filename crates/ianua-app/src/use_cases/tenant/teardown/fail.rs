//! Failing a deleted tenant's teardown at a step whose tries are spent: the
//! teardown stops, and the failure goes on record for the operators.

use std::sync::Arc;

use ianua_domain::domains::tenant::teardown::{TeardownStep, TenantTeardown};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::model::steps::RunOutcome;
use ianua_domain::types::UntrustedText;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::{TeardownVersion, TenantTeardownStore};
use crate::services::fresh_reads::tried_on_fresh_reads;
use crate::services::kept_together::kept_together;
use crate::use_case::Command;
use crate::use_cases::scheduling::{StepFailure, StepRequest};
use crate::use_cases::tenant::teardown::lookup::existing_teardown;

/// The ports [`FailStepUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct FailStepPorts {
    /// Loads and saves the terminal failure of a removal step.
    pub teardowns: Arc<dyn TenantTeardownStore>,
    /// Keeps the failure and its record together.
    pub unit: Arc<dyn UnitOfWork>,
}

/// Fails a deleted tenant's teardown at a step whose tries are spent.
pub struct FailStepUseCase {
    ports: FailStepPorts,
}

impl FailStepUseCase {
    /// A use case over `ports`.
    #[must_use]
    pub fn new(ports: FailStepPorts) -> Self {
        Self { ports }
    }

    /// Reads the teardown afresh and, while the step is still ready, fails
    /// it there for `why` in one unit. A step no longer ready is left as it
    /// is, and the teardown answered as it stands.
    ///
    /// # Errors
    ///
    /// `AppError::Conflict` when a step saved the teardown since this read;
    /// the unit kept nothing.
    async fn failed_afresh(
        &self,
        request: StepRequest<TeardownStep>,
        why: &UntrustedText,
        auditor: &RequestAuditor,
    ) -> Result<TenantTeardown, AppError> {
        let mut teardown =
            existing_teardown(self.ports.teardowns.as_ref(), &request.tenant_id).await?;
        if !teardown.ready().contains(&request.step) {
            return Ok(teardown);
        }
        let read = TeardownVersion::of(&teardown);
        teardown
            .fail(request.step, why.clone())
            .map_err(AppError::from_domain)?;
        kept_together(
            self.ports.unit.as_ref(),
            self.recorded(teardown, read, auditor),
        )
        .await
    }

    /// In one unit: the failed teardown saved, while it is as it was read,
    /// and its record kept.
    async fn recorded(
        &self,
        mut teardown: TenantTeardown,
        read: TeardownVersion,
        auditor: &RequestAuditor,
    ) -> Result<TenantTeardown, AppError> {
        self.ports
            .teardowns
            .save_unchanged_since(&teardown, read)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch(&teardown.take_events())
            .await
            .or_internal()?;
        Ok(teardown)
    }
}

impl Command for FailStepUseCase {
    type Caller = ();
    type Input = StepFailure<TeardownStep>;
    type Output = Result<RunOutcome, AppError>;

    /// Fails the teardown at `failure`'s step for its reason, and answers
    /// how the teardown stands. A step no longer ready, because it is done
    /// or the teardown failed already, is left as it is. A failure that
    /// lost its race to a sibling step's save is kept again at once over
    /// the teardown read afresh. Records `tenant.teardown_failed`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the teardown is gone.
    /// - `AppError::Conflict` when the teardown kept changing under every
    ///   try.
    /// - `AppError::Internal` when a store or the audit fails.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        failure: StepFailure<TeardownStep>,
    ) -> Result<RunOutcome, AppError> {
        let StepFailure { request, why } = failure;
        let why = &why;
        let auditor = &auditor.with_tenant(request.tenant_id);
        let teardown =
            tried_on_fresh_reads(move || self.failed_afresh(request, why, auditor)).await?;
        Ok(teardown.outcome())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::teardown::TenantTeardownRow;

    use super::*;
    use crate::test_support::tenant::{
        FakeTenantTeardownStore, test_tenant_deleted, test_tenant_deleted_apart,
    };
    use crate::test_support::{FakeEventDispatcher, PassThroughUnitOfWork, block_on, test_auditor};

    /// Arranges a sibling completion between reading and saving the failure.
    fn records_finishing_a_sibling(tenant: &Tenant) -> Arc<FakeTenantTeardownStore> {
        let records = Arc::new(FakeTenantTeardownStore::empty());
        block_on(records.save(&TenantTeardown::begin(tenant).unwrap())).unwrap();
        records.changes_before_next_save(|row| {
            let mut teardown = TenantTeardown::reconstitute(row).unwrap();
            teardown.finish(TeardownStep::AuditTrail).unwrap();
            TenantTeardownRow::from(&teardown)
        });
        records
    }

    /// A step whose tries are spent fails the teardown, and goes on record
    /// for the operators with its reason.
    #[test]
    fn a_step_out_of_tries_fails_the_teardown() {
        let tenant = test_tenant_deleted();
        let tenant_id = *tenant.id();
        let teardowns = Arc::new(FakeTenantTeardownStore::empty());
        block_on(teardowns.save(&TenantTeardown::begin(&tenant).unwrap())).unwrap();
        let audit = Arc::new(FakeEventDispatcher::new());
        let fail = FailStepUseCase::new(FailStepPorts {
            teardowns: teardowns.clone(),
            unit: Arc::new(PassThroughUnitOfWork),
        });
        let failure = StepFailure {
            request: StepRequest {
                tenant_id,
                step: TeardownStep::Data,
            },
            why: UntrustedText::record("the database host did not answer"),
        };

        let outcome = block_on(fail.execute(&(), &test_auditor(audit.clone()), failure)).unwrap();

        assert_eq!(outcome, RunOutcome::Failed);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["tenant.teardown_failed"]
        );
        let failed = teardowns.of(&tenant_id).unwrap();
        let (step, why) = failed.failure().unwrap();
        assert_eq!(step, TeardownStep::Data);
        assert_eq!(why.as_str(), "the database host did not answer");
    }

    /// The audit-trail step finishes while a data-step failure is being saved.
    /// Retrying with the current teardown preserves the completion and the
    /// failed data step, with one failure event.
    #[test]
    fn a_failure_racing_a_finished_step_keeps_both() {
        let tenant = test_tenant_deleted_apart();
        let tenant_id = *tenant.id();
        let teardowns = records_finishing_a_sibling(&tenant);
        let audit = Arc::new(FakeEventDispatcher::new());
        let fail = FailStepUseCase::new(FailStepPorts {
            teardowns: teardowns.clone(),
            unit: Arc::new(PassThroughUnitOfWork),
        });
        let failure = StepFailure {
            request: StepRequest {
                tenant_id,
                step: TeardownStep::Data,
            },
            why: UntrustedText::record("the database host did not answer"),
        };

        let outcome = block_on(fail.execute(&(), &test_auditor(audit.clone()), failure)).unwrap();

        let teardown = teardowns.of(&tenant_id).unwrap();
        assert_eq!(outcome, RunOutcome::Failed);
        assert_eq!(teardown.done(), [TeardownStep::AuditTrail]);
        assert_eq!(
            teardown.failure().map(|(step, _)| step),
            Some(TeardownStep::Data)
        );
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["tenant.teardown_failed"]
        );
    }
}
