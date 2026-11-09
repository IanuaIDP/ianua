//! End overdue evaluations: end every tenant's evaluations still running
//! past their deadline, every open case not run.
//!
//! An evaluation's own looks end it at its deadline. This sweep catches
//! the one whose look job was lost or failed every try, so no evaluation
//! stays running for ever and counted against the plan. Each is written
//! only over the copy read, so a look that raced the sweep wins and the
//! sweep leaves it; ending one is recorded, as its look would record it.
//!
//! It runs on a schedule, outside any request, for nobody. Running it late
//! or twice ends nothing twice: an ended evaluation is not overdue.

use std::sync::Arc;

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::workflows::evaluation::run::Evaluation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::model::aggregate::Aggregate;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::TenantStore;
use crate::ports::workflows::EvaluationStore;
use crate::services::kept_together::kept_together;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The most overdue evaluations of one tenant one round ends.
const ENDED_AT_ONCE: u32 = 100;

/// What one round across every tenant did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OverdueReport {
    /// Evaluations ended across every tenant.
    pub ended: u64,
    /// Tenants whose evaluations could not be ended this time.
    pub unswept: u64,
}

/// The ports [`EndOverdueUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EndOverduePorts {
    /// Keeps the evaluations.
    pub evaluations: Arc<dyn EvaluationStore>,
    /// Lists the tenants whose evaluations are swept.
    pub tenants: Arc<dyn TenantStore>,
    /// Keeps each evaluation ended with its record.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Ends every tenant's evaluations past their deadline.
pub struct EndOverdueUseCase {
    ports: EndOverduePorts,
}

impl EndOverdueUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EndOverduePorts) -> Self {
        Self { ports }
    }

    /// The evaluations of `tenant`, read as `scoped`, overdue at `now`, a
    /// batch at a time;
    /// `None`, warned of, when they could not be read.
    async fn overdue(
        &self,
        tenant: &Tenant,
        scoped: &ScopedTenant,
        now: OffsetDateTime,
    ) -> Option<Vec<Evaluation<ResolvedTenant>>> {
        match self
            .ports
            .evaluations
            .overdue(scoped, now, ENDED_AT_ONCE)
            .await
        {
            Ok(overdue) => Some(overdue),
            Err(error) => {
                tracing::warn!(tenant_id = %tenant.id(), %error, "overdue evaluations not read");
                None
            }
        }
    }

    /// Ends `tenant`'s evaluations overdue at `now` and says how many
    /// ended; `None` when they could not be read. One that changed
    /// meanwhile is left to the look that changed it.
    async fn ended(
        &self,
        tenant: &Tenant,
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Option<u64> {
        let scoped = ScopedTenant::for_background(*tenant.id());
        let auditor = auditor.with_tenant(*tenant.id());
        let overdue = self.overdue(tenant, &scoped, now).await?;
        let mut ended = 0_u64;
        for mut evaluation in overdue {
            let kept = kept_together(
                self.ports.unit_of_work.as_ref(),
                self.end(&scoped, &auditor, &mut evaluation),
            )
            .await;
            match kept {
                Ok(()) => ended = ended.saturating_add(1),
                Err(error) => {
                    tracing::warn!(tenant_id = %tenant.id(), %error, "overdue evaluation not ended");
                }
            }
        }
        Some(ended)
    }

    /// Ends `evaluation` and keeps it over the copy read, with its record.
    async fn end(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        evaluation: &mut Evaluation<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let read_at = Aggregate::updated_at(evaluation);
        evaluation.give_up().map_err(AppError::from_domain)?;
        self.ports
            .evaluations
            .save_unchanged_since(tenant, evaluation, read_at)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch(&evaluation.take_events(tenant))
            .await
            .or_internal()
    }
}

impl Command for EndOverdueUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<OverdueReport, AppError>;

    /// Ends every tenant's evaluations still running past their deadline,
    /// and says how many ended.
    ///
    /// One tenant whose evaluations cannot be read does not stop the
    /// others; it is counted as unswept and tried again next time.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the tenant list cannot be read.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<OverdueReport, AppError> {
        let now = clock::now();
        let mut report = OverdueReport::default();
        let mut tenants = TenantBatches::over(self.ports.tenants.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                report = counted(report, self.ended(tenant, auditor, now).await);
            }
        }
        Ok(report)
    }
}

/// `report` with one more tenant counted: how many ended, or that none
/// could be read.
fn counted(report: OverdueReport, ended: Option<u64>) -> OverdueReport {
    let Some(ended) = ended else {
        return OverdueReport {
            unswept: report.unswept.saturating_add(1),
            ..report
        };
    };
    OverdueReport {
        ended: report.ended.saturating_add(ended),
        ..report
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::evaluation::outcome::Verdict;
    use ianua_domain::domains::workflows::evaluation::run::{EVALUATION_TIME, EvaluationState};
    use ianua_domain::domains::workflows::evaluation::set::PublishGate;
    use time::Duration;

    use super::*;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::workflows::{
        FakeEvaluationStore, draft_by, evaluation_of, parcel_case, person, set_for, tidy_step,
    };
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    /// The sweep over the evaluations in `evaluations`, for the test's
    /// tenant.
    fn sweep_over(evaluations: &Arc<FakeEvaluationStore>) -> EndOverdueUseCase {
        EndOverdueUseCase::new(EndOverduePorts {
            evaluations: evaluations.clone(),
            tenants: Arc::new(FakeTenantStore::holding_all(vec![test_tenant_for_ctx()])),
            unit_of_work: Arc::new(RecordingUnitOfWork::default()),
        })
    }

    /// Ann's evaluation started two hours ago and its looks were lost. The
    /// sweep ends it, its case not run, and records that it ended; one
    /// started now is left running.
    #[test]
    fn an_evaluation_past_its_deadline_is_ended() {
        let ann = person("ann@corp.test");
        let draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
        let set = set_for(&draft, &ann, vec![parcel_case("late")], PublishGate::Off);
        let stale = {
            let _then =
                clock::freeze(clock::now().saturating_sub(EVALUATION_TIME + Duration::hours(1)));
            evaluation_of(&set, &draft, &ann)
        };
        let fresh = evaluation_of(&set, &draft, &ann);
        let evaluations = Arc::new(FakeEvaluationStore::holding(&stale));
        block_on(evaluations.insert(&test_ctx().tenant(), &fresh)).unwrap();
        let sink = Arc::new(FakeEventDispatcher::new());

        let report =
            block_on(sweep_over(&evaluations).execute(&(), &test_auditor(sink.clone()), ()))
                .unwrap();

        let state_of = |evaluation: &Evaluation<ResolvedTenant>| {
            evaluations.stored(evaluation.id()).unwrap().state()
        };
        assert_eq!(report.ended, 1);
        assert_eq!(
            (state_of(&stale), state_of(&fresh)),
            (
                EvaluationState::Ended(Verdict::Failed),
                EvaluationState::Running
            )
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["workflows.evaluation_ended"]
        );
    }
}
