//! Get evaluation: one evaluation of a workflow and what each case came
//! to, for someone who may view workflows, with what is above their
//! clearance withheld.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::evaluation::view::EvaluationView;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{EvaluationId, WorkflowId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::EvaluationStore;
use crate::use_case::Query;
use crate::use_cases::workflows::evaluations::lookup::existing_evaluation;

/// Which evaluation to read.
pub struct GetRequest {
    /// The workflow it tries.
    pub workflow_id: WorkflowId,
    /// The evaluation read.
    pub evaluation_id: EvaluationId,
}

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Keeps the evaluations.
    pub evaluations: Arc<dyn EvaluationStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads evaluations.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = GetRequest;
    type Output = Result<EvaluationView<ResolvedTenant>, AppError>;

    /// The evaluation `request` names, as the caller may read it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::NotFound` when the tenant has no such evaluation of
    ///   that workflow, or it was cleared.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: GetRequest,
    ) -> Result<EvaluationView<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let evaluation = existing_evaluation(
            self.ports.evaluations.as_ref(),
            &ctx.tenant(),
            &request.workflow_id,
            &request.evaluation_id,
        )
        .await?;
        evaluation.viewed_by(control).map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::evaluation::set::PublishGate;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeEvaluationStore, draft_by, evaluation_of, parcel_case, person, set_for, tidy_step,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Sam reads Ann's evaluation through its own workflow; asked through
    /// another workflow, it is not found.
    #[test]
    fn an_evaluation_is_read_through_its_workflow() {
        let ann = person("ann@corp.test");
        let draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
        let set = set_for(&draft, &ann, vec![parcel_case("late")], PublishGate::Off);
        let evaluation = evaluation_of(&set, &draft, &ann);
        let use_case = GetUseCase::new(GetPorts {
            evaluations: Arc::new(FakeEvaluationStore::holding(&evaluation)),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Workflows(WorkflowAction::View),
            ])),
        });
        let asked = |workflow_id| GetRequest {
            workflow_id,
            evaluation_id: *evaluation.id(),
        };

        let shown = block_on(use_case.execute(&test_ctx(), asked(*draft.id()))).unwrap();
        let elsewhere = block_on(use_case.execute(&test_ctx(), asked(WorkflowId::new())));

        assert_eq!(shown.id(), evaluation.id());
        assert_eq!(shown.cases().count(), 1);
        assert!(matches!(elsewhere, Err(AppError::NotFound(_))));
    }
}
