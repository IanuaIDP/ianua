//! Get evaluation set: a workflow's sample cases and its publishing gate,
//! for someone who may view workflows, with each case above their
//! clearance shown by name only.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::evaluation::view::SetView;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::EvaluationSetStore;
use crate::use_case::Query;
use crate::use_cases::workflows::evaluations::lookup::existing_set;

/// Which workflow's set to read.
pub struct GetSetRequest {
    /// The workflow whose set is read.
    pub workflow_id: WorkflowId,
}

/// The ports [`GetSetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetSetPorts {
    /// Keeps the sets.
    pub evaluation_sets: Arc<dyn EvaluationSetStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads workflows' evaluation sets.
pub struct GetSetUseCase {
    ports: GetSetPorts,
}

impl GetSetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetSetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetSetUseCase {
    type Caller = CallerContext;
    type Input = GetSetRequest;
    type Output = Result<SetView<ResolvedTenant>, AppError>;

    /// The set of `request.workflow_id`, as the caller may read it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::NotFound` when no set was saved for the workflow.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: GetSetRequest,
    ) -> Result<SetView<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let set = existing_set(
            self.ports.evaluation_sets.as_ref(),
            &ctx.tenant(),
            &request.workflow_id,
        )
        .await?;
        set.viewed_by(control).map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::evaluation::set::PublishGate;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeEvaluationSetStore, draft_by, parcel_case, person, set_for, tidy_step,
    };
    use crate::test_support::{block_on, test_ctx};

    fn read(holds: &[SystemPermission]) -> Result<SetView<ResolvedTenant>, AppError> {
        let ann = person("ann@corp.test");
        let draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
        let set = set_for(
            &draft,
            &ann,
            vec![parcel_case("late")],
            PublishGate::MustPass,
        );
        let use_case = GetSetUseCase::new(GetSetPorts {
            evaluation_sets: Arc::new(FakeEvaluationSetStore::holding(&set)),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
        });
        let request = GetSetRequest {
            workflow_id: *draft.id(),
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    /// Someone who may view workflows reads the cases and the gate; someone
    /// without the right is refused before anything is read.
    #[test]
    fn a_viewer_reads_the_set() {
        let views = [SystemPermission::Workflows(WorkflowAction::View)];

        let shown = read(&views).unwrap();
        let refused = read(&[]);

        assert_eq!(shown.cases().count(), 1);
        assert_eq!(shown.gate(), PublishGate::MustPass);
        assert!(matches!(refused, Err(AppError::Forbidden(_))));
    }
}
