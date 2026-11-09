//! List evaluations: a workflow's latest evaluations, newest first, for
//! someone who may view workflows. The first is the one its publishing
//! gate reads.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::evaluation::view::EvaluationView;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::EvaluationStore;
use crate::use_case::Query;

/// The most evaluations one listing shows. Older ones are kept until the
/// purge takes them, for nothing reads them but the audit trail's records.
pub(crate) const LISTED_EVALUATIONS: u32 = 20;

/// Which workflow's evaluations to list.
pub struct ListRequest {
    /// The workflow whose evaluations are listed.
    pub workflow_id: WorkflowId,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the evaluations.
    pub evaluations: Arc<dyn EvaluationStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists workflows' evaluations.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Vec<EvaluationView<ResolvedTenant>>, AppError>;

    /// The latest [`LISTED_EVALUATIONS`] evaluations of
    /// `request.workflow_id`, newest first, as the caller may read them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Vec<EvaluationView<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .evaluations
            .latest_of(&ctx.tenant(), &request.workflow_id, LISTED_EVALUATIONS)
            .await
            .or_internal()?
            .into_iter()
            .map(|evaluation| evaluation.viewed_by(control).map_err(AppError::from_domain))
            .collect()
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

    /// Ann evaluated her draft twice. Both are listed, the newer first.
    #[test]
    fn evaluations_are_listed_newest_first() {
        let ann = person("ann@corp.test");
        let draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
        let set = set_for(&draft, &ann, vec![parcel_case("late")], PublishGate::Off);
        let older = evaluation_of(&set, &draft, &ann);
        let newer = evaluation_of(&set, &draft, &ann);
        let store = FakeEvaluationStore::holding(&older);
        block_on(store.insert(&test_ctx().tenant(), &newer)).unwrap();
        let use_case = ListUseCase::new(ListPorts {
            evaluations: Arc::new(store),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Workflows(WorkflowAction::View),
            ])),
        });
        let request = ListRequest {
            workflow_id: *draft.id(),
        };

        let listed = block_on(use_case.execute(&test_ctx(), request)).unwrap();

        let ids: Vec<_> = listed.iter().map(|view| *view.id()).collect();
        assert_eq!(ids, [*newer.id(), *older.id()]);
    }
}
