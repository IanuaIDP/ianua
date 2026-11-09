//! Next draft: a person starts the next version of a workflow from its
//! latest one.
//!
//! The version in service keeps running unchanged. The new draft copies its
//! steps, and storage keeps each version number once, so two drafts made
//! from the same version cannot both be kept.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::WorkflowStore;
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::latest_version;

/// The ports [`NextDraftUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct NextDraftPorts {
    /// Keeps the versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Drafts the next version of workflows.
pub struct NextDraftUseCase {
    ports: NextDraftPorts,
}

impl NextDraftUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: NextDraftPorts) -> Self {
        Self { ports }
    }
}

impl Command for NextDraftUseCase {
    type Caller = CallerContext;
    type Input = WorkflowId;
    type Output = Result<Workflow<ResolvedTenant>, AppError>;

    /// Drafts the version after the latest one of `workflow_id`, designed by
    /// the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such workflow.
    /// - `AppError::Forbidden` when the caller may not create workflows.
    /// - `AppError::Conflict` when the latest version is still a draft, no
    ///   number is left, or someone drafted the same number meanwhile.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        workflow_id: WorkflowId,
    ) -> Result<Workflow<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let latest =
            latest_version(self.ports.workflows.as_ref(), &ctx.tenant(), &workflow_id).await?;
        let mut draft = latest
            .next_draft(&WorkflowControl::new(&authority))
            .map_err(AppError::from_domain)?;
        self.ports
            .workflows
            .insert(&ctx.tenant(), &draft)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), draft.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(draft)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::WorkflowStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{FakeWorkflowStore, draft_by, published_by, tidy_step};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The versions a next draft reads and writes, and what it recorded.
    struct Drafting {
        workflows: Arc<FakeWorkflowStore>,
        sink: Arc<FakeEventDispatcher>,
        id: WorkflowId,
    }

    impl Drafting {
        fn of(workflow: &Workflow<ResolvedTenant>) -> Self {
            Self {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(workflow))),
                sink: Arc::new(FakeEventDispatcher::new()),
                id: *workflow.id(),
            }
        }

        fn draft(
            &self,
            authorities: FakeTenantAuthorities,
        ) -> Result<Workflow<ResolvedTenant>, AppError> {
            let use_case = NextDraftUseCase::new(NextDraftPorts {
                workflows: self.workflows.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), self.id))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn draft() -> Workflow<ResolvedTenant> {
        draft_by(&caller_person(), vec![tidy_step("tidy")], Vec::new())
    }

    fn creator() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Create)])
    }

    /// Version 1 of Ann's workflow is in service. She drafts version 2. It
    /// is kept as a draft beside version 1, which stays in service, and the
    /// draft is recorded.
    #[test]
    fn the_next_version_is_drafted_beside_the_one_in_service() {
        let drafting = Drafting::of(&published_by(&caller_person(), draft()));

        let next = drafting.draft(creator()).unwrap();

        assert_eq!(next.version(), 2);
        let kept = drafting.workflows.stored(&drafting.id, 2).unwrap();
        assert_eq!(kept.status(), WorkflowStatus::Draft);
        let first = drafting.workflows.stored(&drafting.id, 1).unwrap();
        assert_eq!(first.status(), WorkflowStatus::Published);
        assert_eq!(drafting.records(), ["workflows.version_drafted"]);
    }

    /// An existing latest draft prevents creating another draft. The conflict
    /// leaves one stored version and records no audit event.
    #[test]
    fn a_draft_is_not_followed_by_another_draft() {
        let drafting = Drafting::of(&draft());

        let result = drafting.draft(creator());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(drafting.workflows.count(), 1);
        assert!(drafting.records().is_empty());
    }

    /// A workflow viewer cannot draft the next version; only the original
    /// version remains saved.
    #[test]
    fn a_caller_who_may_not_create_workflows_is_refused() {
        let drafting = Drafting::of(&published_by(&caller_person(), draft()));
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = drafting.draft(sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(drafting.workflows.count(), 1);
    }

    /// A signed-out session cannot draft the next workflow version.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let drafting = Drafting::of(&published_by(&caller_person(), draft()));

        let result = drafting.draft(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
