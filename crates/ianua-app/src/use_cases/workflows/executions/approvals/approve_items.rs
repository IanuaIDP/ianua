//! Approve items: a person approves every item a loop will act on, having
//! opened every page of them.
//!
//! The domain decides who may approve, as for an approval step, and counts
//! the yes only once every item of the list fixed at the approval's opening
//! was on a page the approver opened, which the pages store says. The yes
//! that completes the approval starts the loop's first passes, kept with
//! the run in the request's unit of work.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::AnsweredCode;
use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::execution::{ItemsSeen, LoopMoves, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::WorkflowExecutionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrNotFound};
use crate::ports::workflows::{
    ApprovalPages, ExecutionVersion, ItemsViewer, WorkflowExecutionStore,
};
use crate::services::authentication::approver_presence::ApproverPresence;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::approvals::approving::step_approver;
use crate::use_cases::workflows::executions::approvals::decided::ExecutionDecided;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::lookup::existing_execution;

/// One person's approval of every item of a loop.
pub struct ApproveItemsRequest {
    /// The run whose loop asks.
    pub execution_id: WorkflowExecutionId,
    /// The loop step.
    pub step: NodeKey,
    /// A fresh second-factor code, needed when the loop's action may be
    /// high risk.
    pub mfa_code: Option<String>,
}

/// The ports [`ApproveItemsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ApproveItemsPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// The pages of items each person opened.
    pub pages: Arc<dyn ApprovalPages>,
    /// Drives the run and its new passes when their next steps fall due.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end.
    pub run_stops: StopPorts,
    /// Requires a fresh second factor from the approver of a high-risk
    /// loop.
    pub presence: Arc<ApproverPresence>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Approves every item of a loop.
pub struct ApproveItemsUseCase {
    ports: ApproveItemsPorts,
}

impl ApproveItemsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ApproveItemsPorts) -> Self {
        Self { ports }
    }
}

impl Command for ApproveItemsUseCase {
    type Caller = CallerContext;
    type Input = ApproveItemsRequest;
    type Output = Result<ExecutionDecided, AppError>;

    /// Approves every item of the loop `request.step` for the person `ctx`
    /// names. The first of two approvals is recorded and the loop keeps
    /// waiting; the approval that completes it starts the loop's passes.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing execution or a loop asking nobody.
    /// - `AppError::StepUpRequired` or `AccountLocked` for failed high-risk presence checks.
    /// - `AppError::Forbidden` without rights/clearance, for the person acted for, an author on a high-risk loop, or the first approver.
    /// - `AppError::Conflict` before every page was opened, after the list changed, on expiry or a concurrent change.
    /// - `AppError::Domain` for a closed window; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ApproveItemsRequest,
    ) -> Result<ExecutionDecided, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Approve)
            .map_err(AppError::from_domain)?;
        let mut execution = existing_execution(
            self.ports.executions.as_ref(),
            &tenant,
            &request.execution_id,
        )
        .await?;
        let read = ExecutionVersion::of(&execution);
        let answered = self.presence_answer(ctx, &execution, &request).await?;
        let approver = step_approver(&authority, answered.as_ref())?;
        let viewer = ItemsViewer {
            execution_id: request.execution_id,
            step: request.step,
            person: control.by().person().clone(),
        };
        let seen = self.pages_seen(&tenant, &viewer).await?;
        let moves = execution
            .approve_items(&viewer.step, &approver, &seen)
            .map_err(AppError::from_domain)?;
        self.keep(&tenant, auditor, Kept::Changed(&execution, read), moves)
            .await?;
        Ok(ExecutionDecided::of(&execution))
    }
}

impl ApproveItemsUseCase {
    /// Every page of the items `viewer` opened in the tenant.
    async fn pages_seen(
        &self,
        tenant: &ScopedTenant,
        viewer: &ItemsViewer,
    ) -> Result<ItemsSeen, AppError> {
        self.ports
            .pages
            .seen_by(tenant, viewer)
            .await
            .map_err(AppError::from_domain)
    }

    /// Keeps the run `kept` names with the passes its approval started.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        kept: Kept<'_>,
        moves: LoopMoves<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        keeping.keep_loop(tenant, auditor, kept, moves).await
    }

    /// The caller's fresh second-factor answer, when the loop they approve
    /// acts in a way that may be high risk.
    async fn presence_answer(
        &self,
        ctx: &CallerContext,
        execution: &WorkflowExecution<ResolvedTenant>,
        request: &ApproveItemsRequest,
    ) -> Result<Option<AnsweredCode>, AppError> {
        let asked = execution
            .asked_at(&request.step)
            .or_not_found(message!("workflows-approval-step", "approval step"))?;
        if !asked.needs_presence() {
            return Ok(None);
        }
        let answered = self
            .ports
            .presence
            .require(ctx, request.mfa_code.as_deref())
            .await?;
        Ok(Some(answered))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::execution::step::StepState;
    use ianua_domain::types::{ActionClass, Human};

    use super::*;
    use crate::listing::{Limit, PageRequest};
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::agents::PRESENT_CODE;
    use crate::test_support::workflows::{
        FakeApprovalPages, FakeWorkflowExecutionStore, QueuedWakeups, caller_presence,
        loop_asking_for_every_item, person, step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::workflows::executions::approvals::show_items::{
        ShowItemsPorts, ShowItemsRequest, ShowItemsUseCase,
    };

    const APPROVES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Approve)];

    /// The stores approving a loop's items writes to, and what it recorded.
    struct Deciding {
        executions: Arc<FakeWorkflowExecutionStore>,
        pages: Arc<FakeApprovalPages>,
        wakeups: Arc<QueuedWakeups>,
        sink: Arc<FakeEventDispatcher>,
        execution_id: WorkflowExecutionId,
    }

    impl Deciding {
        fn over(execution: &WorkflowExecution<ResolvedTenant>) -> Self {
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::holding(execution)),
                pages: Arc::new(FakeApprovalPages::none()),
                wakeups: Arc::new(QueuedWakeups::none()),
                sink: Arc::new(FakeEventDispatcher::new()),
                execution_id: *execution.id(),
            }
        }

        /// The caller opens pages of two items until `pages` were opened.
        fn open(&self, pages: usize) {
            let use_case = ShowItemsUseCase::new(ShowItemsPorts {
                executions: self.executions.clone(),
                pages: self.pages.clone(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&APPROVES)),
            });
            let auditor = test_auditor(self.sink.clone());
            let mut page = Some(PageRequest::first(Limit::new(2).unwrap()));
            for _ in 0..pages {
                let Some(asked) = page else {
                    return;
                };
                let request = ShowItemsRequest {
                    execution_id: self.execution_id,
                    step: step("each"),
                    page: asked.clone(),
                };
                let shown = block_on(use_case.execute(&test_ctx(), &auditor, request)).unwrap();
                page = asked.following(&shown.items);
            }
        }

        fn approve(&self, code: Option<&str>) -> Result<ExecutionDecided, AppError> {
            let use_case = ApproveItemsUseCase::new(ApproveItemsPorts {
                executions: self.executions.clone(),
                pages: self.pages.clone(),
                wakeups: self.wakeups.wakeups(),
                presence: caller_presence(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&APPROVES)),
                ..ApproveItemsPorts::fakes()
            });
            let request = ApproveItemsRequest {
                execution_id: self.execution_id,
                step: step("each"),
                mfa_code: code.map(str::to_owned),
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        fn stored(&self) -> WorkflowExecution<ResolvedTenant> {
            self.executions.stored(&self.execution_id).unwrap()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn ann() -> Human {
        person("ann@corp.test")
    }

    /// Bob opens the first of two pages of Ann's three issues and says yes.
    /// It is refused, nothing is recorded and no pass starts.
    #[test]
    fn a_yes_before_every_page_was_opened_is_refused() {
        let deciding = Deciding::over(&loop_asking_for_every_item(
            &ann(),
            &["a", "b", "c"],
            ActionClass::Communicate,
        ));
        deciding.open(1);

        let result = deciding.approve(None);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(deciding.records().is_empty());
        assert!(
            deciding
                .executions
                .passes_of(&deciding.execution_id)
                .is_empty()
        );
    }

    /// Bob opens both pages and says yes. The approval is recorded, every
    /// pass is kept with the run and, only tidying its issue, ends at once,
    /// so the loop succeeds.
    #[test]
    fn a_yes_after_every_page_starts_the_passes() {
        let deciding = Deciding::over(&loop_asking_for_every_item(
            &ann(),
            &["a", "b", "c"],
            ActionClass::Communicate,
        ));
        deciding.open(2);

        deciding.approve(None).unwrap();

        assert!(
            deciding
                .records()
                .contains(&"workflows.approval_granted".to_owned())
        );
        assert_eq!(
            deciding.executions.passes_of(&deciding.execution_id).len(),
            3
        );
        assert!(matches!(
            deciding.stored().step(&step("each")),
            Some(StepState::Succeeded { .. })
        ));
    }

    /// Approving every item of a payment without a second-factor code asks
    /// for a step-up and records nothing.
    #[test]
    fn a_high_risk_loop_without_a_code_asks_for_a_step_up() {
        let deciding = Deciding::over(&loop_asking_for_every_item(
            &ann(),
            &["a", "b"],
            ActionClass::Financial,
        ));
        deciding.open(1);

        let result = deciding.approve(None);

        assert!(matches!(result, Err(AppError::StepUpRequired)));
        assert!(deciding.records().is_empty());
    }

    /// Bob answers his code and approves every item of a payment. His is
    /// the first of two approvals: it is recorded, and no pass starts.
    #[test]
    fn a_present_approver_gives_the_first_of_two_approvals_of_every_item() {
        let deciding = Deciding::over(&loop_asking_for_every_item(
            &ann(),
            &["a", "b"],
            ActionClass::Financial,
        ));
        deciding.open(1);

        deciding.approve(Some(PRESENT_CODE)).unwrap();

        assert_eq!(deciding.records(), ["workflows.approval_granted"]);
        assert!(
            deciding
                .executions
                .passes_of(&deciding.execution_id)
                .is_empty()
        );
    }
}
