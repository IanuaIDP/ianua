//! Start evaluation: a person tries a workflow's latest version, its draft
//! before it is published, against every case of its set.
//!
//! Only someone who may edit and run workflows starts one, and the
//! tenant's plan caps how many run at once. The evaluation and the job for
//! its first look are kept in one unit of work with its record, so no
//! evaluation waits on a look nobody will make. Each case then runs as a
//! test run, so nothing outside changes.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::evaluation::run::Evaluation;
use ianua_domain::domains::workflows::evaluation::view::EvaluationView;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{EvaluationSetStore, EvaluationStore, WorkflowStore};
use crate::services::kept_together::kept_together;
use crate::use_case::Command;
use crate::use_cases::workflows::evaluations::lookup::existing_set;
use crate::use_cases::workflows::evaluations::run::Evaluations;
use crate::use_cases::workflows::lookup::designed_version;

/// Which workflow to evaluate.
pub struct StartRequest {
    /// The workflow whose latest version is tried.
    pub workflow_id: WorkflowId,
}

/// The ports [`StartUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartPorts {
    /// The versions, for the latest one.
    pub workflows: Arc<dyn WorkflowStore>,
    /// The sets, for the cases tried.
    pub evaluation_sets: Arc<dyn EvaluationSetStore>,
    /// Keeps the evaluations.
    pub evaluations: Arc<dyn EvaluationStore>,
    /// Queues an evaluation's first look.
    pub looks: Evaluations,
    /// Checks the plan's limit of evaluations running at once.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Keeps the evaluation, its first look and its record all or nothing.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Starts evaluations of workflows.
pub struct StartUseCase {
    ports: StartPorts,
}

impl StartUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartPorts) -> Self {
        Self { ports }
    }

    /// Checks the plan's limit and keeps `evaluation`, its first look and
    /// its record, for the person `ctx` names.
    async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        evaluation: &mut Evaluation<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &tenant, ResourceKind::RunningEvaluations)
            .await
            .map_err(AppError::from_domain)?;
        self.ports
            .evaluations
            .insert(&tenant, evaluation)
            .await
            .or_internal()?;
        self.ports
            .looks
            .look_at(&tenant, evaluation.id(), clock::now())
            .await?;
        auditor
            .dispatch_by(&ctx.actor(), evaluation.take_events(&tenant))
            .await
            .or_internal()
    }
}

impl Command for StartUseCase {
    type Caller = CallerContext;
    type Input = StartRequest;
    type Output = Result<EvaluationView<ResolvedTenant>, AppError>;

    /// Starts an evaluation of the latest version of `request.workflow_id`
    /// against its set, for the person `ctx` names, queues its first look,
    /// and hands it back as they may read it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing workflow or set.
    /// - `AppError::Forbidden` without edit and run rights, or at the plan's limit of evaluations running at once.
    /// - `AppError::Conflict` for an archived latest version; `Domain` for a set with no case.
    /// - `AppError::Internal` on persistence, queue or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: StartRequest,
    ) -> Result<EvaluationView<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        ensure_may_evaluate(&control)?;
        let workflow = designed_version(
            self.ports.workflows.as_ref(),
            &tenant,
            &request.workflow_id,
            None,
        )
        .await?;
        let set = existing_set(
            self.ports.evaluation_sets.as_ref(),
            &tenant,
            &request.workflow_id,
        )
        .await?;
        let mut evaluation =
            Evaluation::start(&set, &workflow, &control).map_err(AppError::from_domain)?;
        kept_together(
            self.ports.unit_of_work.as_ref(),
            self.keep(ctx, auditor, &mut evaluation),
        )
        .await?;
        Ok(evaluation.seen_by_author(control))
    }
}

/// Refuses `control` unless it may change and run workflows, before any
/// workflow is read, so one the caller may not test reads as forbidden
/// rather than telling them it exists.
fn ensure_may_evaluate(control: &WorkflowControl<'_>) -> Result<(), AppError> {
    control
        .ensure_may(WorkflowAction::Update)
        .and_then(|()| control.ensure_may(WorkflowAction::Run))
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::evaluation::run::EvaluationState;
    use ianua_domain::domains::workflows::evaluation::set::PublishGate;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeEvaluationSetStore, FakeEvaluationStore, FakeWorkflowStore, QueuedLooks, draft_by,
        parcel_case, person, set_for, tidy_step,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, RecordingUnitOfWork, RejectingLimitEnforcer,
        block_on, test_auditor, test_ctx,
    };

    const TESTS: [SystemPermission; 2] = [
        SystemPermission::Workflows(WorkflowAction::Update),
        SystemPermission::Workflows(WorkflowAction::Run),
    ];

    /// Ann's draft with a saved set, and what a start wrote, queued and
    /// recorded.
    struct Starting {
        draft: Workflow<ResolvedTenant>,
        sets: Arc<FakeEvaluationSetStore>,
        evaluations: Arc<FakeEvaluationStore>,
        looks: QueuedLooks,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Starting {
        fn new() -> Self {
            let ann = person("ann@corp.test");
            let draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
            let set = set_for(&draft, &ann, vec![parcel_case("late")], PublishGate::Off);
            Self {
                sets: Arc::new(FakeEvaluationSetStore::holding(&set)),
                evaluations: Arc::new(FakeEvaluationStore::empty()),
                looks: QueuedLooks::none(),
                sink: Arc::new(FakeEventDispatcher::new()),
                draft,
            }
        }

        fn start(
            &self,
            holds: &[SystemPermission],
            limits: Arc<dyn LimitEnforcer>,
        ) -> Result<EvaluationView<ResolvedTenant>, AppError> {
            let use_case = StartUseCase::new(StartPorts {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(
                    &self.draft,
                ))),
                evaluation_sets: self.sets.clone(),
                evaluations: self.evaluations.clone(),
                looks: self.looks.looks(),
                limit_enforcer: limits,
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
                unit_of_work: Arc::new(RecordingUnitOfWork::default()),
            });
            let request = StartRequest {
                workflow_id: *self.draft.id(),
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }
    }

    /// Ann evaluates her draft. The evaluation is kept running with its
    /// one case, its first look is queued, and its start is recorded.
    #[test]
    fn a_draft_is_evaluated() {
        let starting = Starting::new();

        let evaluation = starting.start(&TESTS, Arc::new(FakeLimitEnforcer)).unwrap();

        let kept = starting.evaluations.stored(evaluation.id()).unwrap();
        assert_eq!(kept.state(), EvaluationState::Running);
        assert_eq!(kept.cases().len(), 1);
        assert_eq!(starting.looks.queued(), [*evaluation.id()]);
        assert_eq!(
            starting.sink.records.lock().unwrap().as_slice(),
            ["workflows.evaluation_started"]
        );
    }

    /// At the plan's limit of evaluations running at once, a start is
    /// refused; nothing is kept, queued or recorded.
    #[test]
    fn an_evaluation_past_the_plan_is_refused() {
        let starting = Starting::new();

        let refused = starting.start(&TESTS, Arc::new(RejectingLimitEnforcer));

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(starting.looks.queued().is_empty());
        assert!(starting.sink.records.lock().unwrap().is_empty());
    }

    /// Someone who may only run workflows cannot evaluate a draft.
    #[test]
    fn evaluating_needs_the_right_to_edit() {
        let starting = Starting::new();
        let runs = [SystemPermission::Workflows(WorkflowAction::Run)];

        let refused = starting.start(&runs, Arc::new(FakeLimitEnforcer));

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(starting.looks.queued().is_empty());
    }
}
