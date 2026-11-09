//! Start trial: a person hands a built version of a sandbox sample input,
//! and a worker runs it as a code step would.
//!
//! Only someone who may change workflows tries a version, the sandbox must
//! be active and the version its own and built, and the tenant's plan caps
//! how many trials run at once. The trial and its job are kept in one unit
//! of work with its record, so no trial waits on a run nobody will make.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::sandbox::trial::SandboxTrial;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{SandboxId, SandboxVersionId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{SandboxStore, SandboxTrialStore, SandboxVersionStore};
use crate::services::kept_together::kept_together;
use crate::use_case::Command;
use crate::use_cases::workflows::sandboxes::lookup::{existing_sandbox, existing_version};
use crate::use_cases::workflows::sandboxes::trying::run::SandboxTrials;

/// A trial a person starts.
pub struct StartTrialRequest {
    /// The code project whose revision will be tested.
    pub sandbox_id: SandboxId,
    /// The version of it to try.
    pub version_id: SandboxVersionId,
    /// What the code is given.
    pub input: FlowData,
}

/// The ports [`StartTrialUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartTrialPorts {
    /// Keeps the sandboxes.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// Keeps their versions.
    pub versions: Arc<dyn SandboxVersionStore>,
    /// Keeps the trials.
    pub trials: Arc<dyn SandboxTrialStore>,
    /// Queues the job that runs a trial.
    pub runs: SandboxTrials,
    /// Checks the plan's limit of trials running at once.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Keeps the trial, its job and its record all or nothing.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Starts trials of sandbox versions.
pub struct StartTrialUseCase {
    ports: StartTrialPorts,
}

impl StartTrialUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartTrialPorts) -> Self {
        Self { ports }
    }

    /// Checks the plan's limit and keeps `trial`, its job and its record,
    /// for the person `ctx` names, in the unit of work the count holds.
    async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        trial: &mut SandboxTrial<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &tenant, ResourceKind::RunningTrials)
            .await
            .map_err(AppError::from_domain)?;
        self.ports
            .trials
            .insert(&tenant, trial)
            .await
            .map_err(AppError::from_domain)?;
        self.ports.runs.queue(&tenant, trial.id()).await?;
        auditor
            .dispatch_by(&ctx.actor(), trial.take_events(&tenant))
            .await
            .or_internal()
    }
}

impl Command for StartTrialUseCase {
    type Caller = CallerContext;
    type Input = StartTrialRequest;
    type Output = Result<SandboxTrial<ResolvedTenant>, AppError>;

    /// Starts a trial of `request.version_id` on `request.input`, for the
    /// person `ctx` names, and queues its run.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such sandbox, or the
    ///   sandbox no such version.
    /// - `AppError::Forbidden` when the caller may not change workflows, or
    ///   the plan's limit of trials running at once is reached.
    /// - `AppError::Conflict` when the sandbox is archived or the version
    ///   is not built.
    /// - `AppError::Internal` on persistence, queue or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: StartTrialRequest,
    ) -> Result<SandboxTrial<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let sandbox =
            existing_sandbox(self.ports.sandboxes.as_ref(), &tenant, &request.sandbox_id).await?;
        let version =
            existing_version(self.ports.versions.as_ref(), &tenant, &request.version_id).await?;
        let mut trial = sandbox
            .try_version(&control, &version, request.input)
            .map_err(AppError::from_domain)?;
        kept_together(
            self.ports.unit_of_work.as_ref(),
            self.keep(ctx, auditor, &mut trial),
        )
        .await?;
        Ok(trial)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::sandbox::trial::TrialState;

    use super::*;
    use crate::ports::limits::LimitEnforcer;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeSandboxStore, FakeSandboxTrialStore, FakeSandboxVersionStore, QueuedTrials,
        built_version_of, python_sandbox, version_of,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, RecordingUnitOfWork, RejectingLimitEnforcer,
        block_on, test_auditor, test_ctx,
    };

    const CHANGES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Update)];

    /// What a start wrote, queued and recorded.
    struct Starting {
        sandboxes: Arc<FakeSandboxStore>,
        versions: Arc<FakeSandboxVersionStore>,
        trials: Arc<FakeSandboxTrialStore>,
        runs: QueuedTrials,
        sink: Arc<FakeEventDispatcher>,
        request: StartTrialRequest,
    }

    impl Starting {
        /// A sandbox holding a version built, or still building.
        fn new(built: bool) -> Self {
            let mut sandbox = python_sandbox();
            let version = match built {
                true => built_version_of(&mut sandbox),
                false => version_of(&mut sandbox),
            };
            Self {
                request: StartTrialRequest {
                    sandbox_id: *sandbox.id(),
                    version_id: *version.id(),
                    input: FlowData::text("Fix login page").unwrap(),
                },
                sandboxes: Arc::new(FakeSandboxStore::holding(&sandbox)),
                versions: Arc::new(FakeSandboxVersionStore::holding(&version)),
                trials: Arc::new(FakeSandboxTrialStore::empty()),
                runs: QueuedTrials::none(),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn start(
            &self,
            holds: &[SystemPermission],
            limits: Arc<dyn LimitEnforcer>,
        ) -> Result<SandboxTrial<ResolvedTenant>, AppError> {
            let use_case = StartTrialUseCase::new(StartTrialPorts {
                sandboxes: self.sandboxes.clone(),
                versions: self.versions.clone(),
                trials: self.trials.clone(),
                runs: self.runs.runs(),
                limit_enforcer: limits,
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
                unit_of_work: Arc::new(RecordingUnitOfWork::default()),
            });
            let request = StartTrialRequest {
                input: self.request.input.clone(),
                ..self.request
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }
    }

    /// Tess tries a built version. The trial is kept running with its
    /// input, its run is queued, and its start is recorded.
    #[test]
    fn a_built_version_is_tried() {
        let starting = Starting::new(true);

        let trial = starting
            .start(&CHANGES, Arc::new(FakeLimitEnforcer))
            .unwrap();

        let kept = starting
            .trials
            .stored(trial.id())
            .expect("the trial is kept");
        assert_eq!(kept.state(), &TrialState::Running);
        assert_eq!(kept.input(), &starting.request.input);
        assert_eq!(starting.runs.queued(), [*trial.id()]);
        assert_eq!(
            starting.sink.records.lock().unwrap().as_slice(),
            ["workflows.sandbox_trial_started"]
        );
    }

    /// A plan-limit refusal prevents starting a trial, queues no run and records
    /// no audit event.
    #[test]
    fn a_trial_past_the_plan_is_refused() {
        let starting = Starting::new(true);

        let refused = starting.start(&CHANGES, Arc::new(RejectingLimitEnforcer));

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(starting.runs.queued().is_empty());
        assert!(starting.sink.records.lock().unwrap().is_empty());
    }

    /// A viewer cannot start a trial. An editor trying an unbuilt version gets a
    /// conflict and no run is queued for it.
    #[test]
    fn only_a_built_version_is_tried_by_those_who_may_change_workflows() {
        let viewer = Starting::new(true);
        let building = Starting::new(false);
        let views = [SystemPermission::Workflows(WorkflowAction::View)];

        let forbidden = viewer.start(&views, Arc::new(FakeLimitEnforcer));
        let unbuilt = building.start(&CHANGES, Arc::new(FakeLimitEnforcer));

        assert!(matches!(forbidden, Err(AppError::Forbidden(_))));
        assert!(matches!(unbuilt, Err(AppError::Conflict(_))));
        assert!(building.runs.queued().is_empty());
    }
}
