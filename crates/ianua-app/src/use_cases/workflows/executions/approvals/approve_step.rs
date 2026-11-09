//! Approve step: a person approves a workflow's approval step, having been
//! shown the data it lets through.
//!
//! The domain decides who may approve: someone holding the workflow approve
//! right, cleared for what the step shows, who is neither the person the
//! execution acts for nor, on a high-risk step, one of its authors. A
//! high-risk step needs two different people, each present with a fresh
//! code from their own second factor. The app asks for that code.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::AnsweredCode;
use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::execution::WorkflowExecution;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowExecutionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{ExecutionVersion, WorkflowExecutionStore};
use crate::services::authentication::approver_presence::ApproverPresence;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::approvals::approving::{
    approval_step_of, step_approver,
};
use crate::use_cases::workflows::executions::approvals::decided::ExecutionDecided;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::lookup::existing_execution;

/// One person's approval of a step, for the data they were shown.
pub struct ApproveStepRequest {
    /// The execution waiting.
    pub execution_id: WorkflowExecutionId,
    /// The approval step.
    pub step: NodeKey,
    /// The data the approver was shown, which the approval is for.
    pub shown: FlowData,
    /// A fresh second-factor code, needed for a high-risk step.
    pub mfa_code: Option<String>,
}

/// The ports [`ApproveStepUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ApproveStepPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Drives an execution again when its next step falls due.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end, and
    /// settles a paused one at once.
    pub run_stops: StopPorts,
    /// Requires a fresh second factor from the approver of a high-risk step.
    pub presence: Arc<ApproverPresence>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Approves workflow approval steps.
pub struct ApproveStepUseCase {
    ports: ApproveStepPorts,
}

impl ApproveStepUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ApproveStepPorts) -> Self {
        Self { ports }
    }
}

impl Command for ApproveStepUseCase {
    type Caller = CallerContext;
    type Input = ApproveStepRequest;
    type Output = Result<ExecutionDecided, AppError>;

    /// Approves `request.step` for the person `ctx` names. The first of two
    /// approvals is recorded and the step keeps waiting; the approval that
    /// completes it lets the workflow go on. Only where the execution
    /// stands comes back: the approver is cleared for what this step shows,
    /// not for every other step of the run.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing execution/approval step.
    /// - `AppError::StepUpRequired` or `AccountLocked` for failed high-risk presence checks.
    /// - `AppError::Forbidden` without approval rights/clearance, for the person acted for, high-risk step author, first approver, or wrong/spent codes.
    /// - `AppError::Conflict` for wrong shown data, execution expiry or concurrent change; `Domain` for a step not waiting or an ended approval window.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ApproveStepRequest,
    ) -> Result<ExecutionDecided, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::Approve)
            .map_err(AppError::from_domain)?;
        let mut execution = existing_execution(
            self.ports.executions.as_ref(),
            &tenant,
            &request.execution_id,
        )
        .await?;
        let read = ExecutionVersion::of(&execution);
        let answered = presence_answer(&self.ports, ctx, &execution, &request).await?;
        let approver = step_approver(&authority, answered.as_ref())?;
        let records = execution
            .approve(&request.step, &approver, &request.shown)
            .map_err(AppError::from_domain)?;
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        let kept = Kept::Changed(&execution, read);
        keeping.keep(&tenant, auditor, kept, records).await?;
        Ok(ExecutionDecided::of(&execution))
    }
}

/// The caller's fresh second-factor answer, when the step they approve is
/// high risk.
async fn presence_answer(
    ports: &ApproveStepPorts,
    ctx: &CallerContext,
    execution: &WorkflowExecution<ResolvedTenant>,
    request: &ApproveStepRequest,
) -> Result<Option<AnsweredCode>, AppError> {
    if !approval_step_of(execution, &request.step)?.needs_presence() {
        return Ok(None);
    }
    let answered = ports
        .presence
        .require(ctx, request.mfa_code.as_deref())
        .await?;
    Ok(Some(answered))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::execution::step::{
        ApprovalWait, FirstApproval, StepState, Underway,
    };
    use ianua_domain::types::{ActionClass, Human};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{PRESENT_CODE, caller_person};
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, QueuedWakeups, awaiting_approval, awaiting_approval_at,
        caller_presence, person, step, trigger_data,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const APPROVES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Approve)];

    /// The stores an approval writes to, and what it recorded.
    struct Deciding {
        executions: Arc<FakeWorkflowExecutionStore>,
        wakeups: Arc<QueuedWakeups>,
        sink: Arc<FakeEventDispatcher>,
        execution_id: WorkflowExecutionId,
    }

    impl Deciding {
        fn over(execution: &WorkflowExecution<ResolvedTenant>) -> Self {
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::holding(execution)),
                wakeups: Arc::new(QueuedWakeups::none()),
                sink: Arc::new(FakeEventDispatcher::new()),
                execution_id: *execution.id(),
            }
        }

        fn ports(&self, authorities: FakeTenantAuthorities) -> ApproveStepPorts {
            ApproveStepPorts {
                executions: self.executions.clone(),
                wakeups: self.wakeups.wakeups(),
                presence: caller_presence(),
                tenant_authorities: Arc::new(authorities),
                ..ApproveStepPorts::fakes()
            }
        }

        fn approve(
            &self,
            ports: ApproveStepPorts,
            shown: FlowData,
            code: Option<&str>,
        ) -> Result<ExecutionDecided, AppError> {
            let request = ApproveStepRequest {
                execution_id: self.execution_id,
                step: step("check"),
                shown,
                mfa_code: code.map(str::to_owned),
            };
            let use_case = ApproveStepUseCase::new(ports);
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        fn shown(&self) -> FlowData {
            self.stored().approval_input(&step("check")).unwrap()
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

    fn report_run() -> WorkflowExecution<ResolvedTenant> {
        awaiting_approval(
            &person("author@corp.test"),
            &ann(),
            ActionClass::Communicate,
        )
    }

    fn approver() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&APPROVES)
    }

    /// Ann's run waits for a sign-off on the weekly report. Bob, who may
    /// approve steps, approves what he was shown. The step succeeds, the
    /// approval is recorded and the run goes on to the step after it.
    #[test]
    fn an_approval_lets_the_workflow_go_on() {
        let deciding = Deciding::over(&report_run());

        let decided = deciding
            .approve(deciding.ports(approver()), deciding.shown(), None)
            .unwrap();

        assert_eq!(
            decided,
            ExecutionDecided {
                execution_id: deciding.execution_id,
                status: deciding.stored().status(),
            }
        );
        assert!(matches!(
            deciding.stored().step(&step("check")),
            Some(StepState::Succeeded { .. })
        ));
        assert!(matches!(
            deciding.stored().step(&step("after")),
            Some(StepState::Succeeded { .. })
        ));
        assert!(
            deciding
                .records()
                .contains(&"workflows.approval_granted".to_owned())
        );
    }

    /// Approving with data different from the step's input returns a conflict
    /// and leaves the stored step running.
    #[test]
    fn an_approval_for_data_other_than_shown_is_refused() {
        let deciding = Deciding::over(&report_run());

        let result = deciding.approve(deciding.ports(approver()), FlowData::null(), None);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(matches!(
            deciding.stored().step(&step("check")),
            Some(StepState::Running { .. })
        ));
    }

    /// A concurrent execution change makes saving an approval conflict. The
    /// stored step remains running and no audit event is recorded.
    #[test]
    fn an_approval_read_before_another_change_is_a_conflict() {
        let deciding = Deciding::over(&report_run());
        let shown = deciding.shown();
        deciding.executions.moves_on_before_each_save();

        let result = deciding.approve(deciding.ports(approver()), shown, None);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(matches!(
            deciding.stored().step(&step("check")),
            Some(StepState::Running { .. })
        ));
        assert!(deciding.records().is_empty());
    }

    /// Approval rights do not let the person a run acts for approve its step.
    #[test]
    fn the_person_a_run_acts_for_cannot_approve_it() {
        let own = awaiting_approval(
            &person("author@corp.test"),
            &caller_person(),
            ActionClass::Communicate,
        );
        let deciding = Deciding::over(&own);

        let result = deciding.approve(deciding.ports(approver()), deciding.shown(), None);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A workflow viewer cannot approve a step; the refusal records no audit event.
    #[test]
    fn approving_needs_the_approve_right() {
        let deciding = Deciding::over(&report_run());
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = deciding.approve(deciding.ports(sam), deciding.shown(), None);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(deciding.records().is_empty());
    }

    /// An approver with only internal clearance cannot approve a step carrying
    /// confidential data.
    #[test]
    fn an_approver_not_cleared_for_the_data_is_refused() {
        let confidential = awaiting_approval_at(
            &person("author@corp.test"),
            &ann(),
            ActionClass::Communicate,
            DataClassLevel::Confidential,
        );
        let deciding = Deciding::over(&confidential);

        let result = deciding.approve(deciding.ports(approver()), deciding.shown(), None);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    fn payment_run() -> WorkflowExecution<ResolvedTenant> {
        awaiting_approval(&person("author@corp.test"), &ann(), ActionClass::Financial)
    }

    /// Approving a payment step without a second-factor code requires step-up
    /// authentication and records no audit event.
    #[test]
    fn a_high_risk_step_without_a_code_asks_for_a_step_up() {
        let deciding = Deciding::over(&payment_run());

        let result = deciding.approve(deciding.ports(approver()), deciding.shown(), None);

        assert!(matches!(result, Err(AppError::StepUpRequired)));
        assert!(deciding.records().is_empty());
    }

    /// Bob answers his authenticator's code and approves a payment step. His
    /// is the first of two approvals, so it is recorded and the step waits
    /// for a second person.
    #[test]
    fn a_present_approver_gives_the_first_of_two_approvals() {
        let deciding = Deciding::over(&payment_run());

        deciding
            .approve(
                deciding.ports(approver()),
                deciding.shown(),
                Some(PRESENT_CODE),
            )
            .unwrap();

        assert!(matches!(
            deciding.stored().step(&step("check")),
            Some(StepState::Running {
                underway: Underway::Approval(ApprovalWait {
                    first: FirstApproval::GivenBy(_),
                    ..
                }),
                ..
            })
        ));
        assert_eq!(deciding.records(), ["workflows.approval_granted"]);
    }

    /// A signed-out session cannot approve a workflow step.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let deciding = Deciding::over(&report_run());
        let mallory = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let result = deciding.approve(deciding.ports(mallory), trigger_data(), None);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
