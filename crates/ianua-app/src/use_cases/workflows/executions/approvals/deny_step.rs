//! Deny step: a person refuses a workflow's approval step, and the
//! execution fails.
//!
//! Denying needs the same right and clearance as approving, so nobody
//! without a say stops every workflow that waits for one. The agent runs a
//! failed execution leaves going are ordered to stop.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::types::WorkflowExecutionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{ExecutionVersion, WorkflowExecutionStore};
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::approvals::approving::step_approver;
use crate::use_cases::workflows::executions::approvals::decided::ExecutionDecided;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::lookup::existing_execution;

/// The step a person refuses.
pub struct DenyStepRequest {
    /// The execution waiting.
    pub execution_id: WorkflowExecutionId,
    /// The approval step.
    pub step: NodeKey,
}

/// The ports [`DenyStepUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DenyStepPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Drives an execution again when its next step falls due.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end, and
    /// settles a paused one at once.
    pub run_stops: StopPorts,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Refuses workflow approval steps.
pub struct DenyStepUseCase {
    ports: DenyStepPorts,
}

impl DenyStepUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DenyStepPorts) -> Self {
        Self { ports }
    }
}

impl Command for DenyStepUseCase {
    type Caller = CallerContext;
    type Input = DenyStepRequest;
    type Output = Result<ExecutionDecided, AppError>;

    /// Refuses `request.step` for the person `ctx` names, failing the
    /// execution. Only where the execution stands comes back: the person
    /// deciding is cleared for what this step shows, not for every other
    /// step of the run.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing execution/step.
    /// - `AppError::Forbidden` without decision rights or clearance; `Conflict` for execution expiry or concurrent change.
    /// - `AppError::Domain` for a step not awaiting approval; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DenyStepRequest,
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
        let approver = step_approver(&authority, None)?;
        let records = execution
            .deny(&request.step, &approver)
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

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::execution::ExecutionStatus;
    use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, awaiting_approval, person, step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store a denial writes to, and what it recorded.
    struct Denying {
        executions: Arc<FakeWorkflowExecutionStore>,
        sink: Arc<FakeEventDispatcher>,
        execution_id: WorkflowExecutionId,
    }

    impl Denying {
        fn new() -> Self {
            let execution = awaiting_approval(
                &person("author@corp.test"),
                &person("ann@corp.test"),
                ActionClass::Communicate,
            );
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::holding(&execution)),
                sink: Arc::new(FakeEventDispatcher::new()),
                execution_id: *execution.id(),
            }
        }

        fn deny(&self, authorities: FakeTenantAuthorities) -> Result<ExecutionDecided, AppError> {
            let use_case = DenyStepUseCase::new(DenyStepPorts {
                executions: self.executions.clone(),
                tenant_authorities: Arc::new(authorities),
                ..DenyStepPorts::fakes()
            });
            let request = DenyStepRequest {
                execution_id: self.execution_id,
                step: step("check"),
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        fn status(&self) -> ExecutionStatus {
            self.executions.stored(&self.execution_id).unwrap().status()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Bob, who may decide steps, refuses the sign-off on Ann's report. The
    /// execution fails, and the failed step and its end are recorded.
    #[test]
    fn a_denial_fails_the_execution_and_is_recorded() {
        let denying = Denying::new();

        let decided = denying
            .deny(FakeTenantAuthorities::holding(&[
                SystemPermission::Workflows(WorkflowAction::Approve),
            ]))
            .unwrap();

        assert_eq!(
            decided,
            ExecutionDecided {
                execution_id: denying.execution_id,
                status: ExecutionStatus::Ended(ExecutionEnd::Failed),
            }
        );
        assert_eq!(
            denying.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
        assert!(
            denying
                .records()
                .contains(&"workflows.execution_ended".to_owned())
        );
    }

    /// A workflow viewer cannot deny an approval step. The execution remains
    /// running and no audit event is recorded.
    #[test]
    fn denying_needs_the_approve_right() {
        let denying = Denying::new();

        let result = denying.deny(FakeTenantAuthorities::holding(&[
            SystemPermission::Workflows(WorkflowAction::View),
        ]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(denying.status(), ExecutionStatus::Running);
        assert!(denying.records().is_empty());
    }

    /// A signed-out session cannot deny an approval step.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let denying = Denying::new();

        let result = denying.deny(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
