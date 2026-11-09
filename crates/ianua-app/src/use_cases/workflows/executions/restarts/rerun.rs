//! Re-run execution: the person a failed run acted for starts it again from
//! its trigger, every step running again.

use ianua_domain::domains::workflows::execution::{RestartFrom, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowExecutionId;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::workflows::executions::restarts::restarting::RestartPorts;

/// Starts failed executions again from their trigger.
pub struct RerunUseCase {
    ports: RestartPorts,
}

impl RerunUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RestartPorts) -> Self {
        Self { ports }
    }
}

impl Command for RerunUseCase {
    type Caller = CallerContext;
    type Input = WorkflowExecutionId;
    type Output = Result<WorkflowExecution<ResolvedTenant>, AppError>;

    /// Starts the failed execution `id` again from its trigger, as a new
    /// run acting for the person `ctx` names, and records its start.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key is invalid.
    /// - `AppError::NotFound` when there is no such execution.
    /// - `AppError::Forbidden` without run rights or ownership of the failed run.
    /// - `AppError::Conflict` unless it failed or ran out of time, or when
    ///   its version is no longer in service.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: WorkflowExecutionId,
    ) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
        self.ports
            .restarted(ctx, auditor, id, RestartFrom::Beginning)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::execution::{Cause, ExecutionStatus};
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, approval_workflow, failed_run, managing,
        person, started_by,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A version, a run of it, and what a re-run wrote and recorded.
    struct Rerunning {
        workflow: Workflow<ResolvedTenant>,
        run: WorkflowExecution<ResolvedTenant>,
        executions: Arc<FakeWorkflowExecutionStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Rerunning {
        /// `run` of `workflow`, kept.
        fn over(
            workflow: Workflow<ResolvedTenant>,
            run: WorkflowExecution<ResolvedTenant>,
        ) -> Self {
            let executions = Arc::new(FakeWorkflowExecutionStore::holding(&run));
            Self {
                workflow,
                run,
                executions,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The caller's own run of the approval workflow, failed.
        fn callers_failed_run() -> Self {
            let (workflow, run) = failed_run(&person("author@corp.test"), &caller_person());
            Self::over(workflow, run)
        }

        /// The caller, holding what `authorities` say, re-runs the run.
        fn rerun(
            &self,
            authorities: FakeTenantAuthorities,
        ) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
            let use_case = RerunUseCase::new(RestartPorts {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(
                    &self.workflow,
                ))),
                executions: self.executions.clone(),
                tenant_authorities: Arc::new(authorities),
                ..RestartPorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                *self.run.id(),
            ))
        }

        /// The names of the events recorded.
        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Someone who may run workflows.
    fn runner() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Run)])
    }

    /// Ann's run failed when Bob refused its approval. She re-runs it: a
    /// new run acting for her starts from the trigger, asks for the
    /// approval again, and its start is recorded. The failed run stays.
    #[test]
    fn a_failed_run_starts_again_from_its_trigger() {
        let rerunning = Rerunning::callers_failed_run();

        let rerun = rerunning.rerun(runner()).unwrap();

        assert_ne!(rerun.id(), rerunning.run.id());
        assert_eq!(
            rerun.cause(),
            Cause::Restart {
                of: *rerunning.run.id(),
                from: RestartFrom::Beginning
            }
        );
        assert!(rerun.acting_for().is_same_account_as(&caller_person()));
        assert_eq!(rerunning.executions.all().len(), 2);
        assert_eq!(rerunning.records()[0], "workflows.execution_started");
    }

    /// Ann's run is still waiting for its approval. Re-running it is
    /// refused, so one run is not doubled while it still goes on.
    #[test]
    fn a_run_still_going_is_not_run_again() {
        let workflow = approval_workflow(&person("author@corp.test"), ActionClass::Communicate);
        let run = started_by(&caller_person(), &workflow);
        let rerunning = Rerunning::over(workflow, run);

        let result = rerunning.rerun(runner());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(rerunning.executions.all().len(), 1);
        assert!(rerunning.records().is_empty());
    }

    /// Ann's run failed, and she archived its version because a step was
    /// wrong. Re-running it is refused, so the archived steps never run.
    #[test]
    fn a_run_of_an_archived_version_is_not_run_again() {
        let (mut workflow, run) = failed_run(&person("author@corp.test"), &caller_person());
        workflow
            .archive(&managing(&person("author@corp.test")))
            .unwrap();
        let rerunning = Rerunning::over(workflow, run);

        let result = rerunning.rerun(runner());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(rerunning.executions.all().len(), 1);
    }

    /// Even full workflow rights do not permit rerunning another person's failed
    /// execution. Only the original run remains saved and no audit event is recorded.
    #[test]
    fn only_the_person_a_run_acted_for_runs_it_again() {
        let (workflow, run) = failed_run(&person("author@corp.test"), &person("ann@corp.test"));
        let rerunning = Rerunning::over(workflow, run);

        let result = rerunning.rerun(FakeTenantAuthorities::holding_everything());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(rerunning.executions.all().len(), 1);
        assert!(rerunning.records().is_empty());
    }

    /// View rights do not permit rerunning the caller's own failed execution;
    /// only the original run remains saved.
    #[test]
    fn a_caller_who_may_not_run_workflows_is_refused() {
        let rerunning = Rerunning::callers_failed_run();
        let viewing =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = rerunning.rerun(viewing);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(rerunning.executions.all().len(), 1);
    }

    /// Ann names a run the tenant does not have. It is not found.
    #[test]
    fn an_unknown_run_is_not_found() {
        let rerunning = Rerunning {
            executions: Arc::new(FakeWorkflowExecutionStore::empty()),
            ..Rerunning::callers_failed_run()
        };

        let result = rerunning.rerun(runner());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot rerun a failed execution; only the original
    /// run remains saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let rerunning = Rerunning::callers_failed_run();

        let result = rerunning.rerun(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(rerunning.executions.all().len(), 1);
    }

    /// A run that failed and ran again is still recorded as failed: the
    /// re-run is a run of its own.
    #[test]
    fn the_failed_run_keeps_its_end() {
        let rerunning = Rerunning::callers_failed_run();

        rerunning.rerun(runner()).unwrap();

        let kept = rerunning.executions.stored(rerunning.run.id()).unwrap();
        assert!(matches!(kept.status(), ExecutionStatus::Ended(_)));
    }
}
