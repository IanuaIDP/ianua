//! Retry execution: the person a failed run acted for starts it again from
//! the steps that did not finish. The steps that finished for good keep
//! what they produced; an approval is always asked for again.

use ianua_domain::domains::workflows::execution::{RestartFrom, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowExecutionId;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::workflows::executions::restarts::restarting::RestartPorts;

/// Starts failed executions again from their failed steps.
pub struct RetryUseCase {
    ports: RestartPorts,
}

impl RetryUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RestartPorts) -> Self {
        Self { ports }
    }
}

impl Command for RetryUseCase {
    type Caller = CallerContext;
    type Input = WorkflowExecutionId;
    type Output = Result<WorkflowExecution<ResolvedTenant>, AppError>;

    /// Starts the failed execution `id` again from the steps that did not
    /// finish, as a new run acting for the person `ctx` names, and records
    /// its start.
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
            .restarted(ctx, auditor, id, RestartFrom::FailedStep)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::execution::Cause;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, failed_run, person,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A failed run, its version, and what a retry wrote and recorded.
    struct Retrying {
        workflow: Workflow<ResolvedTenant>,
        run: WorkflowExecution<ResolvedTenant>,
        executions: Arc<FakeWorkflowExecutionStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Retrying {
        /// The failed run of the approval workflow that acted for
        /// `acting_for`.
        fn failed_for(acting_for: &Human) -> Self {
            let (workflow, run) = failed_run(&person("author@corp.test"), acting_for);
            let executions = Arc::new(FakeWorkflowExecutionStore::holding(&run));
            Self {
                workflow,
                run,
                executions,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The caller, holding what `authorities` say, retries the run.
        fn retry(
            &self,
            authorities: FakeTenantAuthorities,
        ) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
            let use_case = RetryUseCase::new(RestartPorts {
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

    /// Ann's run failed at its approval. She retries it from the failed
    /// step: a new run acting for her asks for the approval again, and its
    /// start is recorded as a retry of the failed run.
    #[test]
    fn a_failed_run_is_retried_from_its_failed_step() {
        let retrying = Retrying::failed_for(&caller_person());

        let retry = retrying.retry(runner()).unwrap();

        assert_eq!(
            retry.cause(),
            Cause::Restart {
                of: *retrying.run.id(),
                from: RestartFrom::FailedStep
            }
        );
        assert!(retry.acting_for().is_same_account_as(&caller_person()));
        assert!(retrying.executions.stored(retry.id()).is_some());
        assert_eq!(retrying.records()[0], "workflows.execution_started");
    }

    /// Even full workflow rights do not permit retrying another person's failed
    /// execution. Only the original run remains saved and no audit event is recorded.
    #[test]
    fn only_the_person_a_run_acted_for_retries_it() {
        let retrying = Retrying::failed_for(&person("ann@corp.test"));

        let result = retrying.retry(FakeTenantAuthorities::holding_everything());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(retrying.executions.all().len(), 1);
        assert!(retrying.records().is_empty());
    }

    /// View rights do not permit retrying the caller's own failed execution;
    /// only the original run remains saved.
    #[test]
    fn a_caller_who_may_not_run_workflows_is_refused() {
        let retrying = Retrying::failed_for(&caller_person());
        let viewing =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = retrying.retry(viewing);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(retrying.executions.all().len(), 1);
    }

    /// Ann names a run the tenant does not have. It is not found.
    #[test]
    fn an_unknown_run_is_not_found() {
        let retrying = Retrying {
            executions: Arc::new(FakeWorkflowExecutionStore::empty()),
            ..Retrying::failed_for(&caller_person())
        };

        let result = retrying.retry(runner());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot retry a failed execution; only the original
    /// run remains saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let retrying = Retrying::failed_for(&caller_person());

        let result = retrying.retry(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(retrying.executions.all().len(), 1);
    }
}
