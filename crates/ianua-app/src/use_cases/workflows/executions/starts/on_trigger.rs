//! Start on trigger: a version's schedule comes round, and it starts for the
//! person who published it.
//!
//! The scheduler calls this once the schedule is due. A webhook call starts
//! a version only through `start_on_webhook`, once its secret is checked,
//! and an event through `start_on_event`.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::{Cause, StartRefusal};
use ianua_domain::types::{WorkflowExecutionId, WorkflowId};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{IntegrationAccountStore, WorkflowExecutionStore, WorkflowStore};
use crate::services::account_now::AccountsNow;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::starts::triggered::{
    Admission, Firing, started_for_publisher,
};
use crate::use_cases::workflows::lookup::published_version;

/// How one firing of a trigger came out for one version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggeredStart {
    /// This execution started, acting for the version's publisher.
    Started(WorkflowExecutionId),
    /// The publisher may not have it run now. The refusal is recorded.
    Refused(StartRefusal),
    /// The event came from a chain of executions already as long as any
    /// may be. Nothing starts, and nothing is recorded that would set off
    /// another.
    ChainTooLong,
}

/// One firing of a version's schedule.
pub struct StartOnTriggerRequest {
    /// The workflow whose version in service fired.
    pub workflow_id: WorkflowId,
    /// The trigger's data.
    pub input: FlowData,
    /// The most sensitive data in it, as the scheduler classed it.
    pub exposure: DataClassLevel,
}

/// The ports a start on a schedule, a webhook or an event needs.
#[derive(ianua_macros::Fakes)]
pub struct TriggerStartPorts {
    /// The versions, for the ones in service.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Hands a new execution to a worker.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end, and
    /// settles a paused one at once.
    pub run_stops: StopPorts,
    /// The publisher's records as they stand.
    pub accounts_now: Arc<AccountsNow>,
    /// The accounts the version acts through, checked before each start.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Keeps a start, or a refusal, and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Starts versions when their schedule comes round.
pub struct StartOnTriggerUseCase {
    ports: TriggerStartPorts,
}

impl StartOnTriggerUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: TriggerStartPorts) -> Self {
        Self { ports }
    }
}

impl Command for StartOnTriggerUseCase {
    type Caller = ScopedTenant;
    type Input = StartOnTriggerRequest;
    type Output = Result<TriggeredStart, AppError>;

    /// Starts the version of `request.workflow_id` in service for its
    /// publisher, or records why it may not start.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when no version of the workflow is published.
    /// - `AppError::Domain` when the version does not start on its schedule.
    /// - `AppError::Internal` when the publisher's records name a role that
    ///   is not there, or the start or its record cannot be kept.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: StartOnTriggerRequest,
    ) -> Result<TriggeredStart, AppError> {
        let workflow =
            published_version(self.ports.workflows.as_ref(), tenant, &request.workflow_id).await?;
        let firing = Firing {
            cause: Cause::Schedule,
            admission: Admission::Trigger,
            input: request.input,
            exposure: request.exposure,
        };
        started_for_publisher(&self.ports, tenant, auditor, &workflow, firing).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::triggers::{CronSchedule, Trigger};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, accounts_now_of, draft_by, draft_on,
        hooked_by, person, published_by, tidy_step, trigger_data,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const RUNS: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Run)];

    /// The nightly export `publisher` wrote and published, run at two each
    /// night.
    fn nightly(publisher: &Human) -> Workflow<ResolvedTenant> {
        let schedule = Trigger::Schedule(CronSchedule::parse("0 2 * * *").unwrap());
        published_by(
            publisher,
            draft_on(publisher, vec![tidy_step("export")], Vec::new(), schedule),
        )
    }

    /// What a firing wrote, and what it recorded.
    struct Fire {
        executions: Arc<FakeWorkflowExecutionStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Fire {
        /// Nothing written or recorded yet.
        fn new() -> Self {
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// `workflow`'s schedule comes round, with `accounts_now` as the
        /// tenant's records.
        fn fire(
            &self,
            workflow: &Workflow<ResolvedTenant>,
            accounts_now: AccountsNow,
        ) -> Result<TriggeredStart, AppError> {
            let use_case = StartOnTriggerUseCase::new(TriggerStartPorts {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(workflow))),
                executions: self.executions.clone(),
                accounts_now: Arc::new(accounts_now),
                ..TriggerStartPorts::fakes()
            });
            let request = StartOnTriggerRequest {
                workflow_id: *workflow.id(),
                input: trigger_data(),
                exposure: DataClassLevel::Internal,
            };
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                request,
            ))
        }

        /// The names of the events recorded.
        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann published the nightly export and may still run workflows. Its
    /// schedule comes round, and it runs acting for Ann.
    #[test]
    fn a_schedule_starts_the_version_for_its_publisher() {
        let ann = person("ann@corp.test");
        let fire = Fire::new();

        let outcome = fire
            .fire(&nightly(&ann), accounts_now_of(&[(&ann, &RUNS)]))
            .unwrap();

        let TriggeredStart::Started(id) = outcome else {
            panic!("the schedule did not start the export");
        };
        assert!(
            fire.executions
                .stored(&id)
                .unwrap()
                .acting_for()
                .is_same_account_as(&ann)
        );
        assert_eq!(fire.records()[0], "workflows.execution_started");
    }

    /// A schedule cannot start a run for a missing publisher. The refusal names
    /// the publisher's run rights, saves no execution and is audited.
    #[test]
    fn a_publisher_who_left_does_not_have_their_workflow_run() {
        let ann = person("ann@corp.test");
        let fire = Fire::new();

        let outcome = fire.fire(&nightly(&ann), accounts_now_of(&[])).unwrap();

        assert_eq!(
            outcome,
            TriggeredStart::Refused(StartRefusal::PersonMayNotRun)
        );
        assert!(fire.executions.all().is_empty());
        assert_eq!(fire.records(), ["workflows.start_refused"]);
    }

    /// A publisher holding only workflow view rights cannot have a scheduled run
    /// start; the refusal names run rights and no execution is saved.
    #[test]
    fn a_publisher_who_lost_the_run_right_does_not_have_their_workflow_run() {
        let ann = person("ann@corp.test");
        let fire = Fire::new();
        let viewing = [SystemPermission::Workflows(WorkflowAction::View)];

        let outcome = fire
            .fire(&nightly(&ann), accounts_now_of(&[(&ann, &viewing)]))
            .unwrap();

        assert_eq!(
            outcome,
            TriggeredStart::Refused(StartRefusal::PersonMayNotRun)
        );
        assert!(fire.executions.all().is_empty());
    }

    /// A schedule firing cannot start a webhook workflow; it fails validation
    /// without saving an execution.
    #[test]
    fn a_schedule_does_not_start_a_webhook_workflow() {
        let ann = person("ann@corp.test");
        let fire = Fire::new();

        let result = fire.fire(&hooked_by(&ann), accounts_now_of(&[(&ann, &RUNS)]));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(fire.executions.all().is_empty());
    }

    /// A schedule fires for a workflow that is still a draft. Nothing is in
    /// service, so it is not found.
    #[test]
    fn a_draft_does_not_start_on_its_schedule() {
        let ann = person("ann@corp.test");
        let fire = Fire::new();
        let draft = draft_by(&ann, vec![tidy_step("export")], Vec::new());

        let result = fire.fire(&draft, accounts_now_of(&[(&ann, &RUNS)]));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
