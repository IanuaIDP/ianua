//! Opening an approval step: people are asked in the platform's inbox, and
//! when the step names a Slack channel, the job that asks there too is
//! queued in the unit of work that keeps the opening, so the approval and
//! its question are kept together or not at all.

use ianua_domain::domains::workflows::design::also_ask::AlsoAsk;
use ianua_domain::domains::workflows::design::node::{NodeKey, WorkflowApprovalStep};
use ianua_domain::domains::workflows::execution::WorkflowExecution;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::AppError;
use crate::ports::workflows::ExecutionVersion;
use crate::services::kept_together::kept_together;
use crate::use_cases::workflows::executions::driving::Driving;
use crate::use_cases::workflows::executions::running::keeping::Kept;

impl Driving<'_> {
    /// Opens the ready approval step `key` of `execution`, read at `read`,
    /// whose settings are `step`, and keeps it with its Slack question
    /// queued when it asks there.
    pub(super) async fn open_approval(
        &self,
        mut execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
        step: &WorkflowApprovalStep,
    ) -> Result<(), AppError> {
        let records = execution
            .request_approval(key)
            .map_err(AppError::from_domain)?;
        if *step.also_ask() == AlsoAsk::Nowhere {
            return self.keep(&execution, read, records).await;
        }
        let keeping = self.keeping();
        let opened_and_queued = async {
            keeping
                .keep(
                    self.tenant,
                    self.auditor,
                    Kept::Changed(&execution, read),
                    records,
                )
                .await?;
            self.ports
                .wakeups
                .ask_in_slack(self.tenant, execution.id(), key)
                .await
        };
        kept_together(self.ports.unit_of_work.as_ref(), opened_and_queued).await
    }
}
