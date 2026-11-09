//! What a person approving, denying or stopping an execution is told:
//! where it stands, and nothing its steps hold.

use ianua_domain::domains::workflows::execution::{ExecutionStatus, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowExecutionId;

/// Where an execution stands once a person approved, denied or stopped it:
/// all such an act hands back. Approving takes the right to approve and
/// stopping one's own run no right at all, while the steps hold data above
/// some people's clearance, so the person reads the execution through
/// [`get_execution`](crate::use_cases::workflows::executions::reading::get)
/// like anyone else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionDecided {
    /// The run whose pending approval has been decided.
    pub execution_id: WorkflowExecutionId,
    /// Where it stands now.
    pub status: ExecutionStatus,
}

impl ExecutionDecided {
    /// Where `execution` stands.
    pub(in crate::use_cases::workflows::executions) fn of(
        execution: &WorkflowExecution<ResolvedTenant>,
    ) -> Self {
        Self {
            execution_id: *execution.id(),
            status: execution.status(),
        }
    }
}
