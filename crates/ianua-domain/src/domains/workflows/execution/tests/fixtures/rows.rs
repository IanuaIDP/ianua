//! The stored row of a test execution, for the tests that rebuild one.

use crate::domains::workflows::execution::tests::fixtures::Execution;
use crate::domains::workflows::execution::{StoredMode, WorkflowExecutionRow};

pub(crate) fn stored(execution: &Execution) -> WorkflowExecutionRow {
    WorkflowExecutionRow {
        id: execution.id,
        workflow_id: execution.workflow_id,
        version: execution.version,
        graph: execution.graph.clone(),
        acting_for: execution.acting_for.clone(),
        authors: execution.authors.clone(),
        failure_alert: execution.failure_alert,
        mode: StoredMode::from(&execution.mode),
        cause: execution.cause,
        pass: execution.pass.clone(),
        chain_depth: execution.chain_depth,
        input: execution.input.clone(),
        exposure: execution.exposure,
        steps: execution.steps.clone(),
        status: execution.status,
        deadline: execution.deadline,
        created_at: execution.created_at,
        updated_at: execution.updated_at,
    }
}
