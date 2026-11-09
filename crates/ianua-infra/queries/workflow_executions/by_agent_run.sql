-- The run of one tenant one of whose steps waits on one agent run.
SELECT e.id, e.workflow_id, e.version, e.graph, e.acting_for, e.authors, e.cause,
    e.cause_event, e.cause_event_depth, e.restarted_execution_id, e.restart_from, e.cause_change,
    e.pass_of, e.pass_step, e.pass_index, e.chain_depth, e.input, e.exposure, e.steps,
    e.status, e.cancelled_by, e.deadline, e.created_at, e.updated_at, e.failure_alert, e.mode,
    e.stand_ins
FROM workflow_execution_runs r
JOIN workflow_executions e ON e.tenant_id = r.tenant_id AND e.id = r.execution_id
WHERE r.tenant_id = $1 AND r.agent_run_id = $2
