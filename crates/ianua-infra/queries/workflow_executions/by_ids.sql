-- The runs of one tenant that the ids name.
SELECT id, workflow_id, version, graph, acting_for, authors, cause, cause_event,
    cause_event_depth, restarted_execution_id, restart_from, cause_change, pass_of, pass_step, pass_index,
    chain_depth, input, exposure, steps, status, cancelled_by, deadline, created_at, updated_at,
    failure_alert, mode, stand_ins
FROM workflow_executions
WHERE tenant_id = $1 AND id = ANY($2)
