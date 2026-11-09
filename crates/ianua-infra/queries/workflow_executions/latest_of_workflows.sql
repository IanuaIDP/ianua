-- One index-limited latest execution per requested workflow, without
-- scanning each workflow's full run history or making per-flow round trips.
-- The passes of loops are no run of their own, so they are left out.
SELECT e.id, e.workflow_id, e.version, e.graph, e.acting_for, e.authors, e.cause,
       e.cause_event, e.cause_event_depth, e.restarted_execution_id, e.restart_from, e.cause_change,
       e.pass_of, e.pass_step, e.pass_index, e.chain_depth, e.input, e.exposure, e.steps,
       e.status, e.cancelled_by, e.deadline, e.created_at, e.updated_at, e.failure_alert, e.mode,
       e.stand_ins
FROM (SELECT DISTINCT unnest($2::uuid[]) AS workflow_id) requested
JOIN LATERAL (
    SELECT id FROM workflow_executions
    WHERE tenant_id = $1 AND workflow_id = requested.workflow_id AND mode = 'live'
        AND pass_of IS NULL
    ORDER BY created_at DESC, id DESC
    LIMIT 1
) latest ON true
JOIN workflow_executions e ON e.tenant_id = $1 AND e.id = latest.id
