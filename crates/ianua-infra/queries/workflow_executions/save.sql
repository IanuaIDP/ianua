-- Keeps a run: a new one is added, a known one takes where its steps stand
-- now. What it runs, who it acts for, what started it, the loop it is a
-- pass of, whether it is a test and when never change. A run ends once:
-- one that ended keeps how it ended, so a save read before the end, still
-- running or ending another way, changes nothing and reports no row.
INSERT INTO workflow_executions
    (id, tenant_id, workflow_id, version, graph, acting_for, authors, cause, cause_event,
     cause_event_depth, restarted_execution_id, restart_from, pass_of, pass_step, pass_index,
     chain_depth, input, exposure, steps, status, cancelled_by, deadline, created_at,
     updated_at, failure_alert, mode, stand_ins, cause_change)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
    $20, $21, $22, $23, $24, $25, $26, $27, $28)
ON CONFLICT (id) DO UPDATE SET
    steps = EXCLUDED.steps,
    status = EXCLUDED.status,
    cancelled_by = EXCLUDED.cancelled_by,
    deadline = EXCLUDED.deadline,
    updated_at = EXCLUDED.updated_at
WHERE workflow_executions.tenant_id = EXCLUDED.tenant_id
    AND (workflow_executions.status = 'running'
        OR (workflow_executions.status = EXCLUDED.status
            AND workflow_executions.cancelled_by IS NOT DISTINCT FROM EXCLUDED.cancelled_by))
