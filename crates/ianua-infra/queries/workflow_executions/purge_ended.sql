-- Removes a tenant's runs that ended before the cutoff, oldest first, at
-- most $3 at once. Each goes with its loop passes and what it waited on. A
-- run still running stays however old, and so does one a later run was
-- started again from, which goes after that run has gone: a run is never
-- removed from under the run picking up from it. A pass goes only with its
-- run, and a run whose pass still works waits for it.
DELETE FROM workflow_executions
WHERE tenant_id = $1 AND id IN (
    SELECT run.id
    FROM workflow_executions AS run
    WHERE run.tenant_id = $1
      AND run.status <> 'running'
      AND run.pass_of IS NULL
      AND run.updated_at < $2
      AND NOT EXISTS (
          SELECT 1
          FROM workflow_executions AS again
          WHERE again.tenant_id = run.tenant_id AND again.restarted_execution_id = run.id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM workflow_executions AS pass
          WHERE pass.tenant_id = run.tenant_id AND pass.pass_of = run.id
            AND pass.status = 'running'
      )
    ORDER BY run.updated_at
    LIMIT $3
)
