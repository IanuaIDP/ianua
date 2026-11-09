-- A tenant's evaluations still running past their deadline, oldest
-- first, at most $3 of them.
SELECT id, workflow_id, version, revision, cases, outcomes, state, started_by, deadline,
    created_at, updated_at
FROM evaluations
WHERE tenant_id = $1 AND state = 'running' AND deadline <= $2
ORDER BY deadline
LIMIT $3
