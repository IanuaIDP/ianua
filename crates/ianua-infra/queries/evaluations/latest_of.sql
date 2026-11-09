-- A workflow's latest evaluations, newest first, at most $3 of them.
SELECT id, workflow_id, version, revision, cases, outcomes, state, started_by, deadline,
    created_at, updated_at
FROM evaluations
WHERE tenant_id = $1 AND workflow_id = $2
ORDER BY created_at DESC, id DESC
LIMIT $3
