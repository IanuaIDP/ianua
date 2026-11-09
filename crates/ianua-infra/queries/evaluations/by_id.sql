-- One evaluation of a tenant.
SELECT id, workflow_id, version, revision, cases, outcomes, state, started_by, deadline,
    created_at, updated_at
FROM evaluations
WHERE tenant_id = $1 AND id = $2
