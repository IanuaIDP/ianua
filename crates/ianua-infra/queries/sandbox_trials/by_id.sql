-- One trial of a tenant.
SELECT id, sandbox_id, version_id, input, state, output, failure, failure_detail, started_by,
    created_at, updated_at
FROM sandbox_trials
WHERE tenant_id = $1 AND id = $2
