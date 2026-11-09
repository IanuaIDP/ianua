-- The webhook secret of one workflow of one tenant.
SELECT id, workflow_id, secret_hash, issued_by, created_at, secret_changed_at
FROM workflow_trigger_secrets
WHERE tenant_id = $1 AND workflow_id = $2
