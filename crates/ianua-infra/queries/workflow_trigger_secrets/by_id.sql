-- One webhook secret of one tenant, by the id its webhook's address names.
SELECT id, workflow_id, secret_hash, issued_by, created_at, secret_changed_at
FROM workflow_trigger_secrets
WHERE tenant_id = $1 AND id = $2
