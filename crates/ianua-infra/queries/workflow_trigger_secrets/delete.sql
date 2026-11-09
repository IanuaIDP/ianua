-- Deletes one webhook secret of one tenant.
DELETE FROM workflow_trigger_secrets
WHERE tenant_id = $1 AND id = $2
