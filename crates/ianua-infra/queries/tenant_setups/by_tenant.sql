-- A tenant's setup.
SELECT tenant_id, planned, done, failed_step, failed_reason, started_at, updated_at
FROM tenant_setups
WHERE tenant_id = $1
