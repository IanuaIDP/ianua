-- A deleted tenant's teardown.
SELECT tenant_id, planned, done, failed_step, failed_reason, started_at, updated_at
FROM tenant_teardowns
WHERE tenant_id = $1
