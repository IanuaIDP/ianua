-- The export request of a tenant with the given id.
SELECT id, user_id, scope, asked_by, status, ready_at, available_until, requested_at
FROM data_exports
WHERE tenant_id = $1 AND id = $2
