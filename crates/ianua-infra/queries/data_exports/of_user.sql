-- Every request a user of a tenant made, newest first.
SELECT id, user_id, scope, asked_by, status, ready_at, available_until, requested_at
FROM data_exports
WHERE tenant_id = $1 AND user_id = $2
ORDER BY requested_at DESC, id DESC
