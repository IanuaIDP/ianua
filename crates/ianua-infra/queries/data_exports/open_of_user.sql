-- The request of a user of a tenant still asked for or ready to download;
-- a person has at most one.
SELECT id, user_id, scope, asked_by, status, ready_at, available_until, requested_at
FROM data_exports
WHERE tenant_id = $1 AND user_id = $2 AND status IN ('requested', 'ready')
