-- The roles of a tenant given straight to someone whose end has come by
-- the given time, the first to end first.
SELECT role_id, principal_kind, principal_id, assigned_by, assigned_at, expires_at
FROM role_assignments
WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2
ORDER BY expires_at, role_id, principal_kind, principal_id
LIMIT 500
