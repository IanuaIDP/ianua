-- The roles of a tenant given straight to one principal, oldest first.
SELECT role_id, principal_kind, principal_id, assigned_by, assigned_at, expires_at
FROM role_assignments
WHERE tenant_id = $1 AND principal_kind = $2 AND principal_id = $3
ORDER BY assigned_at, role_id
