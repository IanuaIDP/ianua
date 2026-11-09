-- Every role given straight to someone in a tenant, oldest first.
SELECT role_id, principal_kind, principal_id, assigned_by, assigned_at, expires_at
FROM role_assignments
WHERE tenant_id = $1
ORDER BY assigned_at, role_id, principal_id
