-- The roles of a tenant given straight to tenant users and still in force
-- at the given time, among the given roles.
SELECT role_id, principal_kind, principal_id, assigned_by, assigned_at, expires_at
FROM role_assignments
WHERE tenant_id = $1 AND role_id = ANY($2) AND principal_kind = 'user'
  AND (expires_at IS NULL OR expires_at > $3)
ORDER BY assigned_at, role_id, principal_id
