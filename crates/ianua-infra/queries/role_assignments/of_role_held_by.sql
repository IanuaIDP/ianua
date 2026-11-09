-- The assignments of one role of a tenant to the principals with the given
-- ids.
SELECT role_id, principal_kind, principal_id, assigned_by, assigned_at, expires_at
FROM role_assignments
WHERE tenant_id = $1 AND role_id = $2 AND principal_id = ANY($3)
