-- One bounded batch after the complete key of the last attempted assignment.
SELECT role_id, principal_kind, principal_id, assigned_by, assigned_at, expires_at
FROM role_assignments
WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2
  AND (expires_at, role_id, principal_kind, principal_id) > ($3, $4, $5, $6)
ORDER BY expires_at, role_id, principal_kind, principal_id
LIMIT 500
