-- The roles of a tenant given straight to one principal.
SELECT r.id, r.name, r.system_permissions, r.custom_permissions, r.is_default,
       r.created_at, r.updated_at
FROM roles r
WHERE r.tenant_id = $1
  AND r.id IN (
      SELECT a.role_id
      FROM role_assignments a
      WHERE a.tenant_id = $1 AND a.principal_kind = $2 AND a.principal_id = $3
  )
ORDER BY r.created_at, r.id
