-- Directly assigned roles for the requested principal kind/id pairs in one tenant.
SELECT a.principal_kind, a.principal_id, r.id, r.name, r.system_permissions,
       r.custom_permissions, r.is_default, r.created_at, r.updated_at
FROM roles r
JOIN role_assignments a ON a.tenant_id = r.tenant_id AND a.role_id = r.id
WHERE r.tenant_id = $1 AND a.tenant_id = $1
  AND EXISTS (
      SELECT 1 FROM unnest($2::text[], $3::uuid[]) wanted(kind, id)
      WHERE wanted.kind = a.principal_kind AND wanted.id = a.principal_id
  )
ORDER BY a.principal_kind, a.principal_id, r.created_at, r.id
