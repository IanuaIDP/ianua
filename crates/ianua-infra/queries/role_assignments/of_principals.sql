-- The roles of a tenant given straight to any of the given principals,
-- each named by its kind and id at the same place in the two lists.
SELECT role_id, principal_kind, principal_id, assigned_by, assigned_at, expires_at
FROM role_assignments
WHERE tenant_id = $1
  AND (principal_kind, principal_id) IN (
      SELECT wanted.kind, wanted.id
      FROM UNNEST($2::text[], $3::uuid[]) AS wanted (kind, id)
  )
ORDER BY assigned_at, role_id
