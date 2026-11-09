-- Removes one role from the requested principal batch, preserving tenant scope.
DELETE FROM role_assignments
WHERE tenant_id = $1 AND role_id = $2
  AND (principal_kind, principal_id) IN (
      SELECT wanted.kind, wanted.id
      FROM UNNEST($3::text[], $4::uuid[]) AS wanted(kind, id)
  )
