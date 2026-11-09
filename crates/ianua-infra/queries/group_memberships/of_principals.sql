-- The memberships in groups of a tenant of any of the given principals,
-- each named by its kind and id at the same place in the two lists.
SELECT group_id, principal_kind, principal_id, joined_at, expires_at
FROM group_memberships
WHERE tenant_id = $1
  AND (principal_kind, principal_id) IN (
      SELECT wanted.kind, wanted.id
      FROM UNNEST($2::text[], $3::uuid[]) AS wanted (kind, id)
  )
ORDER BY joined_at, group_id
