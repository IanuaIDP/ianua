-- Takes the given principals out of one group of a tenant, each named by
-- its kind and id at the same place in the two lists. One not in it is
-- passed over.
DELETE FROM group_memberships
WHERE tenant_id = $1 AND group_id = $2
  AND (principal_kind, principal_id) IN (
      SELECT leaving.kind, leaving.id
      FROM UNNEST($3::text[], $4::uuid[]) AS leaving (kind, id)
  )
