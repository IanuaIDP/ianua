-- The members of the given groups of a tenant, oldest membership first.
SELECT group_id, principal_kind, principal_id, joined_at, expires_at
FROM group_memberships
WHERE tenant_id = $1 AND group_id = ANY($2)
ORDER BY joined_at, principal_id
