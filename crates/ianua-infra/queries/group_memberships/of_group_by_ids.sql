-- The members of one group of a tenant whose ids are given.
SELECT group_id, principal_kind, principal_id, joined_at, expires_at
FROM group_memberships
WHERE tenant_id = $1 AND group_id = $2 AND principal_id = ANY($3)
