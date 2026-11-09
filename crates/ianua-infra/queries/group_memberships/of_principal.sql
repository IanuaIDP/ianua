-- The groups of a tenant one principal is in, oldest membership first.
SELECT group_id, principal_kind, principal_id, joined_at, expires_at
FROM group_memberships
WHERE tenant_id = $1 AND principal_kind = $2 AND principal_id = $3
ORDER BY joined_at, group_id
