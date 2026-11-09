-- Every membership of a group in a tenant, oldest first.
SELECT group_id, principal_kind, principal_id, joined_at, expires_at
FROM group_memberships
WHERE tenant_id = $1
ORDER BY joined_at, group_id, principal_id
