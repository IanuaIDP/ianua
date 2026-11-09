-- The memberships of a tenant whose end has come by the given time, the
-- first to end first.
SELECT group_id, principal_kind, principal_id, joined_at, expires_at
FROM group_memberships
WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2
ORDER BY expires_at, group_id, principal_kind, principal_id
LIMIT 500
