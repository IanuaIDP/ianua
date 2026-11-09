-- One bounded batch after the complete key of the last attempted membership.
SELECT group_id, principal_kind, principal_id, joined_at, expires_at
FROM group_memberships
WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2
  AND (expires_at, group_id, principal_kind, principal_id) > ($3, $4, $5, $6)
ORDER BY expires_at, group_id, principal_kind, principal_id
LIMIT 500
