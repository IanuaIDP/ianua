-- The grant in force at the given moment letting an operator act as one
-- user of one tenant: not revoked and not yet run out. Of two, the one
-- running longest.
SELECT id, operator_id, tenant_id, user_id, reason, expires_at, revoked_at, created_at
FROM impersonation_grants
WHERE operator_id = $1 AND tenant_id = $2 AND user_id = $3
  AND revoked_at IS NULL AND expires_at > $4
ORDER BY expires_at DESC, id
LIMIT 1
