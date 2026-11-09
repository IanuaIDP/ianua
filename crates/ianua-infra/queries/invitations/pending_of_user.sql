-- The invitation of a tenant for the given invited account still stored as
-- pending, whether or not its link ran out, the latest first.
SELECT id, user_id, email, invited_by, role_id, token_hash, status, accepted_at,
       message, expires_at, created_at
FROM invitations
WHERE tenant_id = $1 AND user_id = $2 AND status = 'pending'
ORDER BY created_at DESC
LIMIT 1
