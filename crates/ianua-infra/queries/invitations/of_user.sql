-- Every invitation of a tenant kept for the given invited account,
-- whatever its status, newest first.
SELECT id, user_id, email, invited_by, role_id, token_hash, status, accepted_at,
       message, expires_at, created_at
FROM invitations
WHERE tenant_id = $1 AND user_id = $2
ORDER BY created_at DESC, id DESC
