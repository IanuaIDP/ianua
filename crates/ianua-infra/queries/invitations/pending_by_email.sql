-- The invitation of a tenant to the given address still pending and in
-- date at the given moment, the latest first.
SELECT id, user_id, email, invited_by, role_id, token_hash, status, accepted_at,
       message, expires_at, created_at
FROM invitations
WHERE tenant_id = $1 AND email = $2 AND status = 'pending' AND expires_at > $3
ORDER BY created_at DESC
LIMIT 1
