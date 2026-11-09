-- The invitation of a tenant whose link has the given hash.
SELECT id, user_id, email, invited_by, role_id, token_hash, status, accepted_at,
       message, expires_at, created_at
FROM invitations
WHERE tenant_id = $1 AND token_hash = $2
