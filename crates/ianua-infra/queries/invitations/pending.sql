-- Every invitation of a tenant still stored as pending, oldest first.
SELECT id, user_id, email, invited_by, role_id, token_hash, status, accepted_at,
       message, expires_at, created_at
FROM invitations
WHERE tenant_id = $1 AND status = 'pending'
ORDER BY created_at, id
