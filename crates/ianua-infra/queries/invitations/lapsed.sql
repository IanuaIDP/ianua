-- Hydrate only the bounded keyset page of one tenant's expired invitations.
SELECT id, user_id, email, invited_by, role_id, token_hash, status, accepted_at,
       message, expires_at, created_at
FROM invitations
WHERE tenant_id = $1 AND status = 'pending' AND expires_at <= $2
  AND id = ANY($3::uuid[])
ORDER BY created_at, id
