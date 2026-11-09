-- Hydrate only the bounded keyset page across organizations.
SELECT id, organization_id, org_user_id, email, invited_by, token_hash, status,
       accepted_at, message, expires_at, created_at
FROM org_invitations
WHERE status = 'pending' AND expires_at <= $1
  AND id = ANY($2::uuid[])
ORDER BY expires_at, id
