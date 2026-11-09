-- The invitation of an organization whose link carries the token with the
-- given hash.
SELECT id, organization_id, org_user_id, email, invited_by, token_hash, status,
       accepted_at, message, expires_at, created_at
FROM org_invitations
WHERE token_hash = $2 AND organization_id = $1
