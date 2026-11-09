-- The oldest invitation of an organization sent to an address that is
-- still pending and whose link still works at the given time.
SELECT id, organization_id, org_user_id, email, invited_by, token_hash, status,
       accepted_at, message, expires_at, created_at
FROM org_invitations
WHERE organization_id = $1 AND email = $2 AND status = 'pending' AND expires_at > $3
ORDER BY created_at, id
LIMIT 1
