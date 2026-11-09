-- The oldest invitation for one member of an organization still stored as
-- pending, whether or not its link ran out.
SELECT id, organization_id, org_user_id, email, invited_by, token_hash, status,
       accepted_at, message, expires_at, created_at
FROM org_invitations
WHERE organization_id = $1 AND org_user_id = $2 AND status = 'pending'
ORDER BY created_at, id
LIMIT 1
