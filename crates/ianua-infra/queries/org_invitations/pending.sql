-- An organization's invitations still stored as pending, oldest first.
SELECT id, organization_id, org_user_id, email, invited_by, token_hash, status,
       accepted_at, message, expires_at, created_at
FROM org_invitations
WHERE organization_id = $1 AND status = 'pending'
ORDER BY created_at, id
