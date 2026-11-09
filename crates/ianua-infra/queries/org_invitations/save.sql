-- Keeps an invitation: a new one is added, a known one takes the new
-- values while it is still open. Its organization, member, sender and
-- creation time never change, and an accepted, declined or revoked
-- invitation is never moved again by a copy read before it closed.
INSERT INTO org_invitations
    (id, organization_id, org_user_id, email, invited_by, token_hash, status,
     accepted_at, message, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    token_hash = EXCLUDED.token_hash,
    status = EXCLUDED.status,
    accepted_at = EXCLUDED.accepted_at,
    message = EXCLUDED.message,
    expires_at = EXCLUDED.expires_at
WHERE org_invitations.status NOT IN ('accepted', 'declined', 'revoked')
