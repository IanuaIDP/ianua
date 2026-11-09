-- Keeps an invitation: a new one is added, a known one of the same tenant
-- takes the new values while it is still open. The account it is for, who
-- sent it, the role it gives and when it was sent never change, and an
-- accepted, declined or revoked invitation is never moved again by a copy
-- read before it closed.
INSERT INTO invitations
    (id, tenant_id, user_id, email, invited_by, role_id, token_hash, status,
     accepted_at, message, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    token_hash = EXCLUDED.token_hash,
    status = EXCLUDED.status,
    accepted_at = EXCLUDED.accepted_at,
    message = EXCLUDED.message,
    expires_at = EXCLUDED.expires_at
WHERE invitations.tenant_id = EXCLUDED.tenant_id
    AND invitations.status NOT IN ('accepted', 'declined', 'revoked')
