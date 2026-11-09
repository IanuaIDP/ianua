-- Keeps a password reset: a new one is added, a known one of the same
-- tenant and user takes its new status. Its user, address, initiator, link
-- and times never change.
INSERT INTO password_resets
    (id, tenant_id, user_id, email, initiator, status, completed_at, token_hash,
     created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    completed_at = EXCLUDED.completed_at
WHERE password_resets.tenant_id = EXCLUDED.tenant_id
    AND password_resets.user_id = EXCLUDED.user_id
