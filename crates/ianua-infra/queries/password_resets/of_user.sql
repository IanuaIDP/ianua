-- Every password reset kept for a user of a tenant, whatever its status,
-- newest first.
SELECT id, user_id, email, initiator, status, completed_at, token_hash, created_at, expires_at
FROM password_resets
WHERE tenant_id = $1 AND user_id = $2
ORDER BY created_at DESC, id DESC
