-- The password reset of a tenant whose link hashes to the given value.
SELECT id, user_id, email, initiator, status, completed_at, token_hash, created_at, expires_at
FROM password_resets
WHERE tenant_id = $1 AND token_hash = $2
