-- The initial access token of one tenant whose hash is the given one.
SELECT id, name, token_hash, uses_left, created_at, expires_at, revoked_at
FROM oauth_initial_access_tokens
WHERE tenant_id = $1 AND token_hash = $2
