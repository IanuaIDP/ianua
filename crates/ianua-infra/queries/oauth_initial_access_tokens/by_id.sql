-- The initial access token of one tenant with the given id.
SELECT id, name, token_hash, uses_left, created_at, expires_at, revoked_at
FROM oauth_initial_access_tokens
WHERE tenant_id = $1 AND id = $2
