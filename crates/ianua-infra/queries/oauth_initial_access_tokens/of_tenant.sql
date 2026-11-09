-- Every initial access token one tenant issued, newest first, revoked ones
-- too.
SELECT id, name, token_hash, uses_left, created_at, expires_at, revoked_at
FROM oauth_initial_access_tokens
WHERE tenant_id = $1
ORDER BY created_at DESC, id DESC
