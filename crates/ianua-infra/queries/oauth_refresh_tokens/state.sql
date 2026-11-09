-- The stored state word of one tenant's refresh token whose hash is the
-- given one, read after a rotation was turned down to tell a token another
-- refresh rotated first from one revoked meanwhile.
SELECT state
FROM oauth_refresh_tokens
WHERE tenant_id = $1 AND token_hash = $2
