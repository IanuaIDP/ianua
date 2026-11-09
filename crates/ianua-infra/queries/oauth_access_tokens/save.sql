-- Keeps an access token: a new one is added, a known one of the same tenant
-- takes its revocation. What it was issued for never changes, and a
-- revocation is never undone: a token revoked keeps its first time.
INSERT INTO oauth_access_tokens
    (tenant_id, token_hash, client_id, user_id, scopes, audience_client_id,
     audience_stream_route_id, delegation, binding, binding_thumbprint, created_at, expires_at,
     revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (tenant_id, token_hash) DO UPDATE SET
    revoked_at = coalesce(oauth_access_tokens.revoked_at, EXCLUDED.revoked_at)
