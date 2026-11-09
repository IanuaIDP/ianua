-- The access token of one tenant whose hash is the given one.
SELECT token_hash, client_id, user_id, scopes, audience_client_id, audience_stream_route_id,
       delegation, binding, binding_thumbprint, created_at, expires_at, revoked_at
FROM oauth_access_tokens
WHERE tenant_id = $1 AND token_hash = $2
