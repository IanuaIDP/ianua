-- The refresh token of one tenant whose hash is the given one, whatever
-- its state.
SELECT token_hash, family_id, client_id, user_id, scopes, session_id, binding,
       binding_thumbprint, issued_at, expires_at, family_expires_at, state, ended_at
FROM oauth_refresh_tokens
WHERE tenant_id = $1 AND token_hash = $2
