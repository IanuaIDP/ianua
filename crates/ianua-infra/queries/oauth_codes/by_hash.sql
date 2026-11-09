-- The authorization code of one tenant whose hash is the given one.
SELECT code_hash, client_id, user_id, redirect_uri, scopes, code_challenge,
       code_challenge_method, nonce, session_id, auth_method, second_factor,
       authenticated_at, created_at, expires_at, consumed_at
FROM oauth_codes
WHERE tenant_id = $1 AND code_hash = $2
