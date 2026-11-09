-- Keeps an authorization code: a new one is added, a known one of the same
-- tenant takes when it was used. What it was issued for never changes, and
-- a use is never undone.
INSERT INTO oauth_codes
    (tenant_id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge,
     code_challenge_method, nonce, session_id, auth_method, second_factor,
     authenticated_at, created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (tenant_id, code_hash) DO UPDATE SET
    consumed_at = coalesce(oauth_codes.consumed_at, EXCLUDED.consumed_at)
