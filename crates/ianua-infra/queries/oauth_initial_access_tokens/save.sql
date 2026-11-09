-- Keeps an initial access token: a new one is added, a known one of the
-- same tenant takes its revocation. A revocation is never undone, and the
-- uses left are written only by spending one, so a save racing a
-- registration never gives a use back.
INSERT INTO oauth_initial_access_tokens
    (id, tenant_id, name, token_hash, uses_left, created_at, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
    revoked_at = coalesce(oauth_initial_access_tokens.revoked_at, EXCLUDED.revoked_at)
WHERE oauth_initial_access_tokens.tenant_id = EXCLUDED.tenant_id
