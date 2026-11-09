-- Keeps a refresh token of one tenant: the first of a new family, or the
-- one that replaces a rotated token.
INSERT INTO oauth_refresh_tokens
    (tenant_id, token_hash, family_id, client_id, user_id, scopes, session_id, binding,
     binding_thumbprint, issued_at, expires_at, family_expires_at, state, ended_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
