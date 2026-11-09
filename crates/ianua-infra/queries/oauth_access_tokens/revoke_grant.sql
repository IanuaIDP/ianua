-- Revokes, at the given time, every token still in force that one client
-- of one tenant holds for one person. A token revoked already keeps its
-- time.
UPDATE oauth_access_tokens
SET revoked_at = $4
WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 AND revoked_at IS NULL
