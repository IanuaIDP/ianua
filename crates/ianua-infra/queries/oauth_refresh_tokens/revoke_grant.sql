-- Revokes, at the given time, every active token one client of one tenant
-- holds for one person. A token rotated or revoked already keeps its time.
UPDATE oauth_refresh_tokens
SET state = 'revoked', ended_at = $4
WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 AND state = 'active'
