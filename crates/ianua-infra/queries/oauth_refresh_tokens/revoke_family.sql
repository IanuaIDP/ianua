-- Revokes, at the given time, every active token of one family of one
-- tenant. A token rotated or revoked already keeps its time.
UPDATE oauth_refresh_tokens
SET state = 'revoked', ended_at = $3
WHERE tenant_id = $1 AND family_id = $2 AND state = 'active'
