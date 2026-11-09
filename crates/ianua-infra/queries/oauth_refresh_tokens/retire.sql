-- Writes how one tenant's refresh token ended, just rotated, only while it
-- is still active: of two refreshes with one token arriving together, only
-- one changes the row.
UPDATE oauth_refresh_tokens
SET state = $3, ended_at = $4
WHERE tenant_id = $1 AND token_hash = $2 AND state = 'active'
