-- Writes the name, scopes and pause of one tenant's API key, only while it
-- is still kept: a key revoked meanwhile is gone, and stays gone.
UPDATE api_keys
SET name = $3, scopes = $4, paused_at = $5
WHERE tenant_id = $1 AND id = $2
