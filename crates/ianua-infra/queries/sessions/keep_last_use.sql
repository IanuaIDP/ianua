-- Writes where a session of a tenant was last used, only while it is still
-- active, so a busy session's bookkeeping can never undo a freeze another
-- request made.
UPDATE sessions
SET last_used_network = $3, last_used_latitude = $4, last_used_longitude = $5,
    last_used_country = $6, last_used_at = $7
WHERE tenant_id = $1 AND id = $2 AND status = 'active'
