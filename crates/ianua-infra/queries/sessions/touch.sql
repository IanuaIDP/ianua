-- Records a use of a session of a tenant at the given time, only when its
-- last recorded use is older than the given moment, so a busy session is
-- not a write per request.
UPDATE sessions
SET last_active_at = $3
WHERE tenant_id = $1 AND id = $2 AND last_active_at < $4
