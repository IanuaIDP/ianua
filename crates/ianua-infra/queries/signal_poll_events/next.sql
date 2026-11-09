-- The oldest tokens a poll stream of the tenant holds, at most the given
-- number, without dropping any.
SELECT jti, token
FROM signal_poll_events
WHERE tenant_id = $1 AND stream_id = $2
ORDER BY queued
LIMIT $3
