-- Drops the pushed requests of one tenant that expired by the given time:
-- no browser can use one any more.
DELETE FROM oauth_pushed_requests
WHERE tenant_id = $1 AND expires_at <= $2
