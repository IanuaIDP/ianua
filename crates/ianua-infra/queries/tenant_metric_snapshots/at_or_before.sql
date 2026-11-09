-- The counts the last snapshot of the tenant at or before the given moment
-- kept.
SELECT users_count, active_sessions_count
FROM tenant_metric_snapshots
WHERE tenant_id = $1 AND captured_at <= $2
ORDER BY captured_at DESC
LIMIT 1
