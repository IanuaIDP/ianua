-- The counts the last snapshot of the organization at or before the given
-- moment kept.
SELECT users_count, tenants_count, active_sessions_count
FROM org_metric_snapshots
WHERE organization_id = $1 AND captured_at <= $2
ORDER BY captured_at DESC
LIMIT 1
