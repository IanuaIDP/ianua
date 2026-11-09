-- Keeps, at the given moment, the counts read from the tenants with a
-- database of their own, in one statement, for those that are not
-- archived or deleted.
INSERT INTO tenant_metric_snapshots (tenant_id, captured_at, users_count, active_sessions_count)
SELECT counted.tenant_id, $1, counted.users_count, counted.active_sessions_count
FROM UNNEST($2::uuid[], $3::bigint[], $4::bigint[])
    AS counted (tenant_id, users_count, active_sessions_count)
JOIN tenants t ON t.id = counted.tenant_id
WHERE t.status NOT IN ('archived', 'deleted')
ON CONFLICT (tenant_id, captured_at) DO NOTHING
