-- Keeps, at the given moment, the counts of every tenant in the platform
-- database that is not archived or deleted, those with a database of
-- their own left out: its people, every account not deactivated or
-- closing, and its active sessions not yet expired.
INSERT INTO tenant_metric_snapshots (tenant_id, captured_at, users_count, active_sessions_count)
SELECT t.id, $1,
       (SELECT count(*) FROM users u
        WHERE u.tenant_id = t.id
            AND u.status IN ('invited', 'pending_verification', 'active', 'locked')),
       (SELECT count(*) FROM sessions s
        WHERE s.tenant_id = t.id AND s.status = 'active' AND s.expires_at > $1)
FROM tenants t
WHERE t.status NOT IN ('archived', 'deleted') AND NOT (t.id = ANY($2))
ON CONFLICT (tenant_id, captured_at) DO NOTHING
