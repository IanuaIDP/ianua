-- Keeps, at the given moment, the counts of every organization not
-- closed: its tenants not archived or deleted, and the people and active
-- sessions their snapshots of the same moment kept, added up. Answers how
-- many organizations were captured.
WITH captured AS (
    INSERT INTO org_metric_snapshots
        (organization_id, captured_at, users_count, tenants_count, active_sessions_count)
    SELECT o.id, $1, coalesce(sum(ts.users_count), 0)::bigint, count(t.id),
           coalesce(sum(ts.active_sessions_count), 0)::bigint
    FROM organizations o
    LEFT JOIN tenants t ON t.organization_id = o.id AND t.status NOT IN ('archived', 'deleted')
    LEFT JOIN tenant_metric_snapshots ts ON ts.tenant_id = t.id AND ts.captured_at = $1
    WHERE o.status <> 'closed'
    GROUP BY o.id
    ON CONFLICT (organization_id, captured_at) DO NOTHING
    RETURNING organization_id
)
SELECT count(*) AS "captured!" FROM captured WHERE organization_id IS NOT NULL
