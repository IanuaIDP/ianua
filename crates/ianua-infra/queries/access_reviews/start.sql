-- Captures every direct active holder in one statement snapshot. Only the count
-- crosses the adapter boundary; an empty scope creates neither header nor items.
WITH holders AS MATERIALIZED (
    SELECT principal_kind AS holder_kind, principal_id AS holder_id
    FROM role_assignments
    WHERE tenant_id = $1 AND $4 = 'role' AND role_id = $5
      AND (expires_at IS NULL OR expires_at > $11)
    UNION ALL
    SELECT principal_kind AS holder_kind, principal_id AS holder_id
    FROM group_memberships
    WHERE tenant_id = $1 AND $4 = 'group' AND group_id = $5
      AND (expires_at IS NULL OR expires_at > $11)
), opened AS (
    INSERT INTO access_reviews
        (id, tenant_id, name, scope, scope_id, reviewer_kinds, reviewer_ids,
         reviewer_persons, due, unanswered, status, started_at,
         holder_count, pending_count, remove_count)
    SELECT $2, $1, $3, $4, $5, $6, $7, $8, $9, $10, 'open', $11,
           count(*), count(*), 0
    FROM holders
    HAVING count(*) > 0
    RETURNING id
), listed AS (
    INSERT INTO access_review_items
        (tenant_id, review_id, position, holder_kind, holder_id)
    SELECT $1, opened.id,
           row_number() OVER (ORDER BY holders.holder_kind, holders.holder_id),
           holders.holder_kind, holders.holder_id
    FROM holders CROSS JOIN opened
    RETURNING position
)
SELECT count(*) AS "holder_count!" FROM listed
