-- How many tenants the organization held at the given moment: every one
-- made by then and not archived or deleted.
SELECT count(*) AS "count!"
FROM tenants
WHERE organization_id = $1 AND created_at <= $2 AND status NOT IN ('archived', 'deleted')
