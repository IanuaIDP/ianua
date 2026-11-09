-- The most record sets any one of the given tenants holds across the zones
-- it delegated, for a plan's usage.
SELECT coalesce(max(held), 0) AS "most!"
FROM (
    SELECT count(*) AS held
    FROM dns_records
    WHERE tenant_id = ANY($1)
    GROUP BY tenant_id
) AS counted
