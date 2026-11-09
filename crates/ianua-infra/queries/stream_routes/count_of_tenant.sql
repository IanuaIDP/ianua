-- How many stream routes a tenant holds against its plan, disabled ones
-- too.
SELECT count(*) AS "count!"
FROM stream_routes
WHERE tenant_id = $1
