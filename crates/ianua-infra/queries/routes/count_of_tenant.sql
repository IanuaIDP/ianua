-- How many proxy routes a tenant holds against its plan, disabled ones
-- too, since they are turned on again without a check.
SELECT count(*) AS "count!"
FROM routes
WHERE tenant_id = $1
