-- How many groups a tenant holds against its plan.
SELECT count(*) AS "count!"
FROM groups
WHERE tenant_id = $1
