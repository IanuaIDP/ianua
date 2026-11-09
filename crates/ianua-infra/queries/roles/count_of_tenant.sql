-- How many roles a tenant holds against its plan.
SELECT count(*) AS "count!"
FROM roles
WHERE tenant_id = $1
