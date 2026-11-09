-- How many entries a tenant's permission catalogue holds against its plan.
SELECT count(*) AS "count!"
FROM resource_types
WHERE tenant_id = $1
