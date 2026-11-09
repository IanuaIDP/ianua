-- How many egress policies a tenant holds against its plan.
SELECT count(*) AS "count!"
FROM egress_policies
WHERE tenant_id = $1
