-- How many services a tenant holds against its plan, disabled ones too.
SELECT count(*) AS "count!"
FROM services
WHERE tenant_id = $1
