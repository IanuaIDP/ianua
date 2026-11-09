-- How many consumers a tenant holds against its plan, disabled ones too.
SELECT count(*) AS "count!"
FROM consumers
WHERE tenant_id = $1
