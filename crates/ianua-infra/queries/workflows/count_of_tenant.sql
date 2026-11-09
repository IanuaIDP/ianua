-- How many workflows a tenant holds against its plan, each once whatever
-- its versions.
SELECT count(*) AS "count!"
FROM workflows
WHERE tenant_id = $1
