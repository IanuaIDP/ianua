-- How many sandboxes a tenant holds against its plan, each once whatever
-- its versions, archived ones among them.
SELECT count(*) AS "count!"
FROM sandboxes
WHERE tenant_id = $1
