-- How many sandboxes of the company's own image a tenant holds against its
-- plan, each once whatever its versions, archived ones among them.
SELECT count(*) AS "count!"
FROM sandboxes
WHERE tenant_id = $1 AND kind = 'image'
