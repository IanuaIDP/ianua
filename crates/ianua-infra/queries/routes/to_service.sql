-- How many routes of one tenant forward to the given service.
SELECT count(*) AS "count!"
FROM routes
WHERE tenant_id = $1 AND service_id = $2
