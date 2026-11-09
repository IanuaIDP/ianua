-- How many of the tenant's routes run the given pipeline.
SELECT count(*) AS "count!"
FROM routes
WHERE tenant_id = $1 AND pipeline_id = $2
