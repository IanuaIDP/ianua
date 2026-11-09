-- Route counts for a batch of pipelines, scoped to their tenant.
SELECT pipeline_id, count(*) AS "count!"
FROM routes
WHERE tenant_id = $1 AND pipeline_id = ANY($2::uuid[])
GROUP BY pipeline_id
