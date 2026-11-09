-- The tenant's pipeline with the given id.
SELECT id, name, status, stages, created_at, updated_at
FROM pipelines
WHERE tenant_id = $1 AND id = $2
