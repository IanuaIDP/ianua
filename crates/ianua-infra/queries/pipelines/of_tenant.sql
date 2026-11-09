-- Every pipeline of the tenant, oldest first.
SELECT id, name, status, stages, created_at, updated_at
FROM pipelines
WHERE tenant_id = $1
ORDER BY created_at, id
