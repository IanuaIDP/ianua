-- Every memory of one tenant, by name.
SELECT id, name, embedding_source, provider_id, embedding_model, vector_size, clearance, status,
       deleted_after, created_by, created_at, updated_at
FROM memories
WHERE tenant_id = $1
ORDER BY name, id
