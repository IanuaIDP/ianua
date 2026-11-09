-- The memories of one tenant that the ids name.
SELECT id, name, embedding_source, provider_id, embedding_model, vector_size, clearance, status,
       deleted_after, created_by, created_at, updated_at
FROM memories
WHERE tenant_id = $1 AND id = ANY($2)
