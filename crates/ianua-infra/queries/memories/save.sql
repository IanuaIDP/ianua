-- Keeps a memory: a new one is added, a known one of the same tenant takes
-- its status and when it changed. Its name, embedding model, vector size,
-- clearance, maker and when it was made never change.
INSERT INTO memories
    (id, tenant_id, name, embedding_source, provider_id, embedding_model, vector_size, clearance,
     status, deleted_after, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    deleted_after = EXCLUDED.deleted_after,
    updated_at = EXCLUDED.updated_at
WHERE memories.tenant_id = EXCLUDED.tenant_id
