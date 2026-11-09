-- One tenant's memories whose waiting period is over at $2, the longest
-- due first, at most $3.
SELECT id, name, embedding_source, provider_id, embedding_model, vector_size, clearance, status,
       deleted_after, created_by, created_at, updated_at
FROM memories
WHERE tenant_id = $1 AND status = 'deletion_requested' AND deleted_after <= $2
ORDER BY deleted_after, id
LIMIT $3
