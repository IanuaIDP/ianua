-- Keeps a tenant's latest algorithm migration: the first is added, a later
-- step of it takes the new values, and one planned after the last finished
-- replaces that one whole. A migration planned while another still runs
-- writes nothing, so the caller can refuse it.
INSERT INTO algorithm_migrations AS kept
    (tenant_id, source_algorithm, target_algorithm, source_kid, status, target_kid,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id) DO UPDATE SET
    source_algorithm = EXCLUDED.source_algorithm,
    target_algorithm = EXCLUDED.target_algorithm,
    source_kid = EXCLUDED.source_kid,
    status = EXCLUDED.status,
    target_kid = EXCLUDED.target_kid,
    created_at = EXCLUDED.created_at,
    updated_at = EXCLUDED.updated_at
WHERE kept.status IN ('completed', 'rolled_back', 'cancelled')
   OR (kept.created_at = EXCLUDED.created_at AND kept.source_kid = EXCLUDED.source_kid)
