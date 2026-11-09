-- A tenant's algorithm migration, while it has not finished.
SELECT source_algorithm, target_algorithm, source_kid, status, target_kid, created_at,
       updated_at
FROM algorithm_migrations
WHERE tenant_id = $1 AND status IN ('planned', 'in_progress', 'validating')
