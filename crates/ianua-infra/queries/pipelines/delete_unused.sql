-- Removes the tenant's pipeline with the given id, unless a route of the
-- tenant still runs it.
DELETE FROM pipelines
WHERE tenant_id = $1 AND id = $2
    AND NOT EXISTS (
        SELECT 1 FROM routes r WHERE r.tenant_id = $1 AND r.pipeline_id = $2
    )
