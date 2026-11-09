-- Keeps a pipeline: a new one is added, a known one takes the new values.
-- Its tenant and creation time never change.
INSERT INTO pipelines (id, tenant_id, name, status, stages, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    status = EXCLUDED.status,
    stages = EXCLUDED.stages,
    updated_at = EXCLUDED.updated_at
WHERE pipelines.tenant_id = EXCLUDED.tenant_id
