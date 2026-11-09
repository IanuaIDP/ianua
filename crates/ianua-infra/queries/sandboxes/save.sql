-- Keeps a sandbox: a new one is added, a known one of the same tenant takes
-- its name, status, latest version number and when it changed. Its kind,
-- language, maker and when it was made never change.
INSERT INTO sandboxes
    (id, tenant_id, name, kind, language, status, latest_version, created_by, created_at,
     updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    status = EXCLUDED.status,
    latest_version = EXCLUDED.latest_version,
    updated_at = EXCLUDED.updated_at
WHERE sandboxes.tenant_id = EXCLUDED.tenant_id
