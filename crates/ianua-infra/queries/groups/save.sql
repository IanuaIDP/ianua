-- Keeps a group: a new one is added, a known one takes the new values. Its
-- tenant, origin and creation time never change.
INSERT INTO groups (id, tenant_id, name, origin, parent_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    parent_id = EXCLUDED.parent_id,
    updated_at = EXCLUDED.updated_at
WHERE groups.tenant_id = EXCLUDED.tenant_id
