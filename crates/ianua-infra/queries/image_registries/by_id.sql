-- The registry of one tenant the id names.
SELECT id, host, login, username, password, allowed_by, created_at, updated_at
FROM image_registries
WHERE tenant_id = $1 AND id = $2
