-- The registry one tenant allowed for a host, which an image names first.
SELECT id, host, login, username, password, allowed_by, created_at, updated_at
FROM image_registries
WHERE tenant_id = $1 AND host = $2
