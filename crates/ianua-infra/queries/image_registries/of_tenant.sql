-- Every registry one tenant allowed, by host. A tenant allows a few, so
-- they are read whole.
SELECT id, host, login, username, password, allowed_by, created_at, updated_at
FROM image_registries
WHERE tenant_id = $1
ORDER BY host
