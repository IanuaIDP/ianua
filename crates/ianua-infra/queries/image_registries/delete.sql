-- Drops a registry taken off one tenant's list.
DELETE FROM image_registries
WHERE tenant_id = $1 AND id = $2
