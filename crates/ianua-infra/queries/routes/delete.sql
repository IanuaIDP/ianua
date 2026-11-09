-- Deletes one route of one tenant.
DELETE FROM routes
WHERE tenant_id = $1 AND id = $2
