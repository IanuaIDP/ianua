-- Deletes one stream route of one tenant.
DELETE FROM stream_routes
WHERE tenant_id = $1 AND id = $2
