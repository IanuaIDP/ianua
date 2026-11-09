-- Deletes one connector of one tenant.
DELETE FROM connectors
WHERE tenant_id = $1 AND id = $2
