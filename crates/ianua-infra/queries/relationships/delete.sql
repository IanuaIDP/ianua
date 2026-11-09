-- Removes a relationship of a tenant.
DELETE FROM relationships
WHERE tenant_id = $1 AND id = $2
