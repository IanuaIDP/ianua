-- Deletes a resource type of a tenant.
DELETE FROM resource_types
WHERE tenant_id = $1 AND id = $2
