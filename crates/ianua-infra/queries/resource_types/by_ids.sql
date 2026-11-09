-- The resource types of a tenant with the given ids.
SELECT id, key, display_name, description, actions, data_class, created_at, updated_at
FROM resource_types
WHERE tenant_id = $1 AND id = ANY($2)
