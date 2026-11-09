-- The resource type of a tenant with the given key.
SELECT id, key, display_name, description, actions, data_class, created_at, updated_at
FROM resource_types
WHERE tenant_id = $1 AND key = $2
