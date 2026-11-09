-- Every resource type a tenant declares, by key.
SELECT id, key, display_name, description, actions, data_class, created_at, updated_at
FROM resource_types
WHERE tenant_id = $1
ORDER BY key, id
