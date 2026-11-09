-- The attribute a tenant declared under the given namespace and key.
SELECT id, namespace, key, kind, control, display_name, description, options,
       max_length, minimum, maximum, required, sensitive, filterable, sortable,
       listed, archived, created_at, updated_at
FROM user_attribute_definitions
WHERE tenant_id = $1 AND namespace = $2 AND key = $3
