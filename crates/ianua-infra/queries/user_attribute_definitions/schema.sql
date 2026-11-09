-- Every attribute a tenant declared, archived ones too, in the order they
-- were declared.
SELECT id, namespace, key, kind, control, display_name, description, options,
       max_length, minimum, maximum, required, sensitive, filterable, sortable,
       listed, archived, created_at, updated_at
FROM user_attribute_definitions
WHERE tenant_id = $1
ORDER BY created_at, id
