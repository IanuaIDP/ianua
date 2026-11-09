-- Keeps a declaration: a new one is added, a known one of the same tenant
-- takes the new values. Its namespace, key, kind and creation time never
-- change.
INSERT INTO user_attribute_definitions
    (id, tenant_id, namespace, key, kind, control, display_name, description,
     options, max_length, minimum, maximum, required, sensitive, filterable,
     sortable, listed, archived, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
        $17, $18, $19, $20)
ON CONFLICT (id) DO UPDATE SET
    control = EXCLUDED.control,
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    options = EXCLUDED.options,
    max_length = EXCLUDED.max_length,
    minimum = EXCLUDED.minimum,
    maximum = EXCLUDED.maximum,
    required = EXCLUDED.required,
    sensitive = EXCLUDED.sensitive,
    filterable = EXCLUDED.filterable,
    sortable = EXCLUDED.sortable,
    listed = EXCLUDED.listed,
    archived = EXCLUDED.archived,
    updated_at = EXCLUDED.updated_at
WHERE user_attribute_definitions.tenant_id = EXCLUDED.tenant_id
