-- Keeps one value of a user of a tenant: a new key is added, a held one
-- takes the new value, in the one column its type keeps it in.
INSERT INTO user_metadata
    (tenant_id, user_id, namespace, key, value_type, value_text, value_int,
     value_float, value_bool, value_array)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (tenant_id, user_id, namespace, key) DO UPDATE SET
    value_type = EXCLUDED.value_type,
    value_text = EXCLUDED.value_text,
    value_int = EXCLUDED.value_int,
    value_float = EXCLUDED.value_float,
    value_bool = EXCLUDED.value_bool,
    value_array = EXCLUDED.value_array
