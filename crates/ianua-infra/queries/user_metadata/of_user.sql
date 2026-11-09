-- Every value one user of a tenant holds, in both namespaces.
SELECT user_id, namespace, key, value_type, value_text, value_int, value_float,
       value_bool, value_array
FROM user_metadata
WHERE tenant_id = $1 AND user_id = $2
