-- The values the given users of a tenant hold under the given attributes,
-- each named by its namespace and key at the same place in two lists.
SELECT user_id, namespace, key, value_type, value_text, value_int, value_float,
       value_bool, value_array
FROM user_metadata
WHERE tenant_id = $1
  AND user_id = ANY($2)
  AND (namespace, key) IN (
      SELECT wanted.namespace, wanted.key
      FROM UNNEST($3::text[], $4::text[]) AS wanted (namespace, key)
  )
