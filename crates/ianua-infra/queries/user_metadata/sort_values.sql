-- The value one attribute holds for each of the given users of a tenant,
-- read beside a page sorted by it.
SELECT user_id, value_text, value_int, value_float, value_bool
FROM user_metadata
WHERE tenant_id = $1 AND user_id = ANY($2) AND namespace = $3 AND key = $4
