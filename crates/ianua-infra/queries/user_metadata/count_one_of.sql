-- How many users of a tenant hold, under one attribute, one of the given
-- options as their text or among their list.
SELECT count(*) AS "count!"
FROM user_metadata
WHERE tenant_id = $1 AND namespace = $2 AND key = $3
  AND (value_text = ANY($4::text[]) OR value_array && $4::text[])
