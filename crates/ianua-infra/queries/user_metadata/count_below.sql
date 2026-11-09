-- How many users of a tenant hold, under one attribute, a number below the
-- given one, whether kept as a whole number or not.
SELECT count(*) AS "count!"
FROM user_metadata
WHERE tenant_id = $1 AND namespace = $2 AND key = $3
  AND coalesce(value_float, value_int::float8) < $4
