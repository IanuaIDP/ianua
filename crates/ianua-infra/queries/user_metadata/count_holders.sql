-- How many users of a tenant hold any value under one attribute.
SELECT count(*) AS "count!"
FROM user_metadata
WHERE tenant_id = $1 AND namespace = $2 AND key = $3
