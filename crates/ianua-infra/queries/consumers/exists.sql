-- Whether a tenant has a consumer with the given id.
SELECT EXISTS (SELECT 1 FROM consumers WHERE tenant_id = $1 AND id = $2) AS "exists!"
